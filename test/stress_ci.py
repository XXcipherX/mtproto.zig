#!/usr/bin/env python3
"""Offline, full-relay correctness and resilience stress for the real proxy."""

from __future__ import annotations

import argparse
import asyncio
import csv
import errno
import json
import math
import os
import random
import re
import resource
import signal
import socket
import subprocess
import sys
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Awaitable, Callable

from process_e2e import wait_for_proxy, wait_for_reuseport_listeners
from stress_protocol import (
    PAYLOAD_MAX,
    PAYLOAD_MIN,
    ClientSession,
    DcResponseBurst,
    FakeDatacenter,
    IntegrityError,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = {
    "scenario": "full",
    "proxy_log_level": "info",
    "users": 1000,
    "connections_min": 5,
    "connections_max": 15,
    "workers": 2,
    "steady_seconds": 60,
    "active_percent": 10,
    "payload_bytes": 4096,
    "traffic_interval_ms": 1000,
    "churn_total": 20000,
    "churn_concurrency": 500,
    "slow_reader_percent": 5,
    "reconnect_percent": 20,
    "success_threshold": 99.5,
    "seed": 1337,
    "endurance_minutes": 20,
}
SCENARIOS = ("quick", "steady", "churn", "adversarial", "full", "endurance")
MAX_SIMULTANEOUS = 15_000
MAX_LIFECYCLES = 200_000
CONNECT_INFLIGHT = 64  # below the process-wide /24 handshake limit of 128
CHURN_STARTS_PER_SECOND = 100  # protects the single proxy->DC 4-tuple range
MIN_PROXY_IDLE_TIMEOUT_SEC = 60 * 60  # beyond the 45-minute hosted workflow limit
PRESSURE_RECEIVE_BUFFER = 4096
PRESSURE_PAYLOAD_BYTES = PAYLOAD_MAX
PRESSURE_FRAMES = 252  # 3.85 MiB of relay bytes per socket, below the 4 MiB cap
PRESSURE_C2S_CONNECTIONS = 12
PRESSURE_S2C_CONNECTIONS = 24
ENDURANCE_PAYLOADS = (256, 1024, 4096, PAYLOAD_MAX)
RESOURCE_ERRNOS = {
    errno.ENFILE,
    errno.ENOBUFS,
    errno.ENOMEM,
}


class FakeDcFailure(RuntimeError):
    """The local test peer, not the proxy, violated the protocol."""


class ProxyFailure(RuntimeError):
    """The real proxy process or one of its worker heartbeats failed."""


class UnexpectedClose(RuntimeError):
    """A held relay vanished; the responsible endpoint is not yet proven."""


class PhaseThresholdFailure(RuntimeError):
    """An observed phase invariant failed; not a harness programming error."""


def socket_inode_states(port: int, *, local: bool) -> dict[str, str]:
    """Read TCP states keyed by inode, for one side of the proxy listener."""
    selected = 1 if local else 2
    target = f"{port:04X}"
    states: dict[str, str] = {}
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(table).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) > 9 and fields[selected].rsplit(":", 1)[1].upper() == target:
                states[fields[9]] = fields[3]
    return states


TCP_EXT_KEYS = (
    "TCPKeepAlive", "TCPAbortOnTimeout", "TCPAbortOnMemory",
    "TCPAbortOnClose", "TCPAbortOnData", "TCPTimeouts", "TCPBacklogDrop",
)


def parse_tcp_ext(text: str) -> dict[str, int]:
    lines = text.splitlines()
    for header, values in zip(lines[::2], lines[1::2]):
        names = header.split()
        counts = values.split()
        if names and names[0] == "TcpExt:" and len(names) == len(counts):
            return {
                name: int(value)
                for name, value in zip(names[1:], counts[1:])
                if name in TCP_EXT_KEYS
            }
    return {}


def tcp_ext_snapshot() -> dict[str, int]:
    try:
        return parse_tcp_ext(Path("/proc/net/netstat").read_text(encoding="ascii"))
    except (OSError, ValueError):
        return {}


def parse_softnet_stat(text: str) -> dict[str, int]:
    """Aggregate Linux per-CPU receive drops and processing-budget misses."""
    totals = {"processed": 0, "dropped": 0, "time_squeeze": 0}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            for key, value in zip(totals, fields[:3]):
                totals[key] += int(value, 16)
        except ValueError:
            return {}
    return totals


def softnet_snapshot() -> dict[str, int]:
    try:
        return parse_softnet_stat(Path("/proc/net/softnet_stat").read_text(encoding="ascii"))
    except OSError:
        return {}


def client_tcp_state(session: ClientSession, states: dict[str, str]) -> str:
    if session.closed:
        return "harness_closed"
    sock = session.writer.get_extra_info("socket")
    if sock is None or sock.fileno() != session.socket_fd or session.writer.is_closing():
        return "transport_closed"
    try:
        target = os.readlink(f"/proc/self/fd/{session.socket_fd}")
    except OSError:
        return "fd_missing"
    if not target.startswith("socket:[") or not target.endswith("]"):
        return "fd_reused"
    return states.get(target[8:-1], "tcp_missing")


@dataclass(frozen=True)
class StressConfig:
    scenario: str = "full"
    proxy_log_level: str = "info"
    users: int = 1000
    connections_min: int = 5
    connections_max: int = 15
    workers: int = 2
    steady_seconds: int = 60
    active_percent: int = 10
    payload_bytes: int = 4096
    traffic_interval_ms: int = 1000
    churn_total: int = 20000
    churn_concurrency: int = 500
    slow_reader_percent: int = 5
    reconnect_percent: int = 20
    success_threshold: float = 99.5
    seed: int = 1337
    endurance_minutes: int = 20

    @classmethod
    def from_environment(cls) -> StressConfig:
        values: dict[str, object] = {}
        for name, default in DEFAULTS.items():
            raw = os.environ.get("STRESS_" + name.upper(), "").strip()
            if not raw:
                values[name] = default
            elif isinstance(default, int):
                if not re.fullmatch(r"[0-9]+", raw):
                    raise ValueError(f"{name} must be a nonnegative decimal integer")
                values[name] = int(raw)
            elif isinstance(default, float):
                if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw):
                    raise ValueError(f"{name} must be a decimal percentage")
                values[name] = float(raw)
            else:
                values[name] = raw
        config = cls(**values)
        config.validate()
        return config

    def validate(self) -> None:
        if self.scenario not in SCENARIOS:
            raise ValueError(f"scenario must be one of {SCENARIOS}")
        if self.proxy_log_level not in ("info", "debug"):
            raise ValueError("proxy_log_level must be info or debug")
        if not (1 <= self.users <= MAX_SIMULTANEOUS):
            raise ValueError("users must be in 1..15000")
        if not (1 <= self.connections_min <= self.connections_max <= MAX_SIMULTANEOUS):
            raise ValueError("connections_min/max must be ordered positive integers")
        if self.users * self.connections_max > MAX_SIMULTANEOUS:
            raise ValueError(
                "requested maximum population exceeds 15000 full relays; "
                "reduce users or connections_max"
            )
        if not (0 <= self.workers <= 16):
            raise ValueError("workers must be 0 (auto) or 1..16")
        if not (0 <= self.steady_seconds <= 600):
            raise ValueError("steady_seconds must be in 0..600")
        for name in ("active_percent", "slow_reader_percent", "reconnect_percent"):
            if not (0 <= getattr(self, name) <= 100):
                raise ValueError(f"{name} must be in 0..100")
        if not (PAYLOAD_MIN <= self.payload_bytes <= PAYLOAD_MAX):
            raise ValueError(f"payload_bytes must be in {PAYLOAD_MIN}..{PAYLOAD_MAX}")
        if not (50 <= self.traffic_interval_ms <= 10_000):
            raise ValueError("traffic_interval_ms must be in 50..10000")
        if not (0 <= self.churn_total <= 100_000):
            raise ValueError("churn_total must be in 0..100000")
        if not (1 <= self.churn_concurrency <= 500):
            raise ValueError("churn_concurrency must be in 1..500")
        if not (90 <= self.success_threshold <= 100):
            raise ValueError("success_threshold must be in 90..100")
        if not (0 <= self.seed < 1 << 63):
            raise ValueError("seed must be in 0..2^63-1")
        if not (1 <= self.endurance_minutes <= 30):
            raise ValueError("endurance_minutes must be in 1..30")
        planned_reconnects = math.ceil(self.endurance_minutes * 60 / 9) if self.scenario == "endurance" else 0
        if self.users * self.connections_max + self.churn_total + self.users * self.connections_max + planned_reconnects > MAX_LIFECYCLES:
            raise ValueError("planned full-relay lifecycles exceed the 200000 safety ceiling")


def population_for(config: StressConfig) -> list[dict[str, int]]:
    rng = random.Random(config.seed)
    return [
        {"user": user, "connections": rng.randint(config.connections_min, config.connections_max)}
        for user in range(1, config.users + 1)
    ]


def proxy_capacity_for(config: StressConfig, total: int) -> int:
    """Leave room above the proxy's 90% admission-pause threshold."""
    phases = phases_for(config.scenario)
    reconnect = math.ceil(total * config.reconnect_percent / 100) if "reconnect" in phases else 0
    churn = min(config.churn_total, config.churn_concurrency) if "churn" in phases else 0
    hysteresis_headroom = (total + 10 * churn + 8) // 9
    return total + max(reconnect, churn, hysteresis_headroom) + 512


def proxy_idle_timeout_for(config: StressConfig) -> int:
    """Keep intentional idle relays alive throughout the entire stress job.

    This suite tests relay/keepalive stability, not application idle expiry.
    Queue pressure and churn can take much longer than their traffic estimates,
    so the old 600-second floor let healthy first-ramp relays expire mid-run.
    The one-hour floor outlives the 45-minute hosted job; the workload term
    preserves headroom if supported manual durations are extended later.
    """
    workload_seconds = (
        config.endurance_minutes * 60 if config.scenario == "endurance"
        else config.steady_seconds + math.ceil(config.churn_total / CHURN_STARTS_PER_SECOND)
    )
    return max(MIN_PROXY_IDLE_TIMEOUT_SEC, workload_seconds + 900)


def phases_for(scenario: str) -> tuple[str, ...]:
    common = ("ramp_25", "ramp_50", "ramp_75", "ramp_100")
    profiles = {
        "quick": common + ("steady", "cleanup", "shutdown"),
        "steady": common + ("steady", "cleanup", "shutdown"),
        "churn": common + ("churn", "cleanup", "shutdown"),
        "adversarial": common + ("burst", "slow", "queue_pressure", "reconnect", "half_close", "cleanup", "shutdown"),
        "full": common + ("steady", "burst", "slow", "queue_pressure", "reconnect", "churn", "half_close", "cleanup", "shutdown"),
        "endurance": common + ("endurance", "cleanup", "shutdown"),
    }
    return profiles[scenario]


@dataclass(frozen=True)
class EnduranceTick:
    at_ms: int
    traffic: tuple[tuple[int, int], ...]  # stable population index, body bytes
    reconnect_index: int | None


def endurance_schedule(config: StressConfig, population_size: int) -> tuple[EnduranceTick, ...]:
    """Pure workload decisions; wall-clock scheduling cannot change their order."""
    if population_size < 1:
        raise ValueError("endurance requires at least one live connection")
    rng = random.Random(config.seed ^ 0xE0D0A11C)
    count = min(population_size, max(2, min(24, math.ceil(
        population_size * config.active_percent / 5000
    ))))
    duration_ms = config.endurance_minutes * 60_000
    next_tick = 0
    next_reconnect = 9000 + rng.randrange(6000)
    ticks: list[EnduranceTick] = []
    while True:
        next_tick += 1600 + rng.randrange(1200)
        if next_tick >= duration_ms:
            break
        traffic = tuple(
            (index, ENDURANCE_PAYLOADS[rng.choices(range(4), weights=(45, 30, 20, 5))[0]])
            for index in rng.sample(range(population_size), count)
        )
        reconnect_index = None
        if next_tick >= next_reconnect:
            reconnect_index = rng.randrange(population_size)
            next_reconnect += 9000 + rng.randrange(6000)
        ticks.append(EnduranceTick(next_tick, traffic, reconnect_index))
    return tuple(ticks)


def managed_peak_increased(before: dict[int, int], after: dict[int, int]) -> bool:
    return any(value > before.get(worker, 0) for worker, value in after.items())


def counter_delta(before: dict[str, int], after: dict[str, int], key: str) -> int:
    return after.get(key, 0) - before.get(key, 0)


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lo = math.floor(index)
    hi = math.ceil(index)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo), 3)


def parse_proxy_stats(line: str) -> dict[str, int] | None:
    match = re.search(
        r"conn stats: worker=(\d+) local_active=(\d+)/(\d+) "
        r"global_active=(\d+)/(\d+) global_hs=(\d+).*?"
        r"tracked_fds=(\d+).*?worker_managed_buf=(\d+)/(\d+)KiB peak=(\d+)KiB",
        line,
    )
    if not match:
        return None
    keys = (
        "worker", "local_active", "local_capacity", "global_active", "global_capacity",
        "global_handshakes", "tracked_fds", "managed_used_kib", "managed_limit_kib",
        "managed_peak_kib",
    )
    return dict(zip(keys, map(int, match.groups())))


def proc_snapshot(pid: int, port: int) -> dict[str, object]:
    result: dict[str, object] = {
        "rss_kib": None, "vms_kib": None, "threads": None, "fds": None,
        "established": 0, "close_wait": 0,
    }
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        for line in status.splitlines():
            for prefix, key in (("VmRSS:", "rss_kib"), ("VmSize:", "vms_kib"), ("Threads:", "threads")):
                if line.startswith(prefix):
                    result[key] = int(line.split()[1])
        result["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        for state in socket_inode_states(port, local=True).values():
            if state == "01":
                result["established"] = int(result["established"]) + 1
            elif state == "08":
                result["close_wait"] = int(result["close_wait"]) + 1
    except (OSError, IndexError, ValueError):
        pass
    return result


def classify(error: BaseException) -> str:
    if isinstance(error, PhaseThresholdFailure):
        return "phase_threshold_failure"
    if isinstance(error, FakeDcFailure):
        return "fake_dc_failure"
    if isinstance(error, ProxyFailure):
        return "proxy_failure"
    if isinstance(error, UnexpectedClose):
        return "unexpected_close"
    if isinstance(error, OSError) and error.errno in (errno.EADDRNOTAVAIL, errno.EMFILE):
        return "generator_resource_failure"
    if isinstance(error, OSError) and error.errno in RESOURCE_ERRNOS:
        return "runner_resource_failure"
    if isinstance(error, IntegrityError):
        return "integrity_failure"
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(error, (OSError, ConnectionError, asyncio.IncompleteReadError)):
        return "proxy_failure"
    return "test_bug"


class StressRunner:
    def __init__(
        self, config: StressConfig, proxy_bin: Path, obf_gen: Path, output: Path
    ) -> None:
        self.config = config
        self.proxy_bin = proxy_bin
        self.obf_gen = obf_gen
        self.output = output
        self.population = population_for(config)
        self.total = sum(item["connections"] for item in self.population)
        if self.total > MAX_SIMULTANEOUS:
            raise ValueError("generated population exceeds the 15000 full-relay ceiling")
        extra_churn = min(config.churn_concurrency, config.churn_total) if "churn" in phases_for(config.scenario) else 0
        if self.total + extra_churn > MAX_SIMULTANEOUS:
            raise ValueError("held population plus concurrent churn exceeds 15000 full relays")
        self.specs: list[tuple[int, int]] = []
        for group in self.population:
            for _ in range(group["connections"]):
                self.specs.append((group["user"], len(self.specs) + 1))
        self.next_id = self.total + 1
        self.endurance_ticks = endurance_schedule(config, self.total) if config.scenario == "endurance" else ()
        self.sessions: list[ClientSession] = []
        self.handshakes: deque[bytes] = deque()
        self.fake_dc = FakeDatacenter(output / "fake-dc.log", config.slow_reader_percent)
        self.proc: subprocess.Popen[bytes] | None = None
        self.proxy_port = 0
        self.started = time.monotonic()
        self.connect_gate = asyncio.Semaphore(CONNECT_INFLIGHT)
        self.report: dict[str, object] = {
            "head": os.environ.get("GITHUB_SHA", "unknown"),
            "settings": asdict(config),
            "generated_connections": self.total,
            "phases": [],
            "attempts": 0,
            "relay_ready": 0,
            "exchanges": 0,
            "exchange_failures": 0,
            "integrity_failures": 0,
            "adversarial_expected_closes": 0,
            "unexpected_closes": 0,
            "failure_classes": {},
            "queue_pressure": [],
        }
        self.failures: list[dict[str, object]] = []
        self.expected_close_details: list[dict[str, object]] = []
        self.samples: list[dict[str, object]] = []
        self.latencies_ms: list[float] = []
        self.failed_phase: str | None = None
        self.sampler: asyncio.Task[None] | None = None
        self._log_offset = 0
        self._log_tail = ""
        self._recent_stats: dict[int, dict[str, int]] = {}
        self._stats_last_seen: dict[int, float] = {}
        self._worker_peak_active: Counter[int] = Counter()
        self._worker_peak_managed: Counter[int] = Counter()
        self._counter_totals: Counter[str] = Counter()
        self._close_reasons: Counter[str] = Counter()
        self.effective_workers = 0
        self.relay_rtt_ms: list[float] = []
        self.slow_ids: set[int] = set()
        self._last_recorded_error: BaseException | None = None
        self.cleanup_errors: list[str] = []
        self.pre_teardown_sample: dict[str, object] | None = None

    def _record_failure(
        self, phase: str, connection_id: int, error: BaseException,
        diagnostics: dict[str, object] | None = None,
    ) -> None:
        if error is self._last_recorded_error:
            return
        self._last_recorded_error = error
        kind = classify(error)
        self._counter_totals[kind] += 1
        if isinstance(error, IntegrityError):
            self.report["integrity_failures"] = int(self.report["integrity_failures"]) + 1
        if len(self.failures) < 200:
            failure = {
                "phase": phase,
                "connection_id": connection_id,
                "class": kind,
                "error": f"{type(error).__name__}: {error}",
            }
            if diagnostics is not None:
                failure["diagnostics"] = diagnostics
            self.failures.append(failure)

    def _note_expected_close(self, session: ClientSession, reason: str) -> None:
        self.report["adversarial_expected_closes"] = int(self.report["adversarial_expected_closes"]) + 1
        if len(self.expected_close_details) < 200:
            self.expected_close_details.append({
                "connection_id": session.connection_id,
                "reason": reason,
                "client": session.diagnostics(),
                "dc_requests": self.fake_dc.requests_by_id.get(session.connection_id, 0),
                "dc_responses": self.fake_dc.responses_by_id.get(session.connection_id, 0),
            })

    def _read_proxy_log(self) -> None:
        path = self.output / "proxy.log"
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", errors="replace") as log:
            log.seek(self._log_offset)
            text = log.read()
            self._log_offset = log.tell()
        chunk = self._log_tail + text
        lines = chunk.split("\n")
        self._log_tail = lines.pop()
        for line in lines:
            stats = parse_proxy_stats(line)
            if stats is not None:
                self._recent_stats[stats["worker"]] = stats
                self._stats_last_seen[stats["worker"]] = time.monotonic()
                self._worker_peak_active[stats["worker"]] = max(
                    self._worker_peak_active[stats["worker"]], stats["local_active"]
                )
                self._worker_peak_managed[stats["worker"]] = max(
                    self._worker_peak_managed[stats["worker"]], stats["managed_peak_kib"]
                )
            if "local_pool_drops+=" in line:
                found = re.search(r"local_pool_drops\+=(\d+)", line)
                if found:
                    self._counter_totals["local_pool_drops"] += int(found.group(1))
            for token, key in (("memory_pressure+=", "memory_pressure"), ("hs_budget+=", "hs_budget")):
                found = re.search(re.escape(token) + r"(\d+)", line)
                if found:
                    self._counter_totals[key] += int(found.group(1))
            if "relay first EOF:" in line:
                for token, key in (("client+=", "client_eof_first"), ("upstream+=", "upstream_eof_first")):
                    found = re.search(re.escape(token) + r"(\d+)", line)
                    if found:
                        self._counter_totals[key] += int(found.group(1))
            if " closing:" in line:
                reason = re.search(r"reason=(.*?) (?:raw_)?c2s=", line)
                if reason:
                    self._close_reasons[reason.group(1)] += 1

    def sample(self, phase: str) -> dict[str, object]:
        self._read_proxy_log()
        proc = self.proc
        values = proc_snapshot(proc.pid, self.proxy_port) if proc else {
            "rss_kib": None, "vms_kib": None, "threads": None, "fds": None,
            "established": 0, "close_wait": 0,
        }
        sample = {"elapsed_s": round(time.monotonic() - self.started, 2), "phase": phase, **values}
        sample["worker_stats"] = dict(self._recent_stats)
        states = socket_inode_states(self.proxy_port, local=False) if self.proxy_port else {}
        client_states = Counter(client_tcp_state(session, states) for session in self.sessions)
        sample["held_objects"] = len(self.sessions)
        sample["client_established"] = client_states["01"]
        sample["client_states"] = dict(client_states)
        sample["fake_dc_active"] = len(self.fake_dc.active_ids)
        sample["fake_dc_handlers"] = len(self.fake_dc.tasks)
        sample["tcp_kernel"] = tcp_ext_snapshot()
        sample["softnet"] = softnet_snapshot()
        self.samples.append(sample)
        return sample

    async def _sample_periodically(self) -> None:
        while True:
            self.sample("periodic")
            await asyncio.sleep(5)

    def assert_alive(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            code = None if self.proc is None else self.proc.returncode
            raise ProxyFailure(f"proxy process exited unexpectedly: {code}")
        if self.fake_dc.protocol_errors:
            raise FakeDcFailure(f"fake DC protocol failures: {self.fake_dc.errors[:3]}")
        if self.effective_workers and time.monotonic() - self.started > 40:
            for worker in range(self.effective_workers):
                last = self._stats_last_seen.get(worker, self.started)
                if time.monotonic() - last > 35:
                    raise ProxyFailure(f"worker {worker} has no stats heartbeat for 35 seconds")

    async def validate_population(self, phase: str, live_before: int) -> dict[str, object]:
        """Reconcile retained objects with actual Linux TCP and fake-DC peers."""
        await asyncio.sleep(0.4)
        states = socket_inode_states(self.proxy_port, local=False)
        dead: list[tuple[ClientSession, str]] = []
        for session in self.sessions:
            state = client_tcp_state(session, states)
            if state != "01":
                dead.append((session, state))
        unexpected = 0
        if dead:
            dead_ids = {id(session) for session, _ in dead}
            for session, state in dead:
                if phase == "slow" and session.connection_id in self.slow_ids:
                    self._note_expected_close(session, f"slow-peer TCP state {state}")
                else:
                    unexpected += 1
                    self.report["unexpected_closes"] = int(self.report["unexpected_closes"]) + 1
                    self._record_failure(
                        phase, session.connection_id,
                        UnexpectedClose(f"held relay lost TCP state: {state}"),
                        {
                            "client": session.diagnostics(),
                            "client_tcp_state": state,
                            "dc_requests": self.fake_dc.requests_by_id.get(session.connection_id, 0),
                            "dc_responses": self.fake_dc.responses_by_id.get(session.connection_id, 0),
                        },
                    )
                session.close()
            self.sessions = [session for session in self.sessions if id(session) not in dead_ids]
        sample = self.sample(f"{phase}_validated")
        live = int(sample["client_established"])
        tolerance = max(2, math.ceil(live * (100 - self.config.success_threshold) / 100))
        if unexpected > max(0, math.floor(live_before * (100 - self.config.success_threshold) / 100)):
            raise PhaseThresholdFailure(
                f"{phase} lost {unexpected}/{live_before} ordinary held relays; "
                f"client TCP={sample['client_established']} proxy TCP={sample['established']} "
                f"fake DC={sample['fake_dc_active']}"
            )
        if abs(int(sample["established"]) - live) > tolerance:
            raise PhaseThresholdFailure(
                f"{phase} proxy/client TCP disagree: {sample['established']} vs {live}"
            )
        if abs(int(sample["fake_dc_active"]) - live) > tolerance:
            raise PhaseThresholdFailure(
                f"{phase} fake DC/client live counts disagree: {sample['fake_dc_active']} vs {live}"
            )
        return sample

    async def phase(self, name: str, action: Callable[[], Awaitable[None]]) -> None:
        print(f"[stress] start {name}", flush=True)
        started = time.monotonic()
        live_before = len(self.sessions)
        status = "PASS"
        detail = ""
        try:
            if name != "shutdown":
                self.assert_alive()
            await action()
            if name != "shutdown":
                await self.validate_population(name, live_before)
                self.assert_alive()
        except BaseException as error:
            self.failed_phase = name
            status = "FAIL"
            detail = f"{type(error).__name__}: {error}"
            self._record_failure(name, 0, error)
            raise
        finally:
            snap = self.sample(name)
            self.report["phases"].append({
                "name": name,
                "status": status,
                "duration_s": round(time.monotonic() - started, 2),
                "detail": detail,
                "live_before": live_before,
                "held_objects_after": len(self.sessions),
                "client_established_after": snap["client_established"],
                "proxy_established_after": snap["established"],
                "fake_dc_active_after": snap["fake_dc_active"],
                "resource": snap,
            })
            print(f"[stress] {name}: {status} {detail}", flush=True)

    def _next_handshake(self) -> bytes:
        if not self.handshakes:
            raise RuntimeError("batched obfuscated handshakes exhausted")
        return self.handshakes.popleft()

    def _prepare_handshakes(self) -> None:
        reconnect_count = math.ceil(self.total * self.config.reconnect_percent / 100) if "reconnect" in phases_for(self.config.scenario) else 0
        churn_count = self.config.churn_total if "churn" in phases_for(self.config.scenario) else 0
        endurance_reconnects = sum(tick.reconnect_index is not None for tick in self.endurance_ticks)
        requested = self.total + reconnect_count + churn_count + endurance_reconnects
        completed = subprocess.run(
            [str(self.obf_gen), "00112233445566778899aabbccddeeff", "1", "intermediate", str(requested)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"obfuscated handshake batch generator failed: {completed.stderr[-2000:]}")
        lines = completed.stdout.splitlines()
        if len(lines) != requested or any(len(line) != 128 for line in lines):
            raise RuntimeError(f"handshake batch has {len(lines)} records, expected {requested}")
        self.handshakes = deque(bytes.fromhex(line) for line in lines)

    async def _start(self) -> None:
        max_connections = proxy_capacity_for(self.config, self.total)
        needed_fds = 2 * max_connections + 1024
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = needed_fds
        if hard != resource.RLIM_INFINITY and hard < target:
            raise RuntimeError(f"runner RLIMIT_NOFILE hard={hard} below required {target}")
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))

        self._prepare_handshakes()
        dc_port = await self.fake_dc.start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self.proxy_port = int(probe.getsockname()[1])
        idle_timeout = proxy_idle_timeout_for(self.config)
        config = self.output / "config.toml"
        config.write_text(
            "[general]\nuse_middle_proxy = false\nforce_media_middle_proxy = false\n\n"
            "[server]\n"
            f"port = {self.proxy_port}\nworkers = {self.config.workers}\n"
            'public_ip = "127.0.0.1"\n'
            f"max_connections = {max_connections}\nbacklog = 4096\n"
            f"idle_timeout_sec = {idle_timeout}\nidle_timeout_jitter_pct = 0\n"
            "handshake_timeout_sec = 15\ngraceful_shutdown_timeout_sec = 3\n"
            f'rate_limit_per_subnet = 0\nlog_level = "{self.config.proxy_log_level}"\n\n'
            "[censorship]\n"
            'tls_domain = "stress.example"\nmask = false\ndesync = false\n'
            "fast_mode = false\n\n"
            "[access.users]\n"
            'stress = "00112233445566778899aabbccddeeff"\n',
            encoding="utf-8",
        )
        with (self.output / "proxy.log").open("w", encoding="utf-8") as log:
            self.proc = subprocess.Popen(
                [str(self.proxy_bin), str(config), f"--e2e-dc-port={dc_port}"],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        wait_for_proxy(self.proc, self.proxy_port, 15)
        startup_log = (self.output / "proxy.log").read_text(encoding="utf-8", errors="replace")
        worker_match = re.search(r"MTProto workers: requested=\d+ effective=(\d+)", startup_log)
        if worker_match is None:
            raise RuntimeError("could not read effective worker count from proxy startup log")
        self.effective_workers = int(worker_match.group(1))
        if self.config.workers and self.effective_workers != self.config.workers:
            raise RuntimeError("proxy did not start requested worker count")
        if self.effective_workers > 1:
            wait_for_reuseport_listeners(self.proc, self.proxy_port, self.effective_workers)
        self.sample("startup")
        self.sampler = asyncio.create_task(self._sample_periodically())

    async def _open_one(self, user: int, connection_id: int, handshake: bytes) -> ClientSession:
        async with self.connect_gate:
            self.report["attempts"] = int(self.report["attempts"]) + 1
            began = time.monotonic()
            session = await ClientSession.open(
                connection_id, user, self.proxy_port, handshake,
                self.config.payload_bytes, timeout=20,
            )
            self.latencies_ms.append((time.monotonic() - began) * 1000)
            self.report["relay_ready"] = int(self.report["relay_ready"]) + 1
            self.report["exchanges"] = int(self.report["exchanges"]) + 1
            return session

    async def _open_many(self, specs: list[tuple[int, int]], phase: str) -> None:
        for start in range(0, len(specs), 256):
            batch = specs[start : start + 256]
            prepared = [(user, connection_id, self._next_handshake()) for user, connection_id in batch]
            results = await asyncio.gather(
                *(self._open_one(user, connection_id, handshake) for user, connection_id, handshake in prepared),
                return_exceptions=True,
            )
            hard_error: BaseException | None = None
            for (_, connection_id, _), result in zip(prepared, results):
                if isinstance(result, BaseException):
                    self._record_failure(phase, connection_id, result)
                    if (isinstance(result, IntegrityError) or classify(result) in
                            ("runner_resource_failure", "generator_resource_failure", "test_bug")):
                        hard_error = result
                else:
                    self.sessions.append(result)
            if hard_error is not None:
                raise hard_error
            self.assert_alive()
        attempts = int(self.report["attempts"])
        ready = int(self.report["relay_ready"])
        if attempts and 100 * ready / attempts < self.config.success_threshold:
            raise PhaseThresholdFailure(f"relay-ready ratio {ready}/{attempts} below threshold")

    async def _ramp(self, percent: int) -> None:
        target = math.ceil(self.total * percent / 100)
        already_attempted = min(self.total, int(self.report["attempts"]))
        await self._open_many(self.specs[already_attempted:target], f"ramp_{percent}")
        if int(self.report["attempts"]) != target:
            raise RuntimeError(f"ramp attempted {self.report['attempts']}, expected {target}")

    def _active(self) -> list[ClientSession]:
        count = math.ceil(len(self.sessions) * self.config.active_percent / 100)
        rng = random.Random(self.config.seed ^ 0xA0C71)
        return rng.sample(self.sessions, count) if count else []

    async def _exchange_many(
        self,
        sessions: list[ClientSession],
        phase: str,
        *,
        count: int = 1,
        read_delay: float = 0,
        half_close: bool = False,
        allow_backpressure: bool = False,
        payload_sizes: list[int] | None = None,
    ) -> None:
        if payload_sizes is not None and len(payload_sizes) != len(sessions):
            raise ValueError("one payload size is required per selected session")
        attempted = 0
        failed = 0

        async def timed_exchange(session: ClientSession, size: int) -> float:
            began = time.monotonic()
            await session.exchange_batch(
                count, size, timeout=30,
                read_delay=read_delay, half_close=half_close,
            )
            return (time.monotonic() - began) * 1000

        for start in range(0, len(sessions), 512):
            batch = sessions[start : start + 512]
            batch_sizes = (
                payload_sizes[start : start + len(batch)] if payload_sizes is not None
                else [self.config.payload_bytes] * len(batch)
            )
            outcomes = await asyncio.gather(
                *(timed_exchange(session, size) for session, size in zip(batch, batch_sizes)),
                return_exceptions=True,
            )
            client_states = socket_inode_states(self.proxy_port, local=False)
            for session, outcome in zip(batch, outcomes):
                self.report["exchanges"] = int(self.report["exchanges"]) + count
                attempted += 1
                if isinstance(outcome, BaseException):
                    if (
                        allow_backpressure and session.connection_id in self.slow_ids
                        and not isinstance(outcome, IntegrityError)
                        and classify(outcome) == "proxy_failure"
                    ):
                        self._note_expected_close(session, f"slow exchange: {type(outcome).__name__}: {outcome}")
                        session.close()
                        if session in self.sessions:
                            self.sessions.remove(session)
                        continue
                    self.report["exchange_failures"] = int(self.report["exchange_failures"]) + 1
                    failed += 1
                    self._record_failure(phase, session.connection_id, outcome, {
                        "client": session.diagnostics(),
                        "client_tcp_state": client_tcp_state(session, client_states),
                        "dc_requests": self.fake_dc.requests_by_id.get(session.connection_id, 0),
                        "dc_responses": self.fake_dc.responses_by_id.get(session.connection_id, 0),
                    })
                    session.close()
                    if session in self.sessions:
                        self.sessions.remove(session)
                    if isinstance(outcome, IntegrityError) or classify(outcome) in (
                        "runner_resource_failure", "generator_resource_failure", "test_bug"
                    ):
                        raise outcome
                else:
                    self.relay_rtt_ms.append(outcome)
            self.assert_alive()
        if attempted and 100 * (attempted - failed) / attempted < self.config.success_threshold:
            raise PhaseThresholdFailure(f"{phase} validated exchanges {attempted - failed}/{attempted} below threshold")

    async def _steady(self) -> None:
        duration = min(self.config.steady_seconds, 5) if self.config.scenario == "quick" else self.config.steady_seconds
        active = self._active()
        until = time.monotonic() + duration
        while time.monotonic() < until:
            await self._exchange_many(active, "steady")
            await asyncio.sleep(self.config.traffic_interval_ms / 1000)

    async def _burst(self) -> None:
        active = self._active()
        await self._exchange_many(active, "burst", count=4)

    async def _slow(self) -> None:
        slow = [session for session in self.sessions if session.connection_id % 100 < self.config.slow_reader_percent]
        self.slow_ids = {session.connection_id for session in slow}
        if not slow:
            return
        count = min(32, max(8, 128 * 1024 // self.config.payload_bytes))
        await self._exchange_many(slow, "slow", count=count, read_delay=1.5, allow_backpressure=True)
        normal = [session for session in self.sessions if session not in slow]
        if normal:
            await self._exchange_many(normal[: min(128, len(normal))], "slow-normal")

    def _managed_snapshot(self) -> dict[str, object]:
        self._read_proxy_log()
        return {
            "peak_by_worker_kib": {
                worker: self._recent_stats.get(worker, {}).get("managed_peak_kib", 0)
                for worker in range(self.effective_workers)
            },
            "current_by_worker_kib": {
                worker: self._recent_stats.get(worker, {}).get("managed_used_kib", 0)
                for worker in range(self.effective_workers)
            },
            "limit_by_worker_kib": {
                worker: self._recent_stats.get(worker, {}).get("managed_limit_kib", 0)
                for worker in range(self.effective_workers)
            },
        }

    async def _fresh_stats(self, after: float, phase: str, timeout: float = 16) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._read_proxy_log()
            self.assert_alive()
            if all(self._stats_last_seen.get(worker, 0) > after
                   for worker in range(self.effective_workers)):
                self.sample(phase)
                return
            await asyncio.sleep(0.5)
        raise PhaseThresholdFailure(f"{phase}: no fresh per-worker stats within {timeout}s")

    async def _pressure_direction(
        self, direction: str, selected: list[ClientSession]
    ) -> None:
        if not selected:
            raise PhaseThresholdFailure(f"queue_pressure {direction}: no live relays selected")
        await self._fresh_stats(time.monotonic(), f"queue_pressure_{direction}_baseline")
        before = self._managed_snapshot()
        before_peak = before["peak_by_worker_kib"]
        before_denials = self._counter_totals["memory_pressure"]
        before_unexpected = int(self.report["unexpected_closes"])
        before_integrity = int(self.report["integrity_failures"])
        effective_buffers: dict[int, int] = {}
        paused: list[ClientSession] = []
        response_bursts: dict[int, DcResponseBurst] = {}
        sent: list[tuple[int, int]] = []
        during: dict[str, object] | None = None
        peak_reached = False
        dc_requests_before = {
            session.connection_id: self.fake_dc.requests_by_id.get(session.connection_id, 0)
            for session in selected
        }
        dc_requests_stalled: dict[int, int] = {}
        row: dict[str, object] = {
            "direction": direction,
            "connections": len(selected),
            "requested_receive_buffer_bytes": PRESSURE_RECEIVE_BUFFER,
            "effective_receive_buffer_bytes": effective_buffers,
            "frames_per_connection": PRESSURE_FRAMES,
            "managed_before": before,
            "dc_validated_before": dc_requests_before,
            "managed_peak_increased": False,
        }
        self.report["queue_pressure"].append(row)
        try:
            for session in selected:
                if direction == "C2S":
                    effective_buffers[session.connection_id] = self.fake_dc.pause_receiving(
                        session.connection_id, PRESSURE_RECEIVE_BUFFER
                    )
                else:
                    response_bursts[session.connection_id] = self.fake_dc.prepare_response_burst(
                        session.connection_id, PRESSURE_FRAMES
                    )
                    effective_buffers[session.connection_id] = session.pause_receiving(
                        PRESSURE_RECEIVE_BUFFER
                    )
                paused.append(session)
            sent = list(await asyncio.gather(*(
                session.enqueue_pressure_requests(PRESSURE_FRAMES, PRESSURE_PAYLOAD_BYTES)
                for session in selected
            )))
            self.report["exchanges"] = int(self.report["exchanges"]) + len(selected) * PRESSURE_FRAMES
            if direction == "S2C":
                # All C2S frames must reach and validate at the DC *before*
                # its response burst starts. Any new managed peak now belongs
                # to the S2C path, not a blocked upstream request socket.
                await asyncio.wait_for(asyncio.gather(
                    *(session.drain_pressure_requests(60) for session in selected),
                    *(burst.ready.wait() for burst in response_bursts.values()),
                ), 65)
                # A slow DC may have caused incidental C2S buffering while it
                # collected the requests. Reset the baseline only after all
                # requests are validated, before releasing any S2C bytes.
                await self._fresh_stats(
                    time.monotonic(), "queue_pressure_S2C_requests_delivered"
                )
                before = self._managed_snapshot()
                before_peak = before["peak_by_worker_kib"]
                row["managed_before"] = before
                for connection_id in response_bursts:
                    self.fake_dc.release_response_burst(connection_id)
            # Peak is historical in ManagedBufferAllocator, but its periodic
            # worker log must be newer than the stalled traffic itself.
            enqueued_at = time.monotonic()
            deadline = enqueued_at + 24
            while time.monotonic() < deadline:
                self._read_proxy_log()
                self.assert_alive()
                current = self._managed_snapshot()["peak_by_worker_kib"]
                if (
                    all(self._stats_last_seen.get(worker, 0) > enqueued_at + 1
                        for worker in range(self.effective_workers))
                    and managed_peak_increased(before_peak, current)
                ):
                    peak_reached = True
                    self.sample(f"queue_pressure_{direction}_stalled")
                    break
                await asyncio.sleep(0.5)
            during = self._managed_snapshot()
            dc_requests_stalled = {
                session.connection_id: self.fake_dc.requests_by_id.get(session.connection_id, 0)
                for session in selected
            }
        finally:
            for connection_id in response_bursts:
                self.fake_dc.release_response_burst(connection_id)
            for session in paused:
                if direction == "C2S":
                    if session.connection_id in self.fake_dc.paused_receive_buffers:
                        self.fake_dc.resume_receiving(session.connection_id)
                elif session._saved_receive_buffer is not None:
                    session.resume_receiving()

        async def finish(session: ClientSession, first_sequence: int) -> None:
            await asyncio.gather(
                session.drain_pressure_requests(90),
                session.receive_pressure_responses(
                    first_sequence, PRESSURE_FRAMES, PRESSURE_PAYLOAD_BYTES, 45
                ),
            )

        await asyncio.wait_for(asyncio.gather(*(
            finish(session, first_sequence)
            for session, (first_sequence, _) in zip(selected, sent)
        )), 120)
        released_at = time.monotonic()
        await self._fresh_stats(released_at, f"queue_pressure_{direction}_drained")
        after = self._managed_snapshot()
        if direction == "S2C":
            peak_reached = peak_reached or managed_peak_increased(
                before_peak, after["peak_by_worker_kib"]
            )
        row.update({
            "request_wire_bytes": sum(written for _, written in sent),
            "dc_response_bytes": len(selected) * PRESSURE_FRAMES * (PRESSURE_PAYLOAD_BYTES + 4),
            "dc_validated_while_stalled": dc_requests_stalled,
            "dc_validated_after": {
                session.connection_id: self.fake_dc.requests_by_id.get(session.connection_id, 0)
                for session in selected
            },
            "managed_during": during,
            "managed_after": after,
            "managed_peak_increased": peak_reached,
            "memory_pressure_denials": self._counter_totals["memory_pressure"] - before_denials,
            "unexpected_closes": int(self.report["unexpected_closes"]) - before_unexpected,
            "integrity_failures": int(self.report["integrity_failures"]) - before_integrity,
        })
        if not peak_reached:
            raise PhaseThresholdFailure(
                f"queue_pressure {direction} did not reach managed relay queue path: "
                f"before={before_peak} after={after['peak_by_worker_kib']}"
            )
        if direction == "C2S" and dc_requests_stalled != dc_requests_before:
            raise PhaseThresholdFailure("queue_pressure C2S fake DC read while transport was paused")
        if row["memory_pressure_denials"]:
            raise PhaseThresholdFailure(f"queue_pressure {direction} exhausted the managed budget")
        for worker, used in after["current_by_worker_kib"].items():
            if used > after["limit_by_worker_kib"][worker]:
                raise PhaseThresholdFailure(f"queue_pressure {direction} worker {worker} exceeded budget")

    async def _queue_pressure(self) -> None:
        # Two disjoint groups keep the second direction's concurrent allocation
        # larger than the first one's retained worker-local free list.
        needed = PRESSURE_C2S_CONNECTIONS + PRESSURE_S2C_CONNECTIONS
        if len(self.sessions) < needed:
            raise PhaseThresholdFailure(f"queue_pressure needs {needed} live full relays")
        ordinary_peers = [session for session in self.sessions if
                          session.connection_id % 100 >= self.config.slow_reader_percent]
        candidates = ordinary_peers if len(ordinary_peers) >= needed else self.sessions
        chosen = random.Random(self.config.seed ^ 0x9E55).sample(candidates, needed)
        await self._pressure_direction("C2S", chosen[:PRESSURE_C2S_CONNECTIONS])
        await self._pressure_direction("S2C", chosen[PRESSURE_C2S_CONNECTIONS:])
        await self._exchange_many(chosen, "queue_pressure_drained")
        excluded = {id(session) for session in chosen}
        ordinary = [session for session in self.sessions if id(session) not in excluded][:64]
        if ordinary:
            await self._exchange_many(ordinary, "queue_pressure_ordinary")

    async def _endurance(self) -> None:
        if len(self.sessions) != self.total:
            raise PhaseThresholdFailure("endurance requires the full seeded persistent population")
        starting_unexpected = int(self.report["unexpected_closes"])
        starting_integrity = int(self.report["integrity_failures"])
        starting_exchanges = int(self.report["exchanges"])
        starting_failures = dict(self._counter_totals)
        first = await self.validate_population("endurance_start", len(self.sessions))
        began = time.monotonic()
        starting_live = int(first["client_established"])
        minimum_live = starting_live
        sampled_from = len(self.samples) - 1
        reconnects = 0
        checkpoints = 0
        payloads: Counter[int] = Counter()
        last_check = began
        try:
            for tick in self.endurance_ticks:
                await asyncio.sleep(max(0, began + tick.at_ms / 1000 - time.monotonic()))
                selected = [self.sessions[index] for index, _ in tick.traffic]
                sizes = [size for _, size in tick.traffic]
                payloads.update(sizes)
                await self._exchange_many(selected, "endurance", payload_sizes=sizes)
                if tick.reconnect_index is not None:
                    index = tick.reconnect_index
                    old = self.sessions[index]
                    old.close()
                    replacement = await self._open_one(old.user, self.next_id, self._next_handshake())
                    self.next_id += 1
                    self.sessions[index] = replacement
                    reconnects += 1
                if time.monotonic() - last_check >= 30:
                    checkpoint = await self.validate_population("endurance_checkpoint", starting_live)
                    minimum_live = min(minimum_live, int(checkpoint["client_established"]))
                    checkpoints += 1
                    last_check = time.monotonic()
                    self.assert_alive()
                    if int(self.report["unexpected_closes"]) != starting_unexpected:
                        raise PhaseThresholdFailure("endurance lost an ordinary persistent relay")
                    if self._counter_totals["local_pool_drops"] > starting_failures.get("local_pool_drops", 0):
                        raise PhaseThresholdFailure("endurance saw connection-pool drops")
                    if self._counter_totals["memory_pressure"] > starting_failures.get("memory_pressure", 0):
                        raise PhaseThresholdFailure("endurance exhausted managed memory")
                    if first["rss_kib"] and checkpoint["rss_kib"] and int(checkpoint["rss_kib"]) > int(first["rss_kib"]) + 512 * 1024:
                        raise PhaseThresholdFailure("endurance RSS grew more than 512 MiB from ramp baseline")
                    for worker, stats in self._recent_stats.items():
                        if stats["managed_used_kib"] > stats["managed_limit_kib"]:
                            raise PhaseThresholdFailure(f"endurance worker {worker} exceeded managed budget")
            await asyncio.sleep(max(0, began + self.config.endurance_minutes * 60 - time.monotonic()))
            final = await self.validate_population("endurance_end", starting_live)
            minimum_live = min(minimum_live, int(final["client_established"]))
            self.assert_alive()
            if int(self.report["unexpected_closes"]) != starting_unexpected:
                raise PhaseThresholdFailure("endurance lost an ordinary persistent relay")
        finally:
            final_sample = self.sample("endurance_metrics")
            segment = self.samples[sampled_from:]
            rss_values = [int(row["rss_kib"]) for row in segment if row["rss_kib"] is not None]
            fd_values = [int(row["fds"]) for row in segment if row["fds"] is not None]
            self.report["endurance"] = {
                "configured_minutes": self.config.endurance_minutes,
                "elapsed_s": round(time.monotonic() - began, 2),
                "starting_live": starting_live,
                "minimum_live": minimum_live,
                "ending_live": final_sample["client_established"],
                "checkpoints": checkpoints,
                "traffic_exchanges": sum(payloads.values()),
                "total_exchanges_including_reconnect": int(self.report["exchanges"]) - starting_exchanges,
                "background_reconnects": reconnects,
                "payload_counts": dict(payloads),
                "unexpected_closes": int(self.report["unexpected_closes"]) - starting_unexpected,
                "integrity_failures": int(self.report["integrity_failures"]) - starting_integrity,
                "rss_kib_min_max": [min(rss_values), max(rss_values)] if rss_values else None,
                "fds_min_max": [min(fd_values), max(fd_values)] if fd_values else None,
                "managed_start": first["worker_stats"],
                "managed_end": final_sample["worker_stats"],
                "pool_drops": self._counter_totals["local_pool_drops"] - starting_failures.get("local_pool_drops", 0),
                "memory_pressure": self._counter_totals["memory_pressure"] - starting_failures.get("memory_pressure", 0),
                "tcp_keepalive_delta": counter_delta(first["tcp_kernel"], final_sample["tcp_kernel"], "TCPKeepAlive"),
                "tcp_abort_on_timeout_delta": counter_delta(first["tcp_kernel"], final_sample["tcp_kernel"], "TCPAbortOnTimeout"),
                "softnet_dropped_delta": counter_delta(first["softnet"], final_sample["softnet"], "dropped"),
                "worker_peak_active": dict(self._worker_peak_active),
            }

    async def _reconnect(self) -> None:
        count = math.ceil(len(self.sessions) * self.config.reconnect_percent / 100)
        if count == 0:
            return
        chosen = random.Random(self.config.seed ^ 0x5EC0).sample(self.sessions, count)
        for session in chosen:
            session.close()
        chosen_ids = {id(session) for session in chosen}
        self.sessions = [session for session in self.sessions if id(session) not in chosen_ids]
        await asyncio.sleep(0.2)
        replacements = []
        for session in chosen:
            replacements.append((session.user, self.next_id))
            self.next_id += 1
        await self._open_many(replacements, "reconnect")

    async def _churn(self) -> None:
        if self.config.churn_total == 0:
            return
        queue: asyncio.Queue[tuple[int, int, bytes] | None] = asyncio.Queue(maxsize=1024)
        failures = 0
        fatal_error: BaseException | None = None

        async def worker() -> None:
            nonlocal failures, fatal_error
            while True:
                item = await queue.get()
                try:
                    if item is None:
                        return
                    user, connection_id, handshake = item
                    try:
                        session = await self._open_one(user, connection_id, handshake)
                    except Exception as error:
                        failures += 1
                        self._record_failure("churn", connection_id, error)
                        if isinstance(error, IntegrityError) or classify(error) in (
                            "generator_resource_failure", "runner_resource_failure", "test_bug"
                        ):
                            fatal_error = error
                    else:
                        session.close()
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.config.churn_concurrency)]
        try:
            users = random.Random(self.config.seed ^ 0xC4A7)
            for _ in range(self.config.churn_total):
                connection_id = self.next_id
                self.next_id += 1
                await queue.put((users.randint(1, self.config.users), connection_id, self._next_handshake()))
                await asyncio.sleep(1 / CHURN_STARTS_PER_SECOND)
                if fatal_error is not None:
                    raise fatal_error
                if connection_id % 250 == 0:
                    self.assert_alive()
            for _ in workers:
                await queue.put(None)
            await queue.join()
            await asyncio.gather(*workers)
        finally:
            for task in workers:
                task.cancel()
        if failures:
            ratio = 100 * (self.config.churn_total - failures) / self.config.churn_total
            if ratio < self.config.success_threshold:
                raise PhaseThresholdFailure(f"churn full-relay success {ratio:.3f}% below threshold")
        await asyncio.sleep(2)

    async def _half_close(self) -> None:
        count = min(100, max(1, len(self.sessions) // 100))
        chosen = self.sessions[:count]
        await self._exchange_many(chosen, "half_close", half_close=True)
        for session in chosen:
            session.close()
        chosen_ids = {id(session) for session in chosen}
        self.sessions = [session for session in self.sessions if id(session) not in chosen_ids]

    async def _cleanup(self) -> None:
        keep = min(100, max(8, len(self.sessions) // 100))
        survivors = self.sessions[:keep]
        for session in self.sessions[keep:]:
            session.close()
        self.sessions = survivors
        await asyncio.sleep(12)
        current = self.sample("settle")
        if int(current.get("close_wait") or 0) > max(32, 2 * keep):
            raise RuntimeError(f"lingering proxy CLOSE_WAIT: {current['close_wait']}")
        baseline = self.samples[0]
        allowed_fds = int(baseline.get("fds") or 0) + 2 * keep + 128
        if current.get("fds") is not None and int(current["fds"]) > allowed_fds:
            raise RuntimeError(f"proxy fd recovery failed: {current['fds']} > {allowed_fds}")
        baseline_rss = int(baseline.get("rss_kib") or 0)
        rss = int(current.get("rss_kib") or 0)
        if baseline_rss and rss > baseline_rss + 512 * 1024:
            raise RuntimeError(f"proxy RSS did not recover within 512 MiB: {rss} KiB")
        for worker in range(self.effective_workers):
            stats = self._recent_stats.get(worker)
            if stats is None or self._stats_last_seen.get(worker, 0) < time.monotonic() - 15:
                raise RuntimeError(f"worker {worker} did not report a fresh cleanup snapshot")
            if stats["local_active"] > keep + 64:
                raise RuntimeError(f"worker {worker} retained {stats['local_active']} slots after cleanup")
            if stats["managed_used_kib"] > stats["managed_limit_kib"]:
                raise RuntimeError(f"worker {worker} managed accounting exceeds its budget")

    async def _shutdown(self) -> None:
        if self.proc is None:
            raise RuntimeError("proxy was never started")
        self.proc.send_signal(signal.SIGTERM)
        try:
            code = await asyncio.to_thread(self.proc.wait, timeout=12)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("graceful shutdown exceeded 12 seconds") from error
        if code != 0:
            raise RuntimeError(f"graceful shutdown exit={code}")
        for session in self.sessions:
            session.close()
        self.sessions.clear()

    async def run(self) -> None:
        await self._start()
        mapping: dict[str, Callable[[], Awaitable[None]]] = {
            "ramp_25": lambda: self._ramp(25),
            "ramp_50": lambda: self._ramp(50),
            "ramp_75": lambda: self._ramp(75),
            "ramp_100": lambda: self._ramp(100),
            "steady": self._steady,
            "burst": self._burst,
            "slow": self._slow,
            "queue_pressure": self._queue_pressure,
            "reconnect": self._reconnect,
            "churn": self._churn,
            "half_close": self._half_close,
            "endurance": self._endurance,
            "cleanup": self._cleanup,
            "shutdown": self._shutdown,
        }
        for name in phases_for(self.config.scenario):
            await self.phase(name, mapping[name])
        attempts = int(self.report["attempts"])
        ready = int(self.report["relay_ready"])
        if attempts == 0 or 100 * ready / attempts < self.config.success_threshold:
            raise PhaseThresholdFailure(f"full-relay readiness {ready}/{attempts} below threshold")
        if int(self.report["integrity_failures"]) or self.fake_dc.protocol_errors:
            raise RuntimeError("payload/session isolation failed")
        maximum_unexpected = math.floor(self.total * (100 - self.config.success_threshold) / 100)
        if int(self.report["unexpected_closes"]) > maximum_unexpected:
            raise PhaseThresholdFailure(
                f"total unexpected closes {self.report['unexpected_closes']} exceed {maximum_unexpected}"
            )
        if self.fake_dc.responses < ready:
            raise FakeDcFailure(f"fake DC responses {self.fake_dc.responses} < relay-ready {ready}")
        if self._counter_totals["local_pool_drops"] or self._counter_totals["memory_pressure"]:
            raise RuntimeError("unexpected pool drops or managed memory pressure")

    async def stop(self) -> None:
        self.pre_teardown_sample = self.sample("pre_teardown")
        print(f"[stress] cleanup: closing {len(self.sessions)} client sessions", flush=True)
        if self.sampler is not None:
            self.sampler.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(self.sampler, return_exceptions=True), 2)
            except TimeoutError:
                self.cleanup_errors.append("sampler cancellation exceeded 2 seconds")
        for session in self.sessions:
            session.close()
        self.sessions.clear()
        print("[stress] cleanup: stopping proxy", flush=True)
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                await asyncio.to_thread(self.proc.wait, timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    await asyncio.to_thread(self.proc.wait, timeout=3)
                except subprocess.TimeoutExpired:
                    self.cleanup_errors.append("proxy remained alive after SIGKILL")
        print(f"[stress] cleanup: stopping fake DC, handlers={len(self.fake_dc.tasks)}", flush=True)
        try:
            await asyncio.wait_for(self.fake_dc.stop(), 15)
        except TimeoutError:
            self.cleanup_errors.append("fake DC stop exceeded 15 seconds")
        if self.fake_dc.stop_diagnostics.get("leftover_tasks"):
            self.cleanup_errors.append(
                f"fake DC left {self.fake_dc.stop_diagnostics['leftover_tasks']} handler tasks"
            )
        if self.fake_dc.stop_diagnostics.get("server_wait_timeout"):
            self.cleanup_errors.append("fake DC server wait_closed exceeded 3 seconds")
        self.sample("final")
        print(f"[stress] cleanup: complete, errors={len(self.cleanup_errors)}", flush=True)

    def capture_failure(self, error: BaseException) -> None:
        """Persist evidence while the proxy and test peers still exist."""
        snap = self.sample("failure_time")
        proxy_log = self.output / "proxy.log"
        log_lines = proxy_log.read_text(encoding="utf-8", errors="replace").splitlines() if proxy_log.exists() else []
        context = {
            "failure_time": {
                "phase": self.failed_phase or "startup",
                "error": f"{type(error).__name__}: {error}",
                "proxy_poll": None if self.proc is None else self.proc.poll(),
                "proxy_alive": self.proc is not None and self.proc.poll() is None,
                "resource": snap,
                "held_objects": len(self.sessions),
                "failed_connection_ids": [row["connection_id"] for row in self.failures],
                "fake_dc": {
                    "accepted": self.fake_dc.accepted,
                    "active": len(self.fake_dc.active_ids),
                    "handlers": len(self.fake_dc.tasks),
                    "validated": self.fake_dc.validated,
                    "responses": self.fake_dc.responses,
                    "protocol_errors": self.fake_dc.protocol_errors,
                    "close_reasons": dict(self.fake_dc.close_reasons),
                    "recent_closes": list(self.fake_dc.recent_closes)[-100:],
                },
                "last_proxy_lines": log_lines[-100:],
                "failure_classes": dict(self._counter_totals),
                "proxy_close_reasons": dict(self._close_reasons),
            },
            "post_cleanup": None,
        }
        (self.output / "failure-context.json").write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
        (self.output / "failed-connections.json").write_text(json.dumps(self.failures, indent=2) + "\n", encoding="utf-8")

    def write_reports(self, outcome: str, error: BaseException | None) -> None:
        self._read_proxy_log()
        report = self.report
        report["outcome"] = outcome
        report["failed_phase"] = self.failed_phase
        report["error"] = None if error is None else f"{type(error).__name__}: {error}"
        report["duration_s"] = round(time.monotonic() - self.started, 2)
        report["failure_classes"] = dict(self._counter_totals)
        report["proxy_close_reasons"] = dict(self._close_reasons)
        report["cleanup_errors"] = self.cleanup_errors
        report["pre_teardown_live"] = None if self.pre_teardown_sample is None else self.pre_teardown_sample["client_established"]
        report["unexpected_closes"] = int(report["unexpected_closes"])
        report["expected_adversarial_closes"] = self.expected_close_details
        report["dc_request_deficit"] = int(report["exchanges"]) - self.fake_dc.validated
        report["fake_dc"] = {
            "accepted": self.fake_dc.accepted,
            "validated": self.fake_dc.validated,
            "responses": self.fake_dc.responses,
            "protocol_errors": self.fake_dc.protocol_errors,
            "errors": self.fake_dc.errors,
            "close_reasons": dict(self.fake_dc.close_reasons),
            "stop": self.fake_dc.stop_diagnostics,
        }
        report["latency_ms"] = {
            f"p{int(q * 100)}": percentile(self.latencies_ms, q)
            for q in (0.5, 0.95, 0.99)
        }
        report["relay_rtt_ms"] = {
            f"p{int(q * 100)}": percentile(self.relay_rtt_ms, q)
            for q in (0.5, 0.95, 0.99)
        }
        report["effective_workers"] = self.effective_workers
        report["worker_peak_active"] = dict(self._worker_peak_active)
        report["peak_managed_kib"] = sum(self._worker_peak_managed.values())
        report["peak_rss_kib"] = max((int(s.get("rss_kib") or 0) for s in self.samples), default=0)
        report["peak_fds"] = max((int(s.get("fds") or 0) for s in self.samples), default=0)
        report["worker_stats"] = self._recent_stats
        (self.output / "stress-summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        with (self.output / "resource-samples.csv").open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=("elapsed_s", "phase", "rss_kib", "vms_kib", "threads", "fds", "established", "close_wait", "held_objects", "client_established", "client_states", "fake_dc_active", "fake_dc_handlers", "tcp_kernel", "softnet", "worker_stats"),
            )
            writer.writeheader()
            for sample in self.samples:
                writer.writerow({
                    **sample,
                    "client_states": json.dumps(sample.get("client_states", {})),
                    "tcp_kernel": json.dumps(sample.get("tcp_kernel", {})),
                    "softnet": json.dumps(sample.get("softnet", {})),
                    "worker_stats": json.dumps(sample.get("worker_stats", {})),
                })
        if outcome != "PASS":
            (self.output / "failed-connections.json").write_text(json.dumps(self.failures, indent=2) + "\n", encoding="utf-8")
            context_path = self.output / "failure-context.json"
            context = json.loads(context_path.read_text(encoding="utf-8")) if context_path.exists() else {"failure_time": None}
            context["post_cleanup"] = {
                "proxy_poll": None if self.proc is None else self.proc.poll(),
                "resource": self.samples[-1] if self.samples else None,
                "fake_dc_stop": self.fake_dc.stop_diagnostics,
                "cleanup_errors": self.cleanup_errors,
            }
            (self.output / "failure-context.json").write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            lines = [
                f"## MTProto Stress CI — {outcome}",
                "",
                f"HEAD: `{report['head']}` · scenario: `{self.config.scenario}` · seed: `{self.config.seed}`",
                f"Users: {self.config.users} · planned held relays: {self.total} · workers: {self.effective_workers}",
                f"Relay-ready ever: {report['relay_ready']}/{report['attempts']} · live before teardown: {report['pre_teardown_live']}",
                f"Expected slow-peer closes: {report['adversarial_expected_closes']} · unexpected closes: {report['unexpected_closes']}",
                f"Integrity failures: {report['integrity_failures']} · DC request deficit: {report['dc_request_deficit']}",
                f"Peak RSS: {report['peak_rss_kib']} KiB · peak proxy FDs: {report['peak_fds']} · peak managed: {report['peak_managed_kib']} KiB",
                f"Pool drops: {self._counter_totals['local_pool_drops']} · memory pressure: {self._counter_totals['memory_pressure']} · duration: {report['duration_s']} s",
                f"Connect+first relay p50/p95/p99: {report['latency_ms']} ms · relay RTT: {report['relay_rtt_ms']} ms",
            ]
            for pressure in report["queue_pressure"]:
                if "managed_after" not in pressure:
                    lines.append(
                        f"Queue {pressure['direction']}: incomplete; "
                        f"managed baseline {pressure['managed_before']['peak_by_worker_kib']} KiB"
                    )
                    continue
                lines.append(
                    f"Queue {pressure['direction']}: {pressure['connections']} peers, "
                    f"request wire {pressure['request_wire_bytes']} B, "
                    f"managed peak {pressure['managed_before']['peak_by_worker_kib']} → "
                    f"{pressure['managed_after']['peak_by_worker_kib']} KiB, "
                    f"current {pressure['managed_after']['current_by_worker_kib']} KiB, "
                    f"denials {pressure['memory_pressure_denials']}"
                )
            if "endurance" in report:
                endurance = report["endurance"]
                lines.append(
                    f"Endurance: {endurance['elapsed_s']} s, live "
                    f"{endurance['starting_live']}/{endurance['minimum_live']}/{endurance['ending_live']} "
                    f"(start/min/end), exchanges {endurance['traffic_exchanges']}, "
                    f"reconnects {endurance['background_reconnects']}, "
                    f"TCPKeepAlive +{endurance['tcp_keepalive_delta']}, "
                    f"TCPAbortOnTimeout +{endurance['tcp_abort_on_timeout_delta']}, "
                    f"softnet drops +{endurance['softnet_dropped_delta']}"
                )
            lines.extend((
                "", "| Phase | Result | Live client TCP after | Proxy TCP after | Fake DC after | Duration |",
                "|---|---|---:|---:|---:|---:|",
            ))
            for phase in report["phases"]:
                lines.append(
                    f"| {phase['name']} | {phase['status']} | {phase['client_established_after']} | "
                    f"{phase['proxy_established_after']} | {phase['fake_dc_active_after']} | {phase['duration_s']} s |"
                )
            if error is not None:
                lines.extend(("", f"Failure: `{type(error).__name__}: {error}`"))
            with Path(summary_path).open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")


async def async_main(args: argparse.Namespace) -> int:
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "fake-dc.log").touch()
    config = StressConfig.from_environment()
    runner = StressRunner(config, Path(args.proxy_bin).resolve(), Path(args.obf_gen).resolve(), output)
    if not runner.proxy_bin.is_file() or not runner.obf_gen.is_file():
        raise ValueError("--proxy-bin and --obf-gen must name built executables")
    (output / "stress-population.json").write_text(
        json.dumps({
            "seed": config.seed,
            "users": config.users,
            "total_connections": runner.total,
            "population": runner.population,
            "scenario_settings": asdict(config),
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    error: BaseException | None = None
    try:
        await runner.run()
    except BaseException as caught:
        error = caught
        print(f"stress failed in {runner.failed_phase or 'startup'}: {type(caught).__name__}: {caught}", file=sys.stderr)
        try:
            runner.capture_failure(caught)
        except Exception as capture_error:
            print(f"could not capture failure-time evidence: {capture_error}", file=sys.stderr)
    finally:
        try:
            await asyncio.wait_for(runner.stop(), timeout=25)
        except BaseException as cleanup_error:
            runner.cleanup_errors.append(f"teardown failed: {type(cleanup_error).__name__}: {cleanup_error}")
            if error is None:
                error = cleanup_error
                runner.failed_phase = "cleanup"
                runner._record_failure("cleanup", 0, cleanup_error)
                runner.capture_failure(cleanup_error)
        runner.write_reports("PASS" if error is None else "FAIL", error)
    return 0 if error is None else 1


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("stress harness requires Linux", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-bin", required=True)
    parser.add_argument("--obf-gen", required=True)
    parser.add_argument("--output-dir", default="stress-artifacts")
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except BaseException as error:
        print(f"stress setup failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
