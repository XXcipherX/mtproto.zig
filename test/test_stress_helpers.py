"""Fast offline invariants for the full-relay stress tooling (no proxy needed)."""

from __future__ import annotations

import errno
import asyncio
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from stress_ci import (
    FakeDcFailure,
    MIN_PROXY_IDLE_TIMEOUT_SEC,
    PhaseThresholdFailure,
    PRESSURE_C2S_CONNECTIONS,
    PRESSURE_FRAMES,
    PRESSURE_PAYLOAD_BYTES,
    PRESSURE_S2C_CONNECTIONS,
    StressConfig,
    StressRunner,
    classify,
    client_tcp_state,
    endurance_schedule,
    managed_peak_increased,
    parse_proxy_stats,
    parse_softnet_stat,
    parse_tcp_ext,
    percentile,
    phases_for,
    population_for,
    proxy_capacity_for,
    proxy_idle_timeout_for,
)
from stress_crypto import AesCtr
from stress_protocol import (
    DC_INCOMPLETE_FRAME_TIMEOUT_SEC,
    DC_NEXT_FRAME_TIMEOUT_SEC,
    FakeDatacenter,
    IntegrityError,
    parse_request,
    read_dc_frame,
    request_body,
    response_body,
)


class StressHelperTests(unittest.TestCase):
    def test_population_is_seeded_and_bounded(self) -> None:
        config = StressConfig(users=128, connections_min=2, connections_max=6)
        config.validate()
        first = population_for(config)
        self.assertEqual(first, population_for(config))
        self.assertEqual(128, len(first))
        self.assertTrue(all(2 <= item["connections"] <= 6 for item in first))
        self.assertNotEqual(first, population_for(replace(config, seed=9876)))
        total = sum(item["connections"] for item in first)
        self.assertTrue(128 * 2 <= total <= 128 * 6)

    def test_invalid_manual_inputs_and_ceiling(self) -> None:
        for override in (
            {"users": 0}, {"connections_min": 0},
            {"connections_min": 7, "connections_max": 6},
            {"users": 1001, "connections_max": 15},
            {"workers": 17}, {"active_percent": 101},
            {"slow_reader_percent": -1}, {"reconnect_percent": 101},
            {"success_threshold": 89.9}, {"scenario": "other"},
            {"endurance_minutes": 0}, {"endurance_minutes": 31},
        ):
            with self.subTest(override=override), self.assertRaises(ValueError):
                replace(StressConfig(), **override).validate()
        with patch.dict(os.environ, {"STRESS_USERS": "1.0"}):
            with self.assertRaisesRegex(ValueError, "nonnegative decimal integer"):
                StressConfig.from_environment()

    def test_scenario_phases(self) -> None:
        for scenario in ("quick", "steady", "churn", "adversarial", "full", "endurance"):
            phases = phases_for(scenario)
            self.assertEqual(phases[:4], ("ramp_25", "ramp_50", "ramp_75", "ramp_100"))
            self.assertEqual(phases[-2:], ("cleanup", "shutdown"))
        self.assertNotIn("churn", phases_for("quick"))
        self.assertIn("churn", phases_for("full"))
        self.assertIn("half_close", phases_for("adversarial"))
        self.assertIn("queue_pressure", phases_for("adversarial"))
        self.assertIn("queue_pressure", phases_for("full"))
        self.assertNotIn("queue_pressure", phases_for("endurance"))
        self.assertEqual(("endurance", "cleanup", "shutdown"), phases_for("endurance")[-3:])

    def test_endurance_schedule_is_seeded_jittered_and_bounded(self) -> None:
        config = StressConfig(scenario="endurance", endurance_minutes=2, active_percent=10)
        first = endurance_schedule(config, 96)
        self.assertEqual(first, endurance_schedule(config, 96))
        self.assertNotEqual(first, endurance_schedule(replace(config, seed=9876), 96))
        self.assertTrue(first)
        self.assertTrue(all(0 < tick.at_ms < 120_000 for tick in first))
        self.assertEqual(list(first), sorted(first, key=lambda tick: tick.at_ms))
        self.assertGreater(len({b.at_ms - a.at_ms for a, b in zip(first, first[1:])}), 1)
        self.assertGreater(sum(tick.reconnect_index is not None for tick in first), 0)
        self.assertTrue(all(
            tick.reconnect_index is None or 0 <= tick.reconnect_index < 96
            for tick in first
        ))
        self.assertTrue(all(len({index for index, _ in tick.traffic}) == len(tick.traffic) for tick in first))
        self.assertTrue(all(0 <= index < 96 and size in (256, 1024, 4096, 16_000)
                            for tick in first for index, size in tick.traffic))
        self.assertGreater(len({size for tick in first for _, size in tick.traffic}), 1)

    def test_pressure_budget_and_peak_comparison(self) -> None:
        self.assertLess(PRESSURE_FRAMES * (PRESSURE_PAYLOAD_BYTES + 5), 4 * 1024 * 1024)
        self.assertLessEqual(PRESSURE_C2S_CONNECTIONS + PRESSURE_S2C_CONNECTIONS, 64)
        self.assertFalse(managed_peak_increased({0: 0, 1: 4}, {0: 0, 1: 4}))
        self.assertTrue(managed_peak_increased({0: 0, 1: 4}, {0: 4, 1: 4}))

    def test_capacity_stays_above_admission_hysteresis(self) -> None:
        total = 10162
        steady = StressConfig(scenario="steady", reconnect_percent=0, churn_total=0)
        self.assertGreater(proxy_capacity_for(steady, total) * 9 // 10, total)
        full = StressConfig(scenario="full", reconnect_percent=0, churn_total=20000)
        self.assertGreater(proxy_capacity_for(full, total) * 9 // 10, total + full.churn_concurrency)

    def test_proxy_idle_horizon_outlives_hosted_stress_job(self) -> None:
        self.assertGreater(MIN_PROXY_IDLE_TIMEOUT_SEC, 45 * 60)
        self.assertGreater(DC_NEXT_FRAME_TIMEOUT_SEC, MIN_PROXY_IDLE_TIMEOUT_SEC)
        self.assertEqual(30, DC_INCOMPLETE_FRAME_TIMEOUT_SEC)
        for scenario in ("quick", "full", "endurance"):
            with self.subTest(scenario=scenario):
                self.assertGreater(proxy_idle_timeout_for(StressConfig(scenario=scenario)), 45 * 60)
                self.assertGreater(
                    DC_NEXT_FRAME_TIMEOUT_SEC,
                    proxy_idle_timeout_for(StressConfig(scenario=scenario)),
                )
        self.assertEqual(3600, proxy_idle_timeout_for(StressConfig(scenario="full")))
        self.assertEqual(
            3600,
            proxy_idle_timeout_for(StressConfig(scenario="endurance", endurance_minutes=30)),
        )

    def test_dc_idle_eof_and_truncated_header_are_distinct(self) -> None:
        async def check() -> None:
            idle_eof = asyncio.StreamReader()
            idle_eof.feed_eof()
            self.assertIsNone(await read_dc_frame(idle_eof, None))

            partial_header = asyncio.StreamReader()
            partial_header.feed_data(b"\x00")
            partial_header.feed_eof()
            with self.assertRaisesRegex(IntegrityError, "truncated direct-DC frame header"):
                await read_dc_frame(partial_header, None)

        asyncio.run(check())

    def test_percentiles_and_stats_parser(self) -> None:
        self.assertIsNone(percentile([], 0.5))
        self.assertEqual(5, percentile([10, 0], 0.5))
        line = (
            "conn stats: worker=1 local_active=35/64 global_active=70/128 "
            "global_hs=3 accepted+=9 closed+=1 local_pool_drops+=0 "
            "tracked_fds=72 global_total=900 paused=false/false "
            "worker_managed_buf=64/1024KiB peak=128KiB"
        )
        stats = parse_proxy_stats(line)
        self.assertIsNotNone(stats)
        self.assertEqual(35, stats["local_active"])
        self.assertEqual(64, stats["managed_used_kib"])
        self.assertEqual(128, stats["managed_peak_kib"])
        self.assertIsNone(parse_proxy_stats("unrelated log line"))
        self.assertEqual(
            {"TCPKeepAlive": 10, "TCPAbortOnTimeout": 2},
            parse_tcp_ext(
                "TcpExt: TCPKeepAlive TCPAbortOnTimeout Other\n"
                "TcpExt: 10 2 99\n"
            ),
        )
        self.assertEqual(
            {"processed": 18, "dropped": 3, "time_squeeze": 5},
            parse_softnet_stat("00000010 00000001 00000003\n00000002 00000002 00000002\n"),
        )
        self.assertEqual({}, parse_softnet_stat("00000001 invalid 00000000\n"))

    def test_request_response_isolation(self) -> None:
        body = request_body(1234, 7, 4096)
        self.assertEqual((1234, 7), parse_request(body))
        self.assertEqual(len(body), len(response_body(body)))
        self.assertEqual(b"MTSR", response_body(body)[:4])
        self.assertNotEqual(response_body(body), response_body(request_body(1235, 7, 4096)))
        corrupted = bytearray(body)
        corrupted[-1] ^= 1
        with self.assertRaises(IntegrityError):
            parse_request(bytes(corrupted))

    def test_openssl_ctr_matches_aes256_vector_and_streaming(self) -> None:
        key = bytes.fromhex(
            "603deb1015ca71be2b73aef0857d7781"
            "1f352c073b6108d72d9810a30914dff4"
        )
        iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("601ec313775789a5b7a7f504bbf3d228")
        cipher = AesCtr(key, iv)
        try:
            self.assertEqual(expected, cipher.apply(plain[:5]) + cipher.apply(plain[5:]))
        finally:
            cipher.close()

    def test_failure_classes_and_report_serialization(self) -> None:
        self.assertEqual("fake_dc_failure", classify(FakeDcFailure("invalid peer frame")))
        self.assertEqual("generator_resource_failure", classify(OSError(errno.EADDRNOTAVAIL, "ports")))
        self.assertEqual("generator_resource_failure", classify(OSError(errno.EMFILE, "fds")))
        self.assertEqual("runner_resource_failure", classify(OSError(errno.ENFILE, "fds")))
        self.assertEqual("phase_threshold_failure", classify(PhaseThresholdFailure("51/100")))
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            path = Path(directory)
            runner = StressRunner(StressConfig(users=2, connections_min=1, connections_max=1), path / "missing", path / "missing", path)
            runner.write_reports("PASS", None)
            summary = json.loads((path / "stress-summary.json").read_text(encoding="utf-8"))
            population = population_for(runner.config)
            self.assertEqual(2, summary["generated_connections"])
            self.assertEqual(2, sum(row["connections"] for row in population))
            self.assertEqual("PASS", summary["outcome"])
            self.assertEqual([], summary["queue_pressure"])
            runner.report["queue_pressure"].append({
                "direction": "C2S", "connections": 12,
                "managed_before": {"peak_by_worker_kib": {0: 0}},
                "managed_after": {"peak_by_worker_kib": {0: 32}},
                "managed_peak_increased": True,
            })
            runner.report["endurance"] = {
                "starting_live": 2, "minimum_live": 2, "ending_live": 2,
                "background_reconnects": 1, "tcp_abort_on_timeout_delta": 0,
            }
            runner.write_reports("PASS", None)
            summary = json.loads((path / "stress-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["queue_pressure"][0]["managed_peak_increased"])
            self.assertEqual(2, summary["endurance"]["minimum_live"])

    def test_dead_held_session_is_not_counted_live(self) -> None:
        class DeadSession:
            connection_id = 1
            socket_fd = 12
            closed = False
            writer = SimpleNamespace(get_extra_info=lambda _key: None, is_closing=lambda: False)

            def diagnostics(self) -> dict[str, object]:
                return {"socket_fd": None}

            def close(self) -> None:
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            config = StressConfig(scenario="quick", users=1, connections_min=1, connections_max=1)
            runner = StressRunner(config, path / "missing", path / "missing", path)
            session = DeadSession()
            self.assertEqual("transport_closed", client_tcp_state(session, {}))
            runner.sessions = [session]
            with self.assertRaises(PhaseThresholdFailure):
                asyncio.run(runner.validate_population("steady", 1))
            self.assertEqual(0, len(runner.sessions))
            self.assertEqual(1, runner.report["unexpected_closes"])

            expected = DeadSession()
            runner.sessions = [expected]
            runner.slow_ids = {1}
            asyncio.run(runner.validate_population("slow", 1))
            self.assertEqual(1, runner.report["adversarial_expected_closes"])
            self.assertEqual(0, len(runner.sessions))

    def test_failure_evidence_precedes_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            path = Path(directory)
            config = StressConfig(scenario="quick", users=1, connections_min=1, connections_max=1)
            runner = StressRunner(config, path / "missing", path / "missing", path)
            state = {"returncode": None}
            runner.proc = SimpleNamespace(pid=os.getpid(), poll=lambda: state["returncode"])
            failure = PhaseThresholdFailure("lost relay")
            runner.capture_failure(failure)
            saved = json.loads((path / "failure-context.json").read_text(encoding="utf-8"))
            self.assertTrue(saved["failure_time"]["proxy_alive"])
            self.assertIsNone(saved["post_cleanup"])
            state["returncode"] = 0
            runner.write_reports("FAIL", failure)
            saved = json.loads((path / "failure-context.json").read_text(encoding="utf-8"))
            self.assertTrue(saved["failure_time"]["proxy_alive"])
            self.assertEqual(0, saved["post_cleanup"]["proxy_poll"])


class FakeDcStopTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_cancels_active_handler_before_waiting_for_server(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dc = FakeDatacenter(Path(directory) / "fake-dc.log", 0)
            port = await dc.start()
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            for _ in range(100):
                if dc.tasks:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(dc.tasks)
            await asyncio.wait_for(dc.stop(), timeout=2)
            self.assertEqual(0, dc.stop_diagnostics["leftover_tasks"])
            writer.close()
            await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
