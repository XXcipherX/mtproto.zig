#!/usr/bin/env python3
"""Run the real mtproto-proxy daemon and verify a FakeTLS handshake."""

from __future__ import annotations

import argparse
import select
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


SECRET_HEX = "00112233445566778899aabbccddeeff"
TLS_DOMAIN = "localhost"


def fail(message: str, proc: subprocess.Popen[str] | None = None) -> None:
    if proc is not None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

        output = ""
        if proc.stdout is not None:
            try:
                output = proc.stdout.read()
            except OSError:
                output = ""
        if output:
            print("daemon output:", file=sys.stderr)
            print(output[-4000:], file=sys.stderr)

    print(f"daemon smoke failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def wait_for_port(
    proc: subprocess.Popen[str],
    hosts: list[str],
    port: int,
    timeout_sec: float,
) -> socket.socket:
    deadline = time.time() + timeout_sec
    last_error: OSError | None = None

    while time.time() < deadline:
        if proc.poll() is not None:
            fail(f"daemon exited early with code {proc.returncode}", proc)

        for host in hosts:
            try:
                sock = socket.create_connection((host, port), timeout=0.2)
                sock.settimeout(1.0)
                return sock
            except OSError as err:
                last_error = err

        time.sleep(0.05)

    detail = f": {last_error}" if last_error is not None else ""
    fail(f"port {port} did not open in {timeout_sec:.1f}s{detail}", proc)


def recv_until(sock: socket.socket, size: int, timeout_sec: float) -> bytes:
    deadline = time.time() + timeout_sec
    data = b""

    while len(data) < size and time.time() < deadline:
        timeout = max(0.0, deadline - time.time())
        readable, _, _ = select.select([sock], [], [], timeout)
        if not readable:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk

    return data


def read_fake_tls_response(sock: socket.socket) -> bytes:
    got = recv_until(sock, 11, 1.0)
    if len(got) < 11:
        return got

    server_hello_len = int.from_bytes(got[3:5], "big")
    ccs_start = 5 + server_hello_len
    app_start = ccs_start + 6
    need = app_start + 5

    if len(got) < need:
        got += recv_until(sock, need - len(got), 1.0)
    return got


def is_valid_fake_tls_response(got: bytes) -> bool:
    if len(got) < 11:
        return False
    if got[0:3] != b"\x16\x03\x03":
        return False

    server_hello_len = int.from_bytes(got[3:5], "big")
    ccs_start = 5 + server_hello_len
    app_start = ccs_start + 6
    need = app_start + 5
    if len(got) < need:
        return False

    ccs = got[ccs_start : ccs_start + 6]
    if ccs != b"\x14\x03\x03\x00\x01\x01":
        return False

    app_header = got[app_start : app_start + 5]
    if app_header[0:3] != b"\x17\x03\x03":
        return False
    return int.from_bytes(app_header[3:5], "big") > 0


def verify_fake_tls_response(sock: socket.socket) -> None:
    got = read_fake_tls_response(sock)
    if not is_valid_fake_tls_response(got):
        raise RuntimeError(f"invalid FakeTLS response: got {len(got)} bytes")


def verify_bad_secret_rejected(
    proc: subprocess.Popen[str],
    args: argparse.Namespace,
    build_tls_auth_client_hello,
) -> None:
    bad_secret = bytearray(bytes.fromhex(SECRET_HEX))
    bad_secret[0] ^= 0xFF

    with wait_for_port(
        proc,
        ["127.0.0.1", "::1"],
        args.port,
        args.startup_timeout_sec,
    ) as sock:
        hello = build_tls_auth_client_hello(bytes(bad_secret), TLS_DOMAIN)
        sock.sendall(hello)
        try:
            got = read_fake_tls_response(sock)
        except OSError:
            return
        if is_valid_fake_tls_response(got):
            raise RuntimeError("bad secret received a valid FakeTLS response")


def write_smoke_config(path: Path, port: int) -> None:
    path.write_text(
        textwrap.dedent(
            f"""\
            [general]
            use_middle_proxy = false
            force_media_middle_proxy = false

            [server]
            port = {port}
            public_ip = "127.0.0.1"
            max_connections = 64
            idle_timeout_sec = 5
            handshake_timeout_sec = 5
            rate_limit_per_subnet = 0

            [censorship]
            tls_domain = "{TLS_DOMAIN}"
            mask = false
            desync = false

            [access.users]
            smoke = "{SECRET_HEX}"
            """
        ),
        encoding="utf-8",
    )


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("daemon smoke is Linux-only", file=sys.stderr)
        return 77

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from capacity_connections_probe import build_tls_auth_client_hello

    parser = argparse.ArgumentParser(description="Real daemon FakeTLS smoke test")
    parser.add_argument("--binary", default="zig-out/bin/mtproto-proxy")
    parser.add_argument("--port", type=int, default=16543)
    parser.add_argument("--startup-timeout-sec", type=float, default=6.0)
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        fail(f"binary not found: {binary}")

    with tempfile.TemporaryDirectory(prefix="mtproto-smoke-") as tmp:
        config_path = Path(tmp) / "config.toml"
        write_smoke_config(config_path, args.port)

        proc = subprocess.Popen(
            [str(binary), str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            with wait_for_port(
                proc,
                ["127.0.0.1", "::1"],
                args.port,
                args.startup_timeout_sec,
            ) as sock:
                hello = build_tls_auth_client_hello(bytes.fromhex(SECRET_HEX), TLS_DOMAIN)
                sock.sendall(hello)
                verify_fake_tls_response(sock)
            verify_bad_secret_rejected(proc, args, build_tls_auth_client_hello)
        except Exception as err:  # noqa: BLE001 - this is a test harness.
            fail(str(err), proc)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    print("daemon smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
