#!/usr/bin/env python3
"""Exercise a complete FakeTLS-to-direct-DC relay with real processes."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECRET_HEX = "00112233445566778899aabbccddeeff"
TLS_DOMAIN = "e2e.example"
CLIENT_PAYLOAD = bytes(range(192))
DC_RESPONSE = bytes((index * 17) & 0xFF for index in range(48))
DC_NONCE_SIZE = 64


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError(f"unexpected EOF after {len(result)} of {size} bytes")
        result.extend(chunk)
    return bytes(result)


def recv_tls_record(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 5)
    if header[1:3] != b"\x03\x03":
        raise AssertionError(f"unexpected TLS version {header[1:3].hex()}")
    length = struct.unpack(">H", header[3:5])[0]
    return header[0], recv_exact(sock, length)


def tls_record(record_type: int, payload: bytes) -> bytes:
    return bytes((record_type, 0x03, 0x03)) + struct.pack(">H", len(payload)) + payload


def generate_obfuscated_handshake(generator: Path) -> bytes:
    completed = subprocess.run(
        [str(generator), SECRET_HEX, "1", "intermediate"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "obfuscated-handshake generator failed:\n"
            f"{completed.stdout}{completed.stderr}"
        )
    encoded = completed.stdout.strip()
    if len(encoded) != 128:
        raise AssertionError(f"generator returned {len(encoded)} hex characters")
    return bytes.fromhex(encoded)


class FakeDatacenter:
    def __init__(self) -> None:
        self.port = free_port()
        self.received = b""
        self.error: BaseException | None = None
        self.ready = threading.Event()
        self.response_sent = threading.Event()
        self.release = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=2):
            raise RuntimeError("fake DC did not start")
        if self.error is not None:
            raise RuntimeError("fake DC failed during startup") from self.error

    def _serve(self) -> None:
        expected = DC_NONCE_SIZE + len(CLIENT_PAYLOAD)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self.port))
                listener.listen(1)
                listener.settimeout(5)
                self.ready.set()
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    self.received = recv_exact(connection, expected)
                    connection.sendall(DC_RESPONSE)
                    self.response_sent.set()
                    self.release.wait(timeout=5)
        except BaseException as error:  # noqa: BLE001 - report worker failures to the test thread.
            self.error = error
            self.ready.set()
            self.response_sent.set()

    def stop(self) -> None:
        self.release.set()
        self.thread.join(timeout=2)


def wait_for_proxy(proc: subprocess.Popen[str], port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxy exited during startup with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.04)
    raise RuntimeError(f"proxy did not listen on port {port}: {last_error}")


def write_config(path: Path, port: int) -> None:
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
            idle_timeout_sec = 30
            handshake_timeout_sec = 5
            graceful_shutdown_timeout_sec = 2
            rate_limit_per_subnet = 0
            unsafe_override_limits = true
            log_level = "debug"

            [censorship]
            tls_domain = "{TLS_DOMAIN}"
            mask = false
            desync = false

            [access.users]
            e2e = "{SECRET_HEX}"
            """
        ),
        encoding="utf-8",
    )


def stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("process E2E is Linux-only; skipping")
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-bin", required=True)
    parser.add_argument("--obf-gen", required=True)
    args = parser.parse_args()

    proxy_bin = Path(args.proxy_bin).resolve()
    obf_gen = Path(args.obf_gen).resolve()
    if not proxy_bin.is_file() or not obf_gen.is_file():
        parser.error("--proxy-bin and --obf-gen must name built executables")

    sys.path.insert(0, str(ROOT / "test"))
    from capacity_connections_probe import build_tls_auth_client_hello

    fake_dc = FakeDatacenter()
    fake_dc.start()
    proxy_port = free_port()

    with tempfile.TemporaryDirectory(prefix="mtproto-process-e2e-") as temp_dir:
        config_path = Path(temp_dir) / "config.toml"
        log_path = Path(temp_dir) / "proxy.log"
        write_config(config_path, proxy_port)

        with log_path.open("w", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                [
                    str(proxy_bin),
                    str(config_path),
                    f"--e2e-dc-port={fake_dc.port}",
                ],
                cwd=ROOT,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                env=os.environ.copy(),
            )

        try:
            wait_for_proxy(proc, proxy_port, 8)
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
                client.settimeout(5)
                hello = build_tls_auth_client_hello(bytes.fromhex(SECRET_HEX), TLS_DOMAIN)
                client.sendall(hello)

                server_records = [recv_tls_record(client) for _ in range(3)]
                if [record_type for record_type, _ in server_records] != [0x16, 0x14, 0x17]:
                    raise AssertionError("proxy returned an invalid FakeTLS record sequence")

                handshake = generate_obfuscated_handshake(obf_gen)
                client.sendall(tls_record(0x14, b"\x01"))
                client.sendall(tls_record(0x17, handshake) + tls_record(0x17, CLIENT_PAYLOAD))

                if not fake_dc.response_sent.wait(timeout=5):
                    raise AssertionError("fake DC did not receive the relayed client payload")
                if fake_dc.error is not None:
                    raise RuntimeError("fake DC worker failed") from fake_dc.error

                record_type, response = recv_tls_record(client)
                if record_type != 0x17 or len(response) != len(DC_RESPONSE):
                    raise AssertionError(
                        "proxy did not return the fake DC response as one TLS application record"
                    )

            if len(fake_dc.received) != DC_NONCE_SIZE + len(CLIENT_PAYLOAD):
                raise AssertionError(
                    f"fake DC received {len(fake_dc.received)} bytes; "
                    f"expected {DC_NONCE_SIZE + len(CLIENT_PAYLOAD)}"
                )
        except BaseException as error:  # noqa: BLE001 - preserve complete process diagnostics.
            stop_process(proc)
            output = log_path.read_text(encoding="utf-8", errors="replace")
            print(output[-6000:], file=sys.stderr)
            print(f"process E2E failed: {error}", file=sys.stderr)
            return 1
        finally:
            fake_dc.stop()
            stop_process(proc)

    print("process E2E passed: FakeTLS, obfuscation, direct C2S and S2C relay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
