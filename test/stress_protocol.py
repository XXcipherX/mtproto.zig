"""Asyncio peers for real FakeTLS -> obfuscated MTProto -> direct-DC relay stress.

The synthetic DC speaks the direct obfuscation transport, not Telegram's remote
service. Every request is an intermediate-framed, checksummed test message and
every response is tied to that connection and sequence number.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import struct
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

from capacity_connections_probe import build_tls_auth_client_hello
from stress_crypto import AesCtr, client_ciphers, dc_ciphers


SECRET_HEX = "00112233445566778899aabbccddeeff"
TLS_DOMAIN = "stress.example"
REQ_MAGIC = b"MTSQ"
RESP_MAGIC = b"MTSR"
PAYLOAD_MIN = 64
PAYLOAD_MAX = 16_000
# A held relay may intentionally send nothing for an entire endurance run.
# Outlive both the hosted 45-minute job and its one-hour proxy idle horizon.
DC_NEXT_FRAME_TIMEOUT_SEC = 61 * 60
DC_INCOMPLETE_FRAME_TIMEOUT_SEC = 30
_HEADER = struct.Struct("<4sQI")
_DIGEST_LEN = 16


class IntegrityError(RuntimeError):
    """A payload, frame, nonce, session ID or sequence failed validation."""


@dataclass
class DcResponseBurst:
    expected_frames: int
    packets: bytearray = field(default_factory=bytearray)
    collected_frames: int = 0
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)


def request_body(connection_id: int, sequence: int, size: int) -> bytes:
    if not (PAYLOAD_MIN <= size <= PAYLOAD_MAX):
        raise ValueError("payload size is outside the safe intermediate-frame range")
    header = _HEADER.pack(REQ_MAGIC, connection_id, sequence)
    repeat = hashlib.blake2s(struct.pack("<QI", connection_id, sequence)).digest()
    filler_size = size - len(header) - _DIGEST_LEN
    filler = (repeat * ((filler_size + len(repeat) - 1) // len(repeat)))[:filler_size]
    content = header + filler
    return content + hashlib.blake2s(content, digest_size=_DIGEST_LEN).digest()


def parse_request(body: bytes) -> tuple[int, int]:
    if len(body) < PAYLOAD_MIN or len(body) > PAYLOAD_MAX:
        raise IntegrityError(f"invalid request size {len(body)}")
    magic, connection_id, sequence = _HEADER.unpack_from(body)
    if magic != REQ_MAGIC:
        raise IntegrityError("wrong request magic")
    expected = request_body(connection_id, sequence, len(body))
    if body != expected:
        raise IntegrityError("request payload/checksum mismatch")
    return connection_id, sequence


def response_body(request: bytes) -> bytes:
    connection_id, sequence = parse_request(request)
    filler = request[_HEADER.size : -_DIGEST_LEN][::-1]
    content = _HEADER.pack(RESP_MAGIC, connection_id, sequence) + filler
    return content + hashlib.blake2s(content, digest_size=_DIGEST_LEN).digest()


def tls_record(record_type: int, payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("TLS record too large")
    return bytes((record_type, 3, 3)) + struct.pack(">H", len(payload)) + payload


async def read_tls_record(
    reader: asyncio.StreamReader, timeout: float
) -> tuple[int, bytes]:
    header = await asyncio.wait_for(reader.readexactly(5), timeout)
    if header[1:3] != b"\x03\x03":
        raise IntegrityError("invalid FakeTLS record version")
    size = struct.unpack_from(">H", header, 3)[0]
    if size == 0 or size > 18_000:
        raise IntegrityError(f"invalid FakeTLS record size {size}")
    return header[0], await asyncio.wait_for(reader.readexactly(size), timeout)


async def read_dc_frame(reader: asyncio.StreamReader, cipher: AesCtr) -> bytes | None:
    encrypted_header = await asyncio.wait_for(reader.read(4), DC_NEXT_FRAME_TIMEOUT_SEC)
    if not encrypted_header:
        return None
    if len(encrypted_header) < 4:
        try:
            encrypted_header += await asyncio.wait_for(
                reader.readexactly(4 - len(encrypted_header)), DC_INCOMPLETE_FRAME_TIMEOUT_SEC
            )
        except asyncio.IncompleteReadError as error:
            raise IntegrityError("truncated direct-DC frame header") from error
    size = struct.unpack("<I", cipher.apply(encrypted_header))[0]
    if not (PAYLOAD_MIN <= size <= PAYLOAD_MAX):
        raise IntegrityError(f"invalid direct-DC frame size {size}")
    try:
        encrypted_body = await asyncio.wait_for(
            reader.readexactly(size), DC_INCOMPLETE_FRAME_TIMEOUT_SEC
        )
    except asyncio.IncompleteReadError as error:
        raise IntegrityError("truncated direct-DC frame body") from error
    return cipher.apply(encrypted_body)


class FakeDatacenter:
    def __init__(self, log_path: Path, slow_percent: int) -> None:
        self.log_path = log_path
        self.slow_percent = slow_percent
        self.server: asyncio.AbstractServer | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.writers_by_id: dict[int, asyncio.StreamWriter] = {}
        self.paused_receive_buffers: dict[int, int] = {}
        self.response_bursts: dict[int, DcResponseBurst] = {}
        self.seen_ids: set[int] = set()
        self.active_ids: set[int] = set()
        self.requests_by_id: dict[int, int] = {}
        self.responses_by_id: dict[int, int] = {}
        self.close_reasons: Counter[str] = Counter()
        self.recent_closes: deque[dict[str, object]] = deque(maxlen=200)
        self.started_at = time.monotonic()
        self.accepted = 0
        self.validated = 0
        self.responses = 0
        self.protocol_errors = 0
        self.errors: list[str] = []
        self.stopping = False
        self.stop_diagnostics: dict[str, int | float] = {}

    async def start(self) -> int:
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, backlog=4096, limit=64 * 1024
        )
        return int(self.server.sockets[0].getsockname()[1])

    def _error(self, error: BaseException) -> None:
        if self.stopping:
            return
        self.protocol_errors += 1
        detail = f"{type(error).__name__}: {error}"
        if len(self.errors) < 100:
            self.errors.append(detail)
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write(detail + "\n")

    def pause_receiving(self, connection_id: int, requested_buffer: int) -> int:
        """Stop only this synthetic DC peer's reads; report Linux's effective buffer."""
        writer = self.writers_by_id[connection_id]
        if connection_id in self.paused_receive_buffers:
            raise RuntimeError(f"DC {connection_id} is already paused")
        sock = writer.get_extra_info("socket")
        if sock is None:
            raise RuntimeError(f"DC {connection_id} has no socket")
        original = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, requested_buffer)
        try:
            effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            writer.transport.pause_reading()
        except BaseException:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, original)
            raise
        self.paused_receive_buffers[connection_id] = original
        return effective

    def resume_receiving(self, connection_id: int) -> None:
        original = self.paused_receive_buffers.pop(connection_id)
        writer = self.writers_by_id.get(connection_id)
        if writer is None:
            return
        sock = writer.get_extra_info("socket")
        try:
            if sock is not None and sock.fileno() >= 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, original)
        finally:
            writer.transport.resume_reading()

    def prepare_response_burst(self, connection_id: int, frames: int) -> DcResponseBurst:
        if connection_id not in self.active_ids or connection_id in self.response_bursts:
            raise RuntimeError(f"DC {connection_id} cannot prepare response burst")
        burst = DcResponseBurst(frames)
        self.response_bursts[connection_id] = burst
        return burst

    def release_response_burst(self, connection_id: int) -> None:
        burst = self.response_bursts.get(connection_id)
        if burst is not None:
            burst.release.set()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        self.writers.add(writer)
        self.accepted += 1
        receive: AesCtr | None = None
        send: AesCtr | None = None
        bound_id: int | None = None
        next_sequence = 0
        close_reason = "dc_read_eof"
        try:
            nonce = await asyncio.wait_for(reader.readexactly(64), 30)
            receive, send = dc_ciphers(nonce)
            while True:
                if bound_id is not None and bound_id % 100 < self.slow_percent:
                    await asyncio.sleep(0.04)
                body = await read_dc_frame(reader, receive)
                if body is None:
                    break
                connection_id, sequence = parse_request(body)
                if bound_id is None:
                    if connection_id in self.seen_ids:
                        raise IntegrityError(f"duplicate logical connection {connection_id}")
                    self.seen_ids.add(connection_id)
                    bound_id = connection_id
                    self.active_ids.add(connection_id)
                    self.writers_by_id[connection_id] = writer
                elif connection_id != bound_id:
                    raise IntegrityError("another connection's request entered this DC socket")
                if sequence != next_sequence:
                    raise IntegrityError(
                        f"connection {connection_id} sequence {sequence}, expected {next_sequence}"
                    )
                next_sequence += 1
                self.validated += 1
                self.requests_by_id[connection_id] = next_sequence
                response = response_body(body)
                packet = send.apply(struct.pack("<I", len(response)) + response)
                burst = self.response_bursts.get(bound_id)
                if burst is not None:
                    burst.packets.extend(packet)
                    burst.collected_frames += 1
                    if burst.collected_frames > burst.expected_frames:
                        raise IntegrityError(f"DC {bound_id} exceeded its planned response burst")
                    if burst.collected_frames == burst.expected_frames:
                        burst.ready.set()
                        await burst.release.wait()
                        writer.write(burst.packets)
                        await writer.drain()
                        self.responses += burst.collected_frames
                        self.responses_by_id[connection_id] = next_sequence
                        self.response_bursts.pop(bound_id, None)
                    continue
                if bound_id % 100 < self.slow_percent:
                    for offset in range(0, len(packet), 512):
                        writer.write(packet[offset : offset + 512])
                        await writer.drain()
                        await asyncio.sleep(0.001)
                else:
                    writer.write(packet)
                    await writer.drain()
                self.responses += 1
                self.responses_by_id[connection_id] = next_sequence
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError) as error:
            close_reason = type(error).__name__
        except asyncio.CancelledError:
            close_reason = "cancelled"
        except BaseException as error:  # Keep async callback failures visible to CI.
            close_reason = type(error).__name__
            self._error(error)
        finally:
            label = f"teardown_{close_reason}" if self.stopping else close_reason
            self.close_reasons[label] += 1
            self.recent_closes.append({
                "at_s": round(time.monotonic() - self.started_at, 3),
                "connection_id": bound_id,
                "reason": label,
                "last_request_sequence": next_sequence - 1,
            })
            if receive is not None:
                receive.close()
            if send is not None:
                send.close()
            writer.close()
            if bound_id is not None:
                self.active_ids.discard(bound_id)
                self.writers_by_id.pop(bound_id, None)
                self.paused_receive_buffers.pop(bound_id, None)
                self.response_bursts.pop(bound_id, None)
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def stop(self) -> None:
        began = time.monotonic()
        self.stopping = True
        tasks = tuple(self.tasks)
        self.stop_diagnostics = {"handlers_before": len(tasks), "leftover_tasks": 0}
        if self.server is not None:
            self.server.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=8)
            for task in pending:
                task.cancel()
            if pending:
                for writer in tuple(self.writers):
                    writer.transport.abort()
                _, pending = await asyncio.wait(pending, timeout=1)
            self.stop_diagnostics["leftover_tasks"] = len(pending)
        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=3)
            except TimeoutError:
                self.stop_diagnostics["server_wait_timeout"] = 1
        self.stop_diagnostics["elapsed_s"] = round(time.monotonic() - began, 2)


class ClientSession:
    def __init__(
        self,
        connection_id: int,
        user: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        transmit: AesCtr,
        receive: AesCtr,
    ) -> None:
        self.connection_id = connection_id
        self.user = user
        self.reader = reader
        self.writer = writer
        self.transmit = transmit
        self.receive = receive
        self.sequence = 0
        self.buffer = bytearray()
        self.closed = False
        self.socket_fd = writer.get_extra_info("socket").fileno()
        self.last_drained_sequence = -1
        self.last_validated_sequence = -1
        self.write_eof_sent = False
        self.saw_eof = False
        self.last_read_error: str | None = None
        self._saved_receive_buffer: int | None = None

    @classmethod
    async def open(
        cls,
        connection_id: int,
        user: int,
        proxy_port: int,
        handshake: bytes,
        payload_size: int,
        timeout: float,
    ) -> ClientSession:
        # Linux routes the full 127/8 block locally. Four source /24s keep a
        # high-churn generator from exhausting one client-side 4-tuple range.
        source_ip = f"127.{1 + connection_id % 4}.0.1"
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1", proxy_port, local_addr=(source_ip, 0), limit=64 * 1024
            ),
            timeout,
        )
        transmit: AesCtr | None = None
        receive: AesCtr | None = None
        try:
            hello = build_tls_auth_client_hello(bytes.fromhex(SECRET_HEX), TLS_DOMAIN)
            writer.write(hello)
            await asyncio.wait_for(writer.drain(), timeout)
            records = [await read_tls_record(reader, timeout) for _ in range(3)]
            if [kind for kind, _ in records] != [0x16, 0x14, 0x17]:
                raise IntegrityError("invalid FakeTLS server record sequence")
            transmit, receive = client_ciphers(handshake, bytes.fromhex(SECRET_HEX))
            session = cls(connection_id, user, reader, writer, transmit, receive)
            # Pipeline the first framed request after the real obfuscated nonce.
            prefix = tls_record(0x14, b"\x01") + tls_record(0x17, handshake)
            await session.exchange_batch(1, payload_size, timeout, prefix=prefix)
            return session
        except BaseException:
            writer.close()
            if transmit is not None:
                transmit.close()
            if receive is not None:
                receive.close()
            raise

    async def _read_response(self, expected: bytes, sequence: int, timeout: float) -> None:
        while len(self.buffer) < 4:
            await self._read_application_record(timeout)
        size = struct.unpack_from("<I", self.buffer)[0]
        if not (PAYLOAD_MIN <= size <= PAYLOAD_MAX):
            raise IntegrityError(f"invalid client response frame size {size}")
        while len(self.buffer) < 4 + size:
            await self._read_application_record(timeout)
        body = bytes(self.buffer[4 : 4 + size])
        del self.buffer[: 4 + size]
        if body != expected:
            raise IntegrityError(
                f"response mismatch for connection={self.connection_id} "
                f"sequence={sequence}"
            )
        self.last_validated_sequence = sequence

    async def _read_application_record(self, timeout: float) -> None:
        try:
            kind, payload = await read_tls_record(self.reader, timeout)
        except (OSError, asyncio.IncompleteReadError) as error:
            self.saw_eof = self.reader.at_eof()
            self.last_read_error = f"{type(error).__name__}: {error}"
            raise
        if kind != 0x17:
            raise IntegrityError(f"unexpected relay TLS record type {kind}")
        self.buffer.extend(self.receive.apply(payload))

    async def exchange_batch(
        self,
        count: int,
        payload_size: int,
        timeout: float,
        *,
        prefix: bytes = b"",
        read_delay: float = 0,
        half_close: bool = False,
    ) -> None:
        if self.closed or count < 1:
            raise ValueError("closed session or empty exchange batch")
        outbound = bytearray(prefix)
        expected: list[tuple[int, bytes]] = []
        for _ in range(count):
            sequence = self.sequence
            request = request_body(self.connection_id, sequence, payload_size)
            expected.append((sequence, response_body(request)))
            packet = struct.pack("<I", len(request)) + request
            outbound.extend(tls_record(0x17, self.transmit.apply(packet)))
            self.sequence += 1
        self.writer.write(outbound)
        await asyncio.wait_for(self.writer.drain(), timeout)
        self.last_drained_sequence = expected[-1][0]
        if half_close:
            if not self.writer.can_write_eof():
                raise RuntimeError("TCP half-close unavailable")
            self.writer.write_eof()
            self.write_eof_sent = True
        if read_delay:
            await asyncio.sleep(read_delay)
        for sequence, response in expected:
            await self._read_response(response, sequence, timeout)
        if half_close:
            trailing = await asyncio.wait_for(self.reader.read(1), timeout)
            if trailing:
                raise IntegrityError("unexpected data after half-close response")
            self.saw_eof = True

    def pause_receiving(self, requested_buffer: int) -> int:
        """Apply pressure to the test client, never to the proxy socket."""
        if self._saved_receive_buffer is not None:
            raise RuntimeError(f"client {self.connection_id} is already paused")
        sock = self.writer.get_extra_info("socket")
        if sock is None:
            raise RuntimeError(f"client {self.connection_id} has no socket")
        original = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, requested_buffer)
        try:
            effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.writer.transport.pause_reading()
        except BaseException:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, original)
            raise
        self._saved_receive_buffer = original
        return effective

    def resume_receiving(self) -> None:
        original = self._saved_receive_buffer
        if original is None:
            raise RuntimeError(f"client {self.connection_id} is not paused")
        self._saved_receive_buffer = None
        sock = self.writer.get_extra_info("socket")
        try:
            if sock is not None and sock.fileno() >= 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, original)
        finally:
            self.writer.transport.resume_reading()

    async def enqueue_pressure_requests(self, count: int, payload_size: int) -> tuple[int, int]:
        """Queue a bounded burst without waiting for peer reads or responses."""
        if self.closed or count < 1:
            raise ValueError("closed session or empty pressure burst")
        first_sequence = self.sequence
        bytes_written = 0
        for index in range(count):
            request = request_body(self.connection_id, self.sequence, payload_size)
            packet = tls_record(0x17, self.transmit.apply(struct.pack("<I", len(request)) + request))
            self.writer.write(packet)
            bytes_written += len(packet)
            self.sequence += 1
            if index % 32 == 31:
                await asyncio.sleep(0)
        return first_sequence, bytes_written

    async def drain_pressure_requests(self, timeout: float) -> None:
        await asyncio.wait_for(self.writer.drain(), timeout)
        self.last_drained_sequence = self.sequence - 1

    async def receive_pressure_responses(
        self, first_sequence: int, count: int, payload_size: int, timeout: float
    ) -> None:
        for sequence in range(first_sequence, first_sequence + count):
            request = request_body(self.connection_id, sequence, payload_size)
            await self._read_response(response_body(request), sequence, timeout)

    def diagnostics(self) -> dict[str, object]:
        sock = self.writer.get_extra_info("socket")
        return {
            "socket_fd": None if sock is None else sock.fileno(),
            "closed_by_harness": self.closed,
            "writer_closing": self.writer.is_closing(),
            "reader_at_eof": self.reader.at_eof(),
            "reader_exception": None if self.reader.exception() is None else
                f"{type(self.reader.exception()).__name__}: {self.reader.exception()}",
            "write_eof_sent": self.write_eof_sent,
            "saw_eof": self.saw_eof,
            "last_drained_sequence": self.last_drained_sequence,
            "last_validated_sequence": self.last_validated_sequence,
            "last_read_error": self.last_read_error,
        }

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.writer.close()
        self.transmit.close()
        self.receive.close()
