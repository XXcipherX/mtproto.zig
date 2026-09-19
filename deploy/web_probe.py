"""Private installer WEB end-to-end probe; all credentials arrive on stdin."""
import base64
import hashlib
from html.parser import HTMLParser
import json
import os
import re
import signal
import socket
import ssl
import struct
import sys
import time


class ProbeError(Exception):
    pass


class BridgeMetadata(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        attrs = dict(attrs)
        name = attrs.get("name")
        if name in ("tproxy-token", "tproxy-ws-path"):
            if name in self.values:
                raise ProbeError("duplicate bridge metadata")
            self.values[name] = attrs.get("content", "")


def frame(kind, stream=0, payload=b""):
    return bytes([kind]) + stream.to_bytes(3, "big") + struct.pack(">I", len(payload)) + payload


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise ProbeError("probe deadline exceeded")
    return value


def receive_exact(sock, length, deadline):
    result = bytearray()
    while len(result) < length:
        sock.settimeout(remaining(deadline))
        part = sock.recv(length - len(result))
        if not part:
            raise ProbeError("connection closed")
        result.extend(part)
    return bytes(result)


def receive_head(sock, deadline, limit=16384):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        if len(result) >= limit:
            raise ProbeError("oversized HTTP response")
        result.extend(receive_exact(sock, 1, deadline))
    return bytes(result)


def parse_head(raw):
    try:
        lines = raw.decode("ascii").split("\r\n")
        status = int(lines[0].split()[1])
    except (UnicodeDecodeError, IndexError, ValueError):
        raise ProbeError("malformed HTTP response")
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ProbeError("malformed HTTP header")
        name, value = line.split(":", 1)
        name = name.lower()
        if name in headers:
            raise ProbeError("duplicate HTTP header")
        headers[name] = value.strip()
    return status, headers


def open_tls(domain, address, port, context, deadline):
    raw = socket.create_connection((address, port), timeout=remaining(deadline))
    try:
        raw.settimeout(remaining(deadline))
        return context.wrap_socket(raw, server_hostname=domain)
    except Exception:
        raw.close()
        raise


def fetch_bridge(data, address, port, context, deadline):
    domain = data["domain"]
    path = data["bridge_path"]
    if not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
        raise ProbeError("invalid bridge path")
    target = path + "?bridge=" + data["capability"]
    with open_tls(domain, address, port, context, deadline) as sock:
        sock.settimeout(remaining(deadline))
        sock.sendall(("GET " + target + " HTTP/1.1\r\nHost: " + domain +
                      "\r\nConnection: close\r\n\r\n").encode("ascii"))
        status, headers = parse_head(receive_head(sock, deadline))
        if status != 200:
            raise ProbeError("bridge request failed")
        if "transfer-encoding" in headers:
            raise ProbeError("unsupported bridge framing")
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError):
            raise ProbeError("bridge length is missing")
        if length < 0 or length > 2 * 1024 * 1024:
            raise ProbeError("oversized bridge page")
        return receive_exact(sock, length, deadline)


def send_ws(sock, payload, opcode=2):
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", length)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", length)
    sock.sendall(header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))


def receive_ws(sock, deadline):
    while True:
        first, second = receive_exact(sock, 2, deadline)
        if first & 0x70 or not first & 0x80 or second & 0x80:
            raise ProbeError("invalid server websocket frame")
        length = second & 127
        if length == 126:
            length = struct.unpack(">H", receive_exact(sock, 2, deadline))[0]
        elif length == 127:
            length = struct.unpack(">Q", receive_exact(sock, 8, deadline))[0]
        opcode = first & 15
        if length > 1024 * 1024 + 8 or (opcode >= 8 and length > 125):
            raise ProbeError("oversized websocket frame")
        payload = receive_exact(sock, length, deadline)
        if opcode == 9:
            sock.settimeout(remaining(deadline))
            send_ws(sock, payload, 10)
        elif opcode == 10:
            continue
        elif opcode == 2:
            return payload
        else:
            raise ProbeError("websocket closed or returned nonbinary data")


def relay_frames(message):
    count = 0
    while message:
        count += 1
        if len(message) < 8 or count > 4096:
            raise ProbeError("invalid relay batch")
        kind = message[0]
        stream = int.from_bytes(message[1:4], "big")
        length = int.from_bytes(message[4:8], "big")
        if length > 1024 * 1024 or len(message) < 8 + length:
            raise ProbeError("incomplete relay frame")
        yield kind, stream, message[8:8 + length]
        message = message[8 + length:]


def run(data, *, address=None, port=443, context=None, timeout=8):
    # Per-read socket timeouts restart after every byte. SIGALRM bounds DNS, TCP, TLS,
    # HTTP, WSS and a trickling peer with one absolute deadline on production Linux.
    def expired(_signum, _frame):
        raise ProbeError("probe deadline exceeded")

    started = time.monotonic()
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        deadline = started + timeout
        return run_until(data, address or data["domain"], port,
                         context or ssl.create_default_context(), deadline)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL,
                             max(0.000001, previous_timer[0] - (time.monotonic() - started)),
                             previous_timer[1])


def run_until(data, address, port, context, deadline):
    domain = data["domain"]
    body = fetch_bridge(data, address, port, context, deadline)
    metadata = BridgeMetadata()
    metadata.feed(body.decode("utf-8", errors="strict"))
    token = metadata.values.get("tproxy-token", "")
    path = metadata.values.get("tproxy-ws-path", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token) or path != data["ws_path"]:
        raise ProbeError("authenticated bridge metadata is missing")

    protocol = "tproxy-v1." + token
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    with open_tls(domain, address, port, context, deadline) as sock:
        sock.settimeout(remaining(deadline))
        sock.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + domain +
                      "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Version: 13\r\nOrigin: https://" + domain +
                      "\r\nSec-WebSocket-Key: " + key +
                      "\r\nSec-WebSocket-Protocol: " + protocol + "\r\n\r\n").encode("ascii"))
        status, headers = parse_head(receive_head(sock, deadline))
        expected_accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        connection_tokens = [part.strip() for part in headers.get("connection", "").lower().split(",")]
        if (status != 101 or headers.get("sec-websocket-accept") != expected_accept or
                headers.get("sec-websocket-protocol") != protocol or
                headers.get("upgrade", "").lower() != "websocket" or
                "upgrade" not in connection_tokens):
            raise ProbeError("websocket upgrade was not authenticated")

        sock.settimeout(remaining(deadline))
        send_ws(sock, frame(0x10, payload=b"\x01"))
        if receive_ws(sock, deadline) != frame(0x11):
            raise ProbeError("missing WELCOME")
        sock.settimeout(remaining(deadline))
        send_ws(sock, frame(1, 1))
        send_ws(sock, frame(2, 1, bytes.fromhex(data["request"])))

        ciphertext = bytearray()
        keystream = bytes.fromhex(data["response_key"])
        nonce = bytes.fromhex(data["nonce"])
        while True:
            for kind, stream, payload in relay_frames(receive_ws(sock, deadline)):
                if kind == 5 and stream == 0 and len(payload) <= 64:
                    sock.settimeout(remaining(deadline))
                    send_ws(sock, frame(6, payload=payload))
                elif kind == 4 and stream == 1 and len(payload) == 4 and int.from_bytes(payload, "big") > 0:
                    continue
                elif kind == 2 and stream == 1 and payload:
                    ciphertext.extend(payload)
                else:
                    raise ProbeError("backend closed or returned invalid relay data")
            if len(ciphertext) > len(keystream):
                raise ProbeError("oversized backend reply")
            plain = bytes(value ^ keystream[i] for i, value in enumerate(ciphertext))
            if len(plain) < 4:
                continue
            length = struct.unpack("<I", plain[:4])[0]
            if length < 40 or length > len(keystream) - 4:
                raise ProbeError("invalid MTProto reply size")
            if len(plain) < length + 4:
                continue
            payload = plain[4:4 + length]
            real_length = 20 + struct.unpack("<I", payload[16:20])[0]
            if (payload[:8] != b"\0" * 8 or not 0 <= length - real_length <= 3 or
                    payload[20:24] != struct.pack("<I", 0x05162463) or payload[24:40] != nonce):
                raise ProbeError("backend did not return the expected res_pq")
            try:
                sock.settimeout(remaining(deadline))
                send_ws(sock, frame(3, 1))
            except OSError:
                pass
            return


if __name__ == "__main__":
    try:
        port = int(os.environ.get("WEB_PROBE_PORT", "443"))
        timeout = float(os.environ.get("WEB_PROBE_TIMEOUT", "12"))
        run(json.load(sys.stdin), address=os.environ.get("WEB_PROBE_ADDRESS"),
            port=port, timeout=timeout)
    except Exception:
        # Exception messages from TLS/HTTP libraries can contain credential-bearing
        # request targets. Never echo them from the installer helper.
        print("WEB_PROBE_FAILED")
        sys.exit(1)
    print("WEB_PROBE_OK")
