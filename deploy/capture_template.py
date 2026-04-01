#!/usr/bin/env python3
"""
capture_template.py — Capture a real Nginx/OpenSSL TLS 1.3 ServerHello template.

Connects to a live HTTPS server (e.g. your tls_domain), captures the ServerHello +
CCS + first AppData, zeroes the mutable fields (random, session_id, x25519 key),
and saves the result as a binary template.

This template can be used to update the comptime Nginx template in tls.zig
when OpenSSL/Nginx updates change the ServerHello structure.

Usage:
    python3 capture_template.py [host] [port]
    python3 capture_template.py wb.ru 443
    python3 capture_template.py                  # defaults to wb.ru:443

Output:
    nginx_template.bin  — raw binary template (zeroed mutable fields)
    nginx_template.txt  — hex dump + field annotations

Requirements:
    Python 3.6+ (stdlib only, no pip packages)
"""

import socket
import struct
import sys
import os

# TLS 1.3 ClientHello (Chrome 120-like) — enough to trigger a real ServerHello
# This is a minimal ClientHello that advertises TLS 1.3 support
MINIMAL_CLIENT_HELLO = bytes.fromhex(
    # TLS Record: Handshake, TLS 1.0 (for compat), length placeholder
    "160301"
    "00c1"  # length = 193
    # Handshake: ClientHello
    "01"
    "0000bd"  # length = 189
    # Client Version: TLS 1.2 (real version in supported_versions ext)
    "0303"
    # Client Random (32 bytes)
    "0001020304050607080910111213141516171819202122232425262728293031"
    # Session ID length + 32-byte session ID (TLS 1.3 middlebox compat)
    "20"
    "e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0011223344"
    # Cipher suites (2 bytes length + suites)
    "0004"
    "1301"  # TLS_AES_128_GCM_SHA256
    "1303"  # TLS_CHACHA20_POLY1305_SHA256
    # Compression methods
    "0100"  # 1 method, null
    # Extensions length
    "006e"  # 110 bytes of extensions
    # SNI extension (will be patched with actual hostname)
    "0000"  # type: server_name
    "0000"  # length placeholder (patched below)
    "0000"  # server_name_list length placeholder
    "00"  # host_name type
    "0000"  # hostname length placeholder
    # ... hostname bytes will be appended
    # supported_groups
    "000a"
    "0004"
    "001d"  # x25519
    "0017"  # secp256r1
    # signature_algorithms
    "000d"
    "0008"
    "0403"  # ecdsa_secp256r1_sha256
    "0804"  # rsa_pss_rsae_sha256
    "0401"  # rsa_pkcs1_sha256
    "0201"  # rsa_pkcs1_sha1
    # supported_versions
    "002b"
    "0003"
    "02"
    "0304"  # TLS 1.3
    # key_share (x25519)
    "0033"
    "0026"
    "0024"
    "001d"  # x25519
    "0020"  # 32 bytes
    "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
)


def build_client_hello(hostname: str) -> bytes:
    """Build a TLS ClientHello with the given SNI hostname."""
    host_bytes = hostname.encode("ascii")
    host_len = len(host_bytes)

    # SNI extension payload:
    # ServerNameList length (2) + ServerName type (1) + hostname length (2) + hostname
    sni_list_len = 1 + 2 + host_len
    sni_ext_len = 2 + sni_list_len

    sni_ext = (
        b"\x00\x00"  # extension type: server_name
        + struct.pack("!H", sni_ext_len)
        + struct.pack("!H", sni_list_len)
        + b"\x00"  # host_name type
        + struct.pack("!H", host_len)
        + host_bytes
    )

    # Remaining extensions (after SNI)
    remaining_exts = bytes.fromhex(
        # supported_groups
        "000a"
        "0004"
        "001d"
        "0017"
        # signature_algorithms
        "000d"
        "0008"
        "0403"
        "0804"
        "0401"
        "0201"
        # supported_versions
        "002b"
        "0003"
        "02"
        "0304"
        # key_share (x25519)
        "0033"
        "0026"
        "0024"
        "001d"
        "0020"
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    )

    extensions = sni_ext + remaining_exts
    extensions_block = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body (after Handshake header)
    ch_body = (
        b"\x03\x03"  # client version TLS 1.2
        + bytes(range(32))  # client random
        + b"\x20"
        + bytes(range(0xE0, 0xE0 + 32))  # session ID
        + b"\x00\x04"
        + b"\x13\x01\x13\x03"  # cipher suites
        + b"\x01\x00"  # compression
        + extensions_block
    )

    # Handshake header
    handshake = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body

    # TLS record header
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    return record


def capture_server_hello(host: str, port: int) -> bytes:
    """Connect to host:port, send ClientHello, capture raw response bytes."""
    client_hello = build_client_hello(host)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    print(f"  Connecting to {host}:{port}...")
    sock.connect((host, port))

    print(f"  Sending ClientHello ({len(client_hello)} bytes)...")
    sock.sendall(client_hello)

    # Read response — we need ServerHello + CCS + first AppData
    # Real Nginx sends these as separate TLS records
    response = b""
    records_captured = 0
    target_records = 3  # ServerHello, CCS, AppData (encrypted extensions + cert + etc)

    while records_captured < target_records:
        # Read TLS record header (5 bytes)
        header = b""
        while len(header) < 5:
            chunk = sock.recv(5 - len(header))
            if not chunk:
                break
            header += chunk

        if len(header) < 5:
            print(f"  Connection closed after {records_captured} records")
            break

        record_type = header[0]
        record_version = struct.unpack("!H", header[1:3])[0]
        record_length = struct.unpack("!H", header[3:5])[0]

        # Read record body
        body = b""
        while len(body) < record_length:
            chunk = sock.recv(record_length - len(body))
            if not chunk:
                break
            body += chunk

        record_type_name = {
            0x14: "ChangeCipherSpec",
            0x15: "Alert",
            0x16: "Handshake",
            0x17: "ApplicationData",
        }.get(record_type, f"Unknown(0x{record_type:02x})")

        print(
            f"  Record #{records_captured + 1}: {record_type_name}, "
            f"version=0x{record_version:04x}, length={record_length}"
        )

        response += header + body
        records_captured += 1

    sock.close()
    return response


def analyze_server_hello(data: bytes) -> dict:
    """Parse the ServerHello to find mutable field offsets."""
    if len(data) < 5:
        raise ValueError("Response too short")

    offsets = {}
    pos = 0

    # First record should be Handshake (ServerHello)
    if data[0] != 0x16:
        raise ValueError(f"Expected Handshake record (0x16), got 0x{data[0]:02x}")

    record_len = struct.unpack("!H", data[3:5])[0]
    pos = 5  # skip TLS record header

    # Handshake header
    if data[pos] != 0x02:
        raise ValueError(f"Expected ServerHello (0x02), got 0x{data[pos]:02x}")

    hs_len = struct.unpack("!I", b"\x00" + data[pos + 1 : pos + 4])[0]
    pos += 4  # skip handshake header

    # Server version (2 bytes)
    server_version = struct.unpack("!H", data[pos : pos + 2])[0]
    pos += 2

    # Server random (32 bytes) — MUTABLE
    offsets["random"] = {"offset": pos, "length": 32}
    print(f"  random:     offset={pos}, length=32")
    pos += 32

    # Session ID length + session ID — MUTABLE
    session_id_len = data[pos]
    pos += 1
    offsets["session_id"] = {"offset": pos, "length": session_id_len}
    print(f"  session_id: offset={pos}, length={session_id_len}")
    pos += session_id_len

    # Cipher suite (2 bytes)
    cipher = struct.unpack("!H", data[pos : pos + 2])[0]
    print(f"  cipher:     0x{cipher:04x}")
    pos += 2

    # Compression method (1 byte)
    pos += 1

    # Extensions
    if pos < 5 + record_len:
        ext_total_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2

        ext_end = pos + ext_total_len
        ext_idx = 0
        while pos < ext_end:
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            ext_len = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
            ext_data = data[pos + 4 : pos + 4 + ext_len]

            ext_name = {
                0x002B: "supported_versions",
                0x0033: "key_share",
            }.get(ext_type, f"0x{ext_type:04x}")

            print(f"  ext[{ext_idx}]:    {ext_name} (len={ext_len})")

            if ext_type == 0x0033:  # key_share
                # key_share contains: group (2) + key_len (2) + key (32)
                key_offset = pos + 4 + 4  # skip ext header + group + key_len
                offsets["x25519_key"] = {"offset": key_offset, "length": 32}
                print(f"  x25519_key: offset={key_offset}, length=32")

            pos += 4 + ext_len
            ext_idx += 1

    # Total ServerHello record size
    sh_record_size = 5 + record_len
    print(f"  ServerHello record: {sh_record_size} bytes")

    offsets["server_hello_end"] = sh_record_size
    return offsets


def create_template(data: bytes, offsets: dict) -> bytes:
    """Zero out mutable fields to create a reusable template."""
    template = bytearray(data)

    for field_name in ("random", "session_id", "x25519_key"):
        if field_name in offsets:
            off = offsets[field_name]["offset"]
            length = offsets[field_name]["length"]
            template[off : off + length] = b"\x00" * length
            print(f"  Zeroed {field_name} at offset {off} ({length} bytes)")

    return bytes(template)


def write_hex_dump(data: bytes, path: str, offsets: dict):
    """Write an annotated hex dump."""
    with open(path, "w") as f:
        f.write(f"# Nginx/OpenSSL TLS 1.3 ServerHello Template\n")
        f.write(f"# Total size: {len(data)} bytes\n")
        f.write(f"# Mutable fields (zeroed):\n")
        for name in ("random", "session_id", "x25519_key"):
            if name in offsets:
                o = offsets[name]
                f.write(f"#   {name}: offset={o['offset']}, length={o['length']}\n")
        f.write(f"#\n")
        f.write(f"# To use in tls.zig, update buildNginxTemplate() with these bytes.\n")
        f.write(f"#\n\n")

        # Hex dump with offset annotations
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            f.write(f"{i:04x}:  {hex_str:<48s}  |{ascii_str}|\n")

        f.write(f"\n# Zig comptime array (paste into tls.zig buildNginxTemplate):\n")
        f.write(f"# const template = [_]u8{{\n")
        for i in range(0, len(data), 12):
            chunk = data[i : i + 12]
            hex_vals = ", ".join(f"0x{b:02x}" for b in chunk)
            f.write(f"#     {hex_vals},\n")
        f.write(f"# }};\n")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "wb.ru"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"\n  Capturing TLS ServerHello from {host}:{port}\n")

    # Step 1: Capture raw response
    response = capture_server_hello(host, port)
    if not response:
        print("\n  ERROR: No response received")
        sys.exit(1)

    print(f"\n  Total captured: {len(response)} bytes\n")

    # Step 2: Analyze ServerHello structure
    print("  Analyzing ServerHello structure:")
    offsets = analyze_server_hello(response)

    # Step 3: Create template (zero mutable fields)
    print(f"\n  Creating template:")
    template = create_template(response, offsets)

    # Step 4: Write outputs
    bin_path = "nginx_template.bin"
    txt_path = "nginx_template.txt"

    with open(bin_path, "wb") as f:
        f.write(template)
    print(f"  Wrote {bin_path} ({len(template)} bytes)")

    write_hex_dump(template, txt_path, offsets)
    print(f"  Wrote {txt_path}")

    # Step 5: Print summary for tls.zig
    print(f"\n  Summary for tls.zig:")
    print(
        f"    tmpl_random_offset     = {offsets.get('random', {}).get('offset', '?')}"
    )
    print(
        f"    tmpl_session_id_offset = {offsets.get('session_id', {}).get('offset', '?')}"
    )
    print(
        f"    tmpl_x25519_key_offset = {offsets.get('x25519_key', {}).get('offset', '?')}"
    )
    print(f"    Total template size    = {len(template)}")
    print()


if __name__ == "__main__":
    main()
