"""Native AES-CTR for the offline full-relay stress harness.

Ubuntu's system OpenSSL is used through ctypes: no per-connection process, Python
crypto package, package installation, or network access is needed at test time.
The key/IV derivation mirrors protocol/obfuscation.zig and proxy.sendDcNonce().
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import struct


_lib_name = ctypes.util.find_library("crypto")
if _lib_name is None:
    raise RuntimeError("system libcrypto is required by Stress CI")
_lib = ctypes.CDLL(_lib_name)
_void = ctypes.c_void_p
_lib.EVP_CIPHER_CTX_new.argtypes = []
_lib.EVP_CIPHER_CTX_new.restype = _void
_lib.EVP_CIPHER_CTX_free.argtypes = [_void]
_lib.EVP_CIPHER_CTX_free.restype = None
_lib.EVP_aes_256_ctr.argtypes = []
_lib.EVP_aes_256_ctr.restype = _void
_lib.EVP_EncryptInit_ex.argtypes = [_void, _void, _void, _void, _void]
_lib.EVP_EncryptInit_ex.restype = ctypes.c_int
_lib.EVP_EncryptUpdate.argtypes = [
    _void, _void, ctypes.POINTER(ctypes.c_int), _void, ctypes.c_int
]
_lib.EVP_EncryptUpdate.restype = ctypes.c_int


class AesCtr:
    """Stateful AES-256-CTR with the proxy's big-endian 128-bit counter."""

    __slots__ = ("_ctx",)

    def __init__(self, key: bytes, iv: bytes, skip_blocks: int = 0) -> None:
        self._ctx = None
        if len(key) != 32 or len(iv) != 16 or skip_blocks < 0:
            raise ValueError("AES-256-CTR requires a 32-byte key and 16-byte IV")
        counter = ((int.from_bytes(iv, "big") + skip_blocks) % (1 << 128)).to_bytes(
            16, "big"
        )
        ctx = _lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise MemoryError("EVP_CIPHER_CTX_new failed")
        key_buf = ctypes.create_string_buffer(key)
        iv_buf = ctypes.create_string_buffer(counter)
        if _lib.EVP_EncryptInit_ex(
            ctx, _lib.EVP_aes_256_ctr(), None, key_buf, iv_buf
        ) != 1:
            _lib.EVP_CIPHER_CTX_free(ctx)
            raise RuntimeError("EVP_EncryptInit_ex failed")
        self._ctx = ctx

    def apply(self, data: bytes) -> bytes:
        if not data:
            return b""
        if self._ctx is None:
            raise RuntimeError("cipher is closed")
        source = ctypes.create_string_buffer(data)
        output = ctypes.create_string_buffer(len(data) + 16)
        size = ctypes.c_int()
        if _lib.EVP_EncryptUpdate(
            self._ctx, output, ctypes.byref(size), source, len(data)
        ) != 1 or size.value != len(data):
            raise RuntimeError("EVP_EncryptUpdate failed")
        return output.raw[: size.value]

    def close(self) -> None:
        if self._ctx is not None:
            _lib.EVP_CIPHER_CTX_free(self._ctx)
            self._ctx = None

    def __del__(self) -> None:
        self.close()


def client_ciphers(handshake: bytes, secret: bytes) -> tuple[AesCtr, AesCtr]:
    """Return client C2S encryptor and S2C decryptor after the 64-byte nonce."""
    if len(handshake) != 64 or len(secret) != 16:
        raise ValueError("invalid obfuscated handshake or access secret")
    prekey_iv = handshake[8:56]
    send = AesCtr(hashlib.sha256(prekey_iv[:32] + secret).digest(), prekey_iv[32:], 4)
    reverse = prekey_iv[::-1]
    try:
        receive = AesCtr(hashlib.sha256(reverse[:32] + secret).digest(), reverse[32:])
    except BaseException:
        send.close()
        raise
    return send, receive


def dc_ciphers(nonce: bytes) -> tuple[AesCtr, AesCtr]:
    """Validate the real proxy's direct-DC nonce and return DC read/write CTR."""
    if len(nonce) != 64:
        raise ValueError("direct-DC nonce must be 64 bytes")
    prekey_iv = nonce[8:56]
    receive = AesCtr(prekey_iv[:32], prekey_iv[32:])
    decoded = receive.apply(nonce)
    if decoded[56:60] != b"\xee" * 4 or struct.unpack_from("<h", decoded, 60)[0] != 1:
        receive.close()
        raise ValueError("invalid direct-DC nonce tag or DC index")
    reverse = prekey_iv[::-1]
    try:
        send = AesCtr(reverse[:32], reverse[32:])
    except BaseException:
        receive.close()
        raise
    return receive, send
