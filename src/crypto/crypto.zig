//! Cryptographic primitives for MTProto proxy.
//!
//! Wraps Zig's std.crypto for:
//! - AES-256-CTR (obfuscation layer)
//! - AES-256-CBC (middle proxy protocol)
//! - SHA-256, HMAC-SHA256 (TLS handshake validation, key derivation)
//! - MD5, SHA-1 (protocol-mandated for middle proxy KDF — not replaceable)

const std = @import("std");
const compat = @import("../compat.zig");
const Aes256 = std.crypto.core.aes.Aes256;

// ============= AES-256-CTR =============

/// AES-256-CTR stream cipher.
/// CTR mode is symmetric — encrypt and decrypt are the same operation.
pub const AesCtr = struct {
    /// Cached expanded key schedule (avoids re-computing on every apply())
    enc_ctx: EncCtx,
    /// Current counter value (big-endian u128)
    ctr: u128,
    /// Buffered keystream block
    buffer: [16]u8 = undefined,
    /// How many bytes remain in current keystream block
    buffer_pos: u8 = 16, // start exhausted so first call generates

    /// Expanded AES-256 encryption context type (backend-independent)
    const EncCtx = @TypeOf(Aes256.initEnc([_]u8{0} ** 32));

    /// Main AES-CTR batch width. Eight independent counter blocks expose enough
    /// instruction-level parallelism for the x86_64 AES-NI production target.
    const wide_blocks = 8;

    pub fn init(key: *const [32]u8, iv: u128) AesCtr {
        return .{
            .enc_ctx = Aes256.initEnc(key.*),
            .ctr = iv,
        };
    }

    pub fn initFromSlices(key: []const u8, iv: []const u8) !AesCtr {
        if (key.len != 32) return error.InvalidKeyLength;
        if (iv.len != 16) return error.InvalidIvLength;
        const k: *const [32]u8 = key[0..32];
        var iv_val = std.mem.readInt(u128, iv[0..16], .big);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&iv_val));
        return init(k, iv_val);
    }

    /// Apply keystream to data in-place (encrypt or decrypt).
    pub fn apply(self: *AesCtr, data: []u8) void {
        var i: usize = 0;

        // Finish a partial keystream block before entering the aligned bulk path.
        if (self.buffer_pos < 16 and i < data.len) {
            const available = @as(usize, 16 - self.buffer_pos);
            const take = @min(available, data.len - i);
            for (0..take) |j| data[i + j] ^= self.buffer[self.buffer_pos + j];
            self.buffer_pos += @intCast(take);
            i += take;
        }

        const wide_bytes = 16 * wide_blocks;
        while (data.len - i >= wide_bytes) {
            var counters: [wide_bytes]u8 = undefined;
            inline for (0..wide_blocks) |block_index| {
                std.mem.writeInt(
                    u128,
                    counters[block_index * 16 ..][0..16],
                    self.ctr +% @as(u128, block_index),
                    .big,
                );
            }
            const chunk: *[wide_bytes]u8 = data[i..][0..wide_bytes];
            self.enc_ctx.xorWide(wide_blocks, chunk, chunk, counters);
            self.ctr +%= wide_blocks;
            i += wide_bytes;
        }

        // Keep sub-128-byte tails on parallel AES rather than regressing them to
        // eight scalar encryptions after increasing the main batch width.
        inline for (.{ 4, 2, 1 }) |blocks| {
            const bytes = blocks * 16;
            if (data.len - i >= bytes) {
                var counters: [bytes]u8 = undefined;
                inline for (0..blocks) |block_index| {
                    std.mem.writeInt(
                        u128,
                        counters[block_index * 16 ..][0..16],
                        self.ctr +% @as(u128, block_index),
                        .big,
                    );
                }
                const chunk: *[bytes]u8 = data[i..][0..bytes];
                self.enc_ctx.xorWide(blocks, chunk, chunk, counters);
                self.ctr +%= blocks;
                i += bytes;
            }
        }

        // Preserve unused keystream bytes for continuity across apply() calls.
        while (i < data.len) {
            if (self.buffer_pos >= 16) {
                var ctr_bytes: [16]u8 = undefined;
                defer std.crypto.secureZero(u8, &ctr_bytes);
                std.mem.writeInt(u128, &ctr_bytes, self.ctr, .big);
                self.enc_ctx.encrypt(&self.buffer, &ctr_bytes);
                self.ctr +%= 1;
                self.buffer_pos = 0;
            }
            const available = @as(usize, 16 - self.buffer_pos);
            const take = @min(available, data.len - i);
            for (0..take) |j| data[i + j] ^= self.buffer[self.buffer_pos + j];
            self.buffer_pos += @intCast(take);
            i += take;
        }
    }

    /// Encrypt/decrypt into a new buffer.
    pub fn process(self: *AesCtr, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        self.apply(result);
        return result;
    }

    /// Securely wipe key material.
    pub fn wipe(self: *AesCtr) void {
        std.crypto.secureZero(u8, &self.buffer);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.ctr));
        // Wipe expanded key schedule
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enc_ctx));
    }
};

// ============= AES-256-CBC =============

fn xorBlockInPlace(block: *[16]u8, mask: *const [16]u8) void {
    const block_int: u128 = @bitCast(block.*);
    const mask_int: u128 = @bitCast(mask.*);
    block.* = @bitCast(block_int ^ mask_int);
}

/// Direction-specific AES-256-CBC encryptor with proper chaining.
pub const AesCbcEncryptor = struct {
    enc_ctx: EncCtx,
    iv: [16]u8,

    const block_size = 16;
    const EncCtx = @TypeOf(Aes256.initEnc([_]u8{0} ** 32));

    pub fn init(key: *const [32]u8, iv: *const [16]u8) AesCbcEncryptor {
        return .{
            .enc_ctx = Aes256.initEnc(key.*),
            .iv = iv.*,
        };
    }

    /// Encrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn encryptInPlace(self: *AesCbcEncryptor, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            xorBlockInPlace(block, &prev);
            var encrypted: [16]u8 = undefined;
            self.enc_ctx.encrypt(&encrypted, block);
            block.* = encrypted;
            prev = encrypted;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    pub fn wipe(self: *AesCbcEncryptor) void {
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enc_ctx));
    }
};

/// Direction-specific AES-256-CBC decryptor with proper chaining.
pub const AesCbcDecryptor = struct {
    dec_ctx: DecCtx,
    iv: [16]u8,

    const block_size = 16;
    const DecCtx = @TypeOf(Aes256.initDec([_]u8{0} ** 32));

    pub fn init(key: *const [32]u8, iv: *const [16]u8) AesCbcDecryptor {
        return .{
            .dec_ctx = Aes256.initDec(key.*),
            .iv = iv.*,
        };
    }

    /// Decrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn decryptInPlace(self: *AesCbcDecryptor, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        const wide_blocks = 4;
        const wide_bytes = block_size * wide_blocks;
        while (data.len - offset >= wide_bytes) : (offset += wide_bytes) {
            var encrypted: [wide_bytes]u8 = undefined;
            var decrypted: [wide_bytes]u8 = undefined;
            @memcpy(encrypted[0..], data[offset .. offset + wide_bytes]);
            self.dec_ctx.decryptWide(wide_blocks, &decrypted, &encrypted);

            for (0..wide_blocks) |block_index| {
                const block_offset = block_index * block_size;
                const block: *[16]u8 = data[offset + block_offset ..][0..16];
                block.* = decrypted[block_offset..][0..16].*;
                const chain = if (block_index == 0)
                    &prev
                else
                    encrypted[block_offset - block_size ..][0..16];
                xorBlockInPlace(block, chain);
            }
            prev = encrypted[wide_bytes - block_size ..][0..16].*;
        }

        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            const saved = block.*;
            // Decrypt
            var decrypted: [16]u8 = undefined;
            self.dec_ctx.decrypt(&decrypted, block);
            block.* = decrypted;
            xorBlockInPlace(block, &prev);
            prev = saved;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    pub fn wipe(self: *AesCbcDecryptor) void {
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.dec_ctx));
    }
};

/// Compatibility constructor for protocol tests and benchmarks that exercise
/// both CBC directions from one value. Runtime connection state uses the
/// direction-specific types above and therefore keeps only one key schedule.
pub const AesCbc = struct {
    encryptor: AesCbcEncryptor,
    decryptor: AesCbcDecryptor,

    pub fn init(key: *const [32]u8, iv: *const [16]u8) AesCbc {
        return .{
            .encryptor = .init(key, iv),
            .decryptor = .init(key, iv),
        };
    }

    pub fn encryptInPlace(self: *AesCbc, data: []u8) !void {
        return self.encryptor.encryptInPlace(data);
    }

    pub fn decryptInPlace(self: *AesCbc, data: []u8) !void {
        return self.decryptor.decryptInPlace(data);
    }

    pub fn intoEncryptor(self: AesCbc) AesCbcEncryptor {
        var legacy = self;
        legacy.decryptor.wipe();
        return legacy.encryptor;
    }

    pub fn intoDecryptor(self: AesCbc) AesCbcDecryptor {
        var legacy = self;
        legacy.encryptor.wipe();
        return legacy.decryptor;
    }

    pub fn wipe(self: *AesCbc) void {
        self.encryptor.wipe();
        self.decryptor.wipe();
    }
};

// ============= Hash Functions =============

/// SHA-256
pub fn sha256(data: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(data);
    return h.finalResult();
}

/// SHA-256 HMAC
pub fn sha256Hmac(key: []const u8, data: []const u8) [32]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var hmac = HmacSha256.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hmac));
    hmac.update(data);
    var mac: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &mac);
    hmac.final(&mac);
    return mac;
}

/// SHA-1 — protocol-required by Telegram Middle Proxy KDF.
pub fn sha1(data: []const u8) [20]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(data);
    return h.finalResult();
}

/// MD5 — protocol-required by Telegram Middle Proxy KDF.
pub fn md5(data: []const u8) [16]u8 {
    var h = std.crypto.hash.Md5.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(data);
    var out: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    h.final(&out);
    return out;
}

// ============= Secure Random =============

/// Fill buffer with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    compat.randomBytes(buf);
}

/// Generate a random integer.
pub fn randomInt(comptime T: type) T {
    return compat.randomInt(T);
}

/// Generate a random integer in [0, max).
pub fn randomRange(comptime T: type, max: T) T {
    return compat.randomRange(T, max);
}

// ============= Tests =============

test "AesCtr roundtrip" {
    const key = [_]u8{0} ** 32;
    const iv: u128 = 12345;
    const original = "Hello, MTProto!";

    var enc = AesCtr.init(&key, iv);
    var buf: [original.len]u8 = undefined;
    @memcpy(&buf, original);
    enc.apply(&buf);

    // encrypted should differ
    try std.testing.expect(!std.mem.eql(u8, &buf, original));

    var dec = AesCtr.init(&key, iv);
    dec.apply(&buf);

    try std.testing.expectEqualSlices(u8, original, &buf);
}

test "AesCtr wide path matches byte-at-a-time across boundaries and counter wrap" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 32;
    const iv: u128 = std.math.maxInt(u128) - 5;
    const lengths = [_]usize{
        0,   1,    15,  16,  17,  31,  63,  64,
        65,  127,  128, 129, 191, 192, 255, 256,
        257, 1000,
    };
    const chunk_sizes = [_]usize{ 3, 17, 65, 1, 127, 8, 31 };

    for (lengths) |len| {
        const plain = try allocator.alloc(u8, len);
        defer allocator.free(plain);
        for (plain, 0..) |*byte, index| byte.* = @truncate(index *% 73 +% len *% 29);

        const reference = try allocator.dupe(u8, plain);
        defer allocator.free(reference);
        var scalar = AesCtr.init(&key, iv);
        for (reference) |*byte| {
            var one = [_]u8{byte.*};
            scalar.apply(&one);
            byte.* = one[0];
        }

        const wide = try allocator.dupe(u8, plain);
        defer allocator.free(wide);
        var batched = AesCtr.init(&key, iv);
        batched.apply(wide);
        try std.testing.expectEqualSlices(u8, reference, wide);

        const chunked = try allocator.dupe(u8, plain);
        defer allocator.free(chunked);
        var split = AesCtr.init(&key, iv);
        var offset: usize = 0;
        var chunk_index: usize = 0;
        while (offset < len) : (chunk_index += 1) {
            const take = @min(len - offset, chunk_sizes[chunk_index % chunk_sizes.len]);
            split.apply(chunked[offset .. offset + take]);
            offset += take;
        }
        try std.testing.expectEqualSlices(u8, reference, chunked);
    }
}

test "AesCtr in-place symmetry" {
    const key = [_]u8{0x42} ** 32;
    const iv: u128 = 999;
    const original = "Test data for in-place encryption";

    var data: [original.len]u8 = undefined;
    @memcpy(&data, original);

    var c1 = AesCtr.init(&key, iv);
    c1.apply(&data);
    try std.testing.expect(!std.mem.eql(u8, &data, original));

    var c2 = AesCtr.init(&key, iv);
    c2.apply(&data);
    try std.testing.expectEqualSlices(u8, original, &data);
}

test "AesCbc roundtrip" {
    const key = [_]u8{0x12} ** 32;
    const iv = [_]u8{0x34} ** 16;

    var plaintext: [48]u8 = undefined;
    for (0..48) |i| {
        plaintext[i] = @intCast(i);
    }
    const original = plaintext;

    var encryptor = AesCbcEncryptor.init(&key, &iv);
    try encryptor.encryptInPlace(&plaintext);
    try std.testing.expect(!std.mem.eql(u8, &plaintext, &original));

    var decryptor = AesCbcDecryptor.init(&key, &iv);
    try decryptor.decryptInPlace(&plaintext);
    try std.testing.expectEqualSlices(u8, &original, &plaintext);
}

test "AesCbc chaining works" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x00} ** 16;
    var plaintext = [_]u8{0xAA} ** 32;

    var encryptor = AesCbcEncryptor.init(&key, &iv);
    try encryptor.encryptInPlace(&plaintext);

    // With CBC chaining, identical plaintext blocks should produce different ciphertext blocks
    try std.testing.expect(!std.mem.eql(u8, plaintext[0..16], plaintext[16..32]));
}

test "sha256 basic" {
    const hash = sha256("");
    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "sha256Hmac basic" {
    const mac = sha256Hmac("key", "The quick brown fox jumps over the lazy dog");
    // Known HMAC-SHA256 test vector
    const expected = [_]u8{
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &mac);
}

test "sha1 basic" {
    const hash = sha1("abc");
    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "md5 basic" {
    const hash = md5("message digest");
    const expected = [_]u8{
        0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
        0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}
