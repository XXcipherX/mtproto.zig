const std = @import("std");
const Io = std.Io;
const constants = @import("protocol/constants.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const crypto = @import("crypto/crypto.zig");

fn usage() noreturn {
    std.debug.print("usage: e2e-obf-handshake-gen <secret_hex32> <dc_idx> [abridged|intermediate|secure]\n", .{});
    std.process.exit(2);
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();

    var args = try init.minimal.args.iterateAllocator(allocator);
    defer args.deinit();
    _ = args.next();

    const secret_hex = args.next() orelse usage();
    if (secret_hex.len != 32) usage();
    const dc_idx_text = args.next() orelse usage();
    const proto_text = args.next() orelse "intermediate";
    if (args.next() != null) usage();

    const dc_idx = std.fmt.parseInt(i16, dc_idx_text, 10) catch usage();
    if (dc_idx == 0) usage();

    const proto_tag: constants.ProtoTag = if (std.mem.eql(u8, proto_text, "abridged"))
        .abridged
    else if (std.mem.eql(u8, proto_text, "intermediate"))
        .intermediate
    else if (std.mem.eql(u8, proto_text, "secure"))
        .secure
    else
        usage();

    var secret: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    _ = std.fmt.hexToBytes(&secret, secret_hex) catch usage();

    var plain = obfuscation.generateNonce();
    defer std.crypto.secureZero(u8, &plain);
    const tag_bytes = proto_tag.toBytes();
    @memcpy(plain[constants.proto_tag_pos..][0..4], &tag_bytes);
    std.mem.writeInt(i16, plain[constants.dc_idx_pos..][0..2], dc_idx, .little);

    const prekey = plain[constants.skip_len .. constants.skip_len + constants.prekey_len];
    const iv_bytes = plain[constants.skip_len + constants.prekey_len .. constants.skip_len + constants.prekey_len + constants.iv_len];
    const iv = std.mem.readInt(u128, iv_bytes, .big);

    var key_input: [constants.prekey_len + 16]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_input);
    @memcpy(key_input[0..constants.prekey_len], prekey);
    @memcpy(key_input[constants.prekey_len..], &secret);
    var key = crypto.sha256(&key_input);
    defer std.crypto.secureZero(u8, &key);

    var encryptor = crypto.AesCtr.init(&key, iv);
    defer encryptor.wipe();
    var encrypted = plain;
    defer std.crypto.secureZero(u8, &encrypted);
    encryptor.apply(&encrypted);

    var wire = plain;
    defer std.crypto.secureZero(u8, &wire);
    @memcpy(wire[constants.proto_tag_pos..], encrypted[constants.proto_tag_pos..]);

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    const encoded = std.fmt.bytesToHex(wire, .lower);
    try stdout.writeAll(encoded[0..]);
    try stdout.writeByte('\n');
    try stdout.flush();
}
