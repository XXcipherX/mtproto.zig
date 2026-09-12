const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.cpu.arch != .x86_64) {
        @compileError("hardware AES probe expects the published x86_64 target");
    }
    if (!std.crypto.core.aes.has_hardware_support) {
        @compileError("optimized Docker CPU profile does not enable Zig's hardware AES backend");
    }
}

export fn hardwareAesProbe() void {}
