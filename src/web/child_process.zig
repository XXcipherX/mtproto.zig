const std = @import("std");
const builtin = @import("builtin");

/// Linux deployments require GNU env to unblock and reset inherited signals.
/// Reset the signalfd owner's inherited mask in the child, never on a live
/// event-loop thread. No shell interpolation; the original argv stays separate.
pub fn run(allocator: std.mem.Allocator, io: std.Io, requested: std.process.RunOptions) !std.process.RunResult {
    var options = requested;
    if (options.timeout == .none) options.timeout = .{ .duration = .{ .raw = .fromSeconds(12), .clock = .awake } };
    if (builtin.target.os.tag != .linux) return std.process.run(allocator, io, options);
    const argv = try allocator.alloc([]const u8, options.argv.len + 2);
    defer allocator.free(argv);
    // Ubuntu 26.04's default Rust env resets handlers but leaves signals blocked.
    // Its GNU variant is installed alongside it under a prefixed name.
    argv[0] = "/usr/bin/gnuenv";
    // Select before spawning so an absent gnuenv does not create a failed child.
    std.Io.Dir.accessAbsolute(io, argv[0], .{ .execute = true }) catch |err| switch (err) {
        error.FileNotFound => argv[0] = "/usr/bin/env", // GNU on Debian/Ubuntu 24.04.
        else => return err,
    };
    argv[1] = "--default-signal=TERM,INT,HUP,USR1";
    @memcpy(argv[2..], options.argv);
    options.argv = argv;
    return std.process.run(allocator, io, options);
}

test "child runner clears inherited signalfd signal mask" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    var mask = std.posix.sigemptyset();
    std.posix.sigaddset(&mask, .TERM);
    var old: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &mask, &old);
    defer std.posix.sigprocmask(std.posix.SIG.SETMASK, &old, null);
    // Initialize after blocking TERM so any backend worker inherits the same
    // mask that the production signalfd owner passes through exec.
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const result = try run(std.testing.allocator, threaded.io(), .{ .argv = &.{ "/bin/sh", "-c", "kill -TERM $$; exit 99" } });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    if (result.term != .signal) std.debug.print("expected SIGTERM termination, got {any}; stderr: {s}\n", .{ result.term, result.stderr });
    try std.testing.expect(result.term == .signal);
    try std.testing.expectEqual(std.posix.SIG.TERM, result.term.signal);
}
