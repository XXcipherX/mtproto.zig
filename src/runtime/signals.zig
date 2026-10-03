//! SIGINT/SIGTERM notification bridge; the handler only writes to eventfd.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

pub fn ignoreSigpipe() void {
    if (builtin.target.os.tag != .linux) return;
    const action = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(.PIPE, &action, null);
}

const invalid_shutdown_event_fd: posix.fd_t = -1;
var shutdown_event_fd = std.atomic.Value(posix.fd_t).init(invalid_shutdown_event_fd);

fn shutdownSignalMask() posix.sigset_t {
    var mask = posix.sigemptyset();
    posix.sigaddset(&mask, .INT);
    posix.sigaddset(&mask, .TERM);
    return mask;
}

fn shutdownSignalHandler(_: posix.SIG) callconv(.c) void {
    const fd = shutdown_event_fd.load(.acquire);
    if (fd == invalid_shutdown_event_fd) return;

    const increment: u64 = 1;
    _ = linux.write(fd, @ptrCast(&increment), @sizeOf(u64));
}

pub const ShutdownSignalBridge = struct {
    fd: posix.fd_t,
    old_int_action: posix.Sigaction,
    old_term_action: posix.Sigaction,
    previous_mask: posix.sigset_t,

    pub fn init() !ShutdownSignalBridge {
        if (builtin.target.os.tag != .linux) return error.UnsupportedOperatingSystem;

        const signal_mask = shutdownSignalMask();
        var previous_mask: posix.sigset_t = undefined;
        posix.sigprocmask(posix.SIG.BLOCK, &signal_mask, &previous_mask);
        errdefer posix.sigprocmask(posix.SIG.SETMASK, &previous_mask, null);

        const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        const fd: posix.fd_t = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        };
        errdefer _ = linux.close(fd);

        shutdown_event_fd.store(fd, .release);
        errdefer shutdown_event_fd.store(invalid_shutdown_event_fd, .release);

        const action = posix.Sigaction{
            .handler = .{ .handler = shutdownSignalHandler },
            .mask = signal_mask,
            .flags = 0,
        };
        var old_int_action: posix.Sigaction = undefined;
        var old_term_action: posix.Sigaction = undefined;
        posix.sigaction(.INT, &action, &old_int_action);
        posix.sigaction(.TERM, &action, &old_term_action);

        posix.sigprocmask(posix.SIG.UNBLOCK, &signal_mask, null);
        return .{
            .fd = fd,
            .old_int_action = old_int_action,
            .old_term_action = old_term_action,
            .previous_mask = previous_mask,
        };
    }

    pub fn deinit(self: *ShutdownSignalBridge) void {
        const signal_mask = shutdownSignalMask();
        posix.sigprocmask(posix.SIG.BLOCK, &signal_mask, null);

        posix.sigaction(.INT, &self.old_int_action, null);
        posix.sigaction(.TERM, &self.old_term_action, null);
        shutdown_event_fd.store(invalid_shutdown_event_fd, .release);
        _ = linux.close(self.fd);

        posix.sigprocmask(posix.SIG.SETMASK, &self.previous_mask, null);
        self.fd = invalid_shutdown_event_fd;
    }
};

test "shutdown signal mask covers SIGINT and SIGTERM" {
    const mask = shutdownSignalMask();
    try std.testing.expect(posix.sigismember(&mask, .INT));
    try std.testing.expect(posix.sigismember(&mask, .TERM));
}
