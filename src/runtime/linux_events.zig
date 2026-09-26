const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;

pub fn createTimerFd() !posix.fd_t {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
    const rc = linux.timerfd_create(.MONOTONIC, .{ .NONBLOCK = true, .CLOEXEC = true });
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn armTimerFd(fd: posix.fd_t, deadline_ns: ?i128) !void {
    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    const value = deadline_ns orelse 0;
    const spec = linux.itimerspec{
        .it_interval = .{ .sec = 0, .nsec = 0 },
        .it_value = if (value <= 0)
            .{ .sec = 0, .nsec = 0 }
        else
            .{
                .sec = @intCast(@divTrunc(value, std.time.ns_per_s)),
                .nsec = @intCast(@mod(value, std.time.ns_per_s)),
            },
    };
    const rc = linux.timerfd_settime(fd, .{ .ABSTIME = true }, &spec, null);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn drainTimerFd(fd: posix.fd_t) void {
    var expirations: u64 = 0;
    while (true) {
        const bytes = std.mem.asBytes(&expirations);
        const rc = linux.read(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return,
            else => return,
        }
    }
}

pub fn epollCreate() !posix.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn createWorkerEventFd() !posix.fd_t {
    const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn writeWorkerEventFd(fd: posix.fd_t, count: u64) !void {
    var value = count;
    const bytes = std.mem.asBytes(&value);
    while (true) {
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc != bytes.len) return error.ShortWorkerEventWrite;
                return;
            },
            .INTR => continue,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

pub fn readWorkerEventFd(fd: posix.fd_t) !u64 {
    var value: u64 = 0;
    const bytes = std.mem.asBytes(&value);
    while (true) {
        const rc = linux.read(fd, bytes.ptr, bytes.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.WorkerEventFdClosed;
                if (rc != bytes.len) return error.ShortWorkerEventRead;
                return value;
            },
            .INTR => continue,
            .AGAIN => return 0,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}
