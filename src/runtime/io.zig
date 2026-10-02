//! Direct daemon stdout/stderr writes. Each log record is preformatted into a
//! bounded stack buffer, usually allowing one Linux write without an Io context.

const std = @import("std");
const builtin = @import("builtin");

// Set once during startup, before either relay starts its workers.
pub var log_level: std.log.Level = .info;

/// Share the logger's filter with call sites that prepare expensive arguments.
pub fn logEnabled(comptime level: std.log.Level, comptime scope: @EnumLiteral()) bool {
    return std.log.logEnabled(level, scope) and @intFromEnum(level) <= @intFromEnum(log_level);
}

pub fn writeStdout(bytes: []const u8) void {
    if (builtin.os.tag == .linux) {
        writeLinuxFd(std.os.linux.STDOUT_FILENO, bytes);
        return;
    }
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    std.Io.File.stdout().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

pub fn writeStderr(bytes: []const u8) void {
    if (builtin.os.tag == .linux) {
        writeLinuxFd(std.os.linux.STDERR_FILENO, bytes);
        return;
    }
    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded_io.deinit();
    std.Io.File.stderr().writeStreamingAll(threaded_io.io(), bytes) catch {};
}

fn writeLinuxFd(fd: i32, bytes: []const u8) void {
    const linux = std.os.linux;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = linux.write(fd, bytes[offset..].ptr, bytes.len - offset);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return;
                offset += rc;
            },
            .INTR => continue,
            else => return,
        }
    }
}
