//! Direct daemon stdout/stderr writes. Each log record is preformatted into a
//! bounded stack buffer, usually allowing one Linux write without an Io context.

const std = @import("std");
const builtin = @import("builtin");

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
