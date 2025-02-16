const lib = @import("lib.zig");
pub fn panic(message: []const u8, stack_trace: ?*anyopaque, return_address: ?usize) noreturn {
    _ = return_address;
    _ = message;
    _ = stack_trace;
    if (lib.os.is_being_debugged()) {
        @trap();
    } else {
        lib.os.exit(1);
    }
}

pub fn main() callconv(.C) c_int {
    const arena = lib.Arena.initialize_default(2 * lib.MB);
    _ = arena.allocate_bytes(1024, 1);
    return 0;
}

comptime {
    if (!@import("builtin").is_test) {
        @export(&main, @import("std").builtin.ExportOptions{
            .name = "main",
        });
    }
}

test {
    _ = lib;
}
