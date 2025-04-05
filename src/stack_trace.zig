const std = @import("std");
export fn enable_signal_handlers() void {
    std.debug.attachSegfaultHandler();
}

export fn dump_stack_trace(return_address: usize) void {
    const stderr = std.io.getStdErr().writer();
    if (@import("builtin").strip_debug_info) {
        stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
        return;
    }
    const debug_info = std.debug.getSelfDebugInfo() catch |err| {
        stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
        return;
    };
    std.debug.writeCurrentStackTrace(stderr, debug_info, std.io.tty.detectConfig(std.io.getStdErr()), return_address) catch |err| {
        stderr.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch return;
        return;
    };
}
