const builtin = @import("builtin");
extern "c" fn _errno() *c_int;
extern "c" fn ptrace(c_int, c_int, usize, usize) c_long;
extern "c" fn IsDebuggerPresent() bool;
fn errno() Error {
    return @enumFromInt(_errno().*);
}

pub const Error = enum(c_int) {
    SUCCESS = 0,
    PERM = 1,
};

pub const os = struct {
    pub extern "c" fn exit(c_int) noreturn;
    pub fn is_being_debugged() bool {
        var result = false;
        switch (builtin.os) {
            .linux => {
                if (ptrace(0, 0, 0, 0) == -1) {
                    result = errno() == Error.PERM;
                }
            },
            .windows => IsDebuggerPresent(),
            else => {},
        }

        return result;
    }
};
