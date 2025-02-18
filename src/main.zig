const lib = @import("lib.zig");
const llvm = @import("LLVM.zig");
const Arena = lib.Arena;

pub const panic = struct {
    const abort = lib.os.abort;
    pub fn call(_: []const u8, _: ?usize) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn sentinelMismatch(_: anytype, _: anytype) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn unwrapError(_: anyerror) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn outOfBounds(_: usize, _: usize) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn startGreaterThanEnd(_: usize, _: usize) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn inactiveUnionField(_: anytype, _: anytype) noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn reachedUnreachable() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn unwrapNull() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn castToNull() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn incorrectAlignment() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn invalidErrorCode() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn castTruncatedData() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn negativeToUnsigned() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn integerOverflow() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn shlOverflow() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn shrOverflow() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn divideByZero() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn exactDivisionRemainder() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn integerPartOutOfBounds() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn corruptSwitch() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn shiftRhsTooBig() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn invalidEnumValue() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn forLenMismatch() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn memcpyLenMismatch() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn memcpyAlias() noreturn {
        @branchHint(.cold);
        abort();
    }

    pub fn noreturnReturned() noreturn {
        @branchHint(.cold);
        abort();
    }
};

var global_persistent_arena: *Arena = undefined;

pub fn main() callconv(.C) c_int {
    lib.GlobalState.initialize();

    llvm.initialize_all();
    llvm.experiment();
    return 0;
}

comptime {
    if (!@import("builtin").is_test) {
        @export(&main, .{
            .name = "main",
        });
    }
}

test {
    _ = lib;
    _ = llvm;
}
