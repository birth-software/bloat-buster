const lib = @import("lib.zig");
const os = lib.os;
const llvm = @import("LLVM.zig");
const converter = @import("converter.zig");
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

pub fn main(argc: c_int, argv: [*:null]const ?[*:0]const u8) callconv(.C) c_int {
    if (argc != 2) {
        lib.print_string("Failed to match argument count");
        return 1;
    }
    const file_path_pointer = argv[1] orelse return 1;
    const file_path = lib.cstring.to_slice(file_path_pointer);
    if (file_path.len < 5) {
        return 1;
    }

    const extension_start = lib.string.last_character(file_path, '.') orelse return 1;
    if (!lib.string.equal(file_path[extension_start..], ".bbb")) {
        return 1;
    }
    const separator_index = lib.string.last_character(file_path, '/') orelse 0;
    const base_start = separator_index + @intFromBool(separator_index != 0 or file_path[separator_index] == '/');
    const base_name = file_path[base_start..extension_start];

    lib.GlobalState.initialize();

    const arena = lib.global.arena;

    const build_dir = "bb-cache";
    os.make_directory(build_dir);
    const output_path_base = arena.join_string(&.{ build_dir, "/", base_name });
    const output_object_path = arena.join_string(&.{ output_path_base, ".o" });
    const output_executable_path = output_path_base;

    const file_content = lib.file.read(arena, file_path);
    converter.convert(.{
        .executable = output_executable_path,
        .object = output_object_path,
        .name = base_name,
        .build_mode = .debug_none,
        .content = file_content,
        .path = file_path,
        .has_debug_info = 1,
    });
    return 0;
}

comptime {
    if (!lib.is_test) {
        @export(&main, .{
            .name = "main",
        });
    }
}

test {
    _ = lib;
    _ = llvm;
    _ = converter;
}
