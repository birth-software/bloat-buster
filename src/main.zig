const lib = @import("lib.zig");
const configuration = @import("configuration");
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

    pub fn sliceCastLenRemainder(_: usize) noreturn {
        @branchHint(.cold);
        abort();
    }
};

pub fn main(argc: c_int, argv: [*:null]const ?[*:0]const u8) callconv(.C) c_int {
    if (argc != 2) {
        lib.print_string("Failed to match argument count");
        return 1;
    }
    const relative_file_path_pointer = argv[1] orelse return 1;
    const relative_file_path = lib.cstring.to_slice(relative_file_path_pointer);
    if (relative_file_path.len < 5) {
        return 1;
    }

    const extension_start = lib.string.last_character(relative_file_path, '.') orelse return 1;
    if (!lib.string.equal(relative_file_path[extension_start..], ".bbb")) {
        return 1;
    }
    const separator_index = lib.string.last_character(relative_file_path, '/') orelse 0;
    const base_start = separator_index + @intFromBool(separator_index != 0 or relative_file_path[separator_index] == '/');
    const base_name = relative_file_path[base_start..extension_start];

    lib.GlobalState.initialize();

    const arena = lib.global.arena;

    const build_dir = "bb-cache";
    os.make_directory(build_dir);
    const output_path_base = arena.join_string(&.{ build_dir, "/", base_name, "_", @tagName(lib.optimization_mode) });
    const output_object_path = arena.join_string(&.{ output_path_base, ".o" });
    const output_executable_path = output_path_base;

    const c_abi_object_path = arena.duplicate_string(configuration.c_abi_object_path);
    const file_content = lib.file.read(arena, relative_file_path);
    const file_path = os.absolute_path(arena, relative_file_path);
    converter.convert(arena, .{
        .executable = output_executable_path,
        .objects = if (lib.string.equal(base_name, "c_abi")) &.{ output_object_path, c_abi_object_path } else &.{output_object_path},
        .name = base_name,
        .build_mode = .soft_optimize,
        .content = file_content,
        .path = file_path,
        .has_debug_info = true,
        .target = converter.Target.get_native(),
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
