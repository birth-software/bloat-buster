const builtin = @import("builtin");
extern "c" fn IsDebuggerPresent() bool;
extern "c" fn __errno_location() *c_int;

pub const KB = 1024;
pub const MB = 1024 * 1024;
pub const GB = 1024 * 1024 * 1024;

pub fn assert(ok: bool) void {
    if (!ok) {
        @branchHint(.unlikely);
        unreachable;
    }
}

fn errno() Error {
    return @enumFromInt(__errno_location().*);
}

fn align_forward(T: type, value: T, alignment: T) T {
    assert(alignment != 0);
    const mask = alignment - 1;
    const result = (value + mask) & ~mask;
    return result;
}

pub fn align_forward_u64(value: u64, alignment: u64) u64 {
    return align_forward(u64, value, alignment);
}

pub fn align_forward_u32(value: u32, alignment: u32) u32 {
    return align_forward(u32, value, alignment);
}

const ValueFromFlag = enum {
    sub,
    cmov,
};
const value_from_flag_kind = ValueFromFlag.sub;

pub fn value_from_flag(value: anytype, flag: anytype) @TypeOf(value) {
    const flag_int: @TypeOf(value) = switch (@TypeOf(flag)) {
        comptime_int => b: {
            assert(flag == 1 or flag == 0);
            break :b flag;
        },
        bool => @intFromBool(flag),
        u1 => flag,
        else => @compileError("Unhandled type: " ++ @typeName(@TypeOf(flag))),
    };

    const result = switch (value_from_flag_kind) {
        .cmov => {
            @compileError("TODO");
        },
        .sub => value & (@as(@TypeOf(value), 0) -% flag_int),
    };
    return result;
}

test "value_from_flag" {
    const std = @import("std");
    const expect = std.testing.expect;

    try expect(value_from_flag(1, 1) == 1);
    try expect(value_from_flag(2, true) == 2);
    try expect(value_from_flag(3, false) == 0);
    try expect(value_from_flag(3, true) == 3);
    try expect(value_from_flag(3, 1) == 3);

    try expect(value_from_flag(0xffff, 1) == 0xffff);
    try expect(value_from_flag(0xffff, 0) == 0);
    try expect(value_from_flag(0xffff, true) == 0xffff);
    try expect(value_from_flag(0xffff, false) == 0);

    try expect(value_from_flag(0xffffffff, 1) == 0xffffffff);
    try expect(value_from_flag(0xffffffff, 0) == 0);
    try expect(value_from_flag(0xffffffff, true) == 0xffffffff);
    try expect(value_from_flag(0xffffffff, false) == 0);

    try expect(value_from_flag(0xffffffffffffffff, 1) == 0xffffffffffffffff);
    try expect(value_from_flag(0xffffffffffffffff, 0) == 0);
    try expect(value_from_flag(0xffffffffffffffff, true) == 0xffffffffffffffff);
    try expect(value_from_flag(0xffffffffffffffff, false) == 0);

    const a: u32 = 1235;
    const b_true: bool = true;
    const b_false: bool = false;
    const u_true: u1 = 1;
    const u_false: u1 = 0;
    try expect(value_from_flag(a, b_true) == a);
    try expect(value_from_flag(a, b_false) == 0);
    try expect(value_from_flag(a, u_true) == a);
    try expect(value_from_flag(a, u_false) == 0);

    const b: u64 = 0xffffffffffffffff;
    try expect(value_from_flag(b, b_true) == b);
    try expect(value_from_flag(b, b_false) == 0);
    try expect(value_from_flag(b, u_true) == b);
    try expect(value_from_flag(b, u_false) == 0);
}

pub const Error = enum(c_int) {
    SUCCESS = 0,
    PERM = 1,
};

pub const u64_max = ~@as(u64, 0);

pub const os = struct {
    pub extern "c" fn exit(c_int) noreturn;
    pub fn is_being_debugged() bool {
        var result = false;
        switch (builtin.os.tag) {
            .linux => {
                if (linux.ptrace(0, 0, 0, 0) == -1) {
                    result = errno() == Error.PERM;
                }
            },
            .windows => IsDebuggerPresent(),
            else => {},
        }

        return result;
    }

    const linux = struct {
        const PROT = packed struct(u32) {
            read: u1,
            write: u1,
            exec: u1,
            sem: u1 = 0,
            _: u28 = 0,
        };
        const MAP = packed struct(u32) {
            const Type = enum(u4) {
                shared = 0x1,
                private = 0x2,
                shared_validate = 0x3,
            };

            type: Type = .private,
            FIXED: u1 = 0,
            ANONYMOUS: u1 = 0,
            @"32BIT": u1 = 0,
            _7: u1 = 0,
            GROWSDOWN: u1 = 0,
            _9: u2 = 0,
            DENYWRITE: u1 = 0,
            EXECUTABLE: u1 = 0,
            LOCKED: u1 = 0,
            NORESERVE: u1 = 0,
            POPULATE: u1 = 0,
            NONBLOCK: u1 = 0,
            STACK: u1 = 0,
            HUGETLB: u1 = 0,
            SYNC: u1 = 0,
            FIXED_NOREPLACE: u1 = 0,
            _21: u5 = 0,
            UNINITIALIZED: u1 = 0,
            _: u5 = 0,
        };

        extern "c" fn ptrace(c_int, c_int, usize, usize) c_long;
        extern "c" fn mmap(usize, usize, PROT, MAP, c_int, isize) *align(4096) anyopaque;
        extern "c" fn mprotect(*anyopaque, usize, PROT) c_int;

        fn protection_flags(protection: ProtectionFlags) PROT {
            const result = PROT{
                .read = protection.read,
                .write = protection.write,
                .exec = protection.execute,
            };
            return result;
        }

        fn map_flags(map: MapFlags) MAP {
            const result = MAP{
                .type = if (map.private != 0) .private else .shared,
                .ANONYMOUS = map.anonymous,
                .NORESERVE = map.no_reserve,
                .POPULATE = map.populate,
            };

            return result;
        }
    };

    const ProtectionFlags = packed struct {
        read: u1,
        write: u1,
        execute: u1,
    };
    const MapFlags = packed struct {
        private: u1,
        anonymous: u1,
        no_reserve: u1,
        populate: u1,
    };

    pub fn reserve(base: u64, size: u64, protection: ProtectionFlags, map: MapFlags) *align(4096) anyopaque {
        switch (builtin.os.tag) {
            .windows => @compileError("TODO"),
            else => {
                const protection_flags = linux.protection_flags(protection);
                const map_flags = linux.map_flags(map);
                const address = linux.mmap(base, size, protection_flags, map_flags, -1, 0);
                if (@intFromPtr(address) == u64_max) {
                    @branchHint(.unlikely);
                    unreachable;
                }
                return address;
            },
        }
    }

    pub fn commit(address: *anyopaque, size: u64, protection: ProtectionFlags) void {
        switch (builtin.os.tag) {
            .windows => @compileError("TODO"),
            else => {
                const protection_flags = linux.protection_flags(protection);
                const result = linux.mprotect(address, size, protection_flags);
                if (result != 0) {
                    unreachable;
                }
            },
        }
    }

    pub fn abort() noreturn {
        if (os.is_being_debugged()) {
            @trap();
        } else {
            os.exit(1);
        }
    }
};

pub const Arena = struct {
    reserved_size: u64,
    position: u64,
    os_position: u64,
    granularity: u64,
    reserved: [32]u8 = [1]u8{0} ** 32,

    const minimum_position = @sizeOf(Arena);

    const Initialization = struct {
        reserved_size: u64,
        granularity: u64,
        initial_size: u64,
    };

    pub fn initialize(initialization: Initialization) *Arena {
        const protection_flags = os.ProtectionFlags{
            .read = 1,
            .write = 1,
            .execute = 0,
        };
        const map_flags = os.MapFlags{
            .private = 1,
            .anonymous = 1,
            .no_reserve = 1,
            .populate = 0,
        };
        const arena: *Arena = @ptrCast(os.reserve(0, initialization.reserved_size, protection_flags, map_flags));
        os.commit(arena, initialization.initial_size, .{
            .read = 1,
            .write = 1,
            .execute = 0,
        });

        arena.* = .{
            .reserved_size = initialization.reserved_size,
            .os_position = initialization.initial_size,
            .position = minimum_position,
            .granularity = initialization.granularity,
        };

        return arena;
    }

    const default_size = 4 * GB;
    const minimum_granularity = 4 * KB;

    pub fn initialize_default(initial_size: u64) *Arena {
        const arena = initialize(.{
            .reserved_size = default_size,
            .granularity = minimum_granularity,
            .initial_size = initial_size,
        });
        return arena;
    }

    pub fn allocate_bytes(arena: *Arena, size: u64, alignment: u64) [*]u8 {
        const aligned_offset = align_forward_u64(arena.position, alignment);
        const aligned_size_after = aligned_offset + size;

        if (aligned_size_after > arena.os_position) {
            const target_committed_size = align_forward_u64(aligned_size_after, arena.granularity);
            const size_to_commit = target_committed_size - arena.os_position;
            const commit_pointer = @as(*anyopaque, @ptrFromInt(@intFromPtr(arena) + arena.os_position));
            os.commit(commit_pointer, size_to_commit, .{
                .read = 1,
                .write = 1,
                .execute = 0,
            });
            arena.os_position = target_committed_size;
        }

        const result = @as([*]u8, @ptrFromInt(@intFromPtr(arena) + aligned_offset));
        arena.position = aligned_size_after;
        assert(arena.position <= arena.os_position);

        return result;
    }

    pub fn join_string(arena: *Arena, pieces: []const []const u8) [:0]u8 {
        var size: u64 = 0;
        for (pieces) |piece| {
            size += piece.len;
        }

        const pointer = arena.allocate_bytes(size + 1, 1);
        var i: u64 = 0;
        for (pieces) |piece| {
            @memcpy(pointer + i, piece);
            i += piece.len;
        }

        assert(i == size);
        pointer[i] = 0;

        return pointer[0..size :0];
    }

    pub fn duplicate_string(arena: *Arena, string: []const u8) [:0]u8 {
        const memory = arena.allocate_bytes(string.len + 1, 1);
        @memcpy(memory, string);
        memory[string.len] = 0;
        return memory[0..string.len :0];
    }

    pub fn restore(arena: *Arena, position: u64) void {
        assert(position <= arena.position);
        @memset(@as([*]u8, @ptrCast(arena))[position..][0 .. arena.position - position], 0);
        arena.position = position;
    }

    pub fn reset(arena: *Arena) void {
        arena.restore(minimum_position);
    }
};
