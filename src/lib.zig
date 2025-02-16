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

pub const file = struct {
    pub const WriteOptions = packed struct {
        executable: u1 = 0,
    };
    pub fn write(path: [:0]const u8, content: []const u8, options: WriteOptions) void {
        const fd = os.File.open(path, .{
            .write = 1,
            .truncate = 1,
            .create = 1,
            .execute = options.executable,
        }, .{
            .read = 1,
            .write = 1,
            .execute = options.executable,
        });
        defer fd.close();

        if (fd.is_valid()) {
            fd.write(content);
        }
    }

    pub fn read(arena: *Arena, path: [:0]const u8) []u8 {
        const fd = os.File.open(path, .{
            .read = 1,
        }, .{
            .read = 1,
        });
        defer fd.close();
        var result: []u8 = undefined;
        const ptr = @as(*[2]u64, @ptrCast(&result));
        ptr[0] = 0;
        ptr[1] = 0;

        if (fd.is_valid()) {
            const file_size = fd.get_size();
            const file_buffer = arena.allocate_bytes(file_size, 1);
            result = file_buffer[0..file_size];
            fd.read(result, file_size);
        }

        return result;
    }
};

pub const os = struct {
    const system = switch (builtin.os.tag) {
        .windows => windows,
        .linux => linux,
        else => @compileError("TODO"),
    };
    pub const posix = switch (builtin.os.tag) {
        .windows => @compileError("TODO"),
        .linux => linux,
        else => @compileError("TODO"),
    };

    pub const File = struct {
        fd: Descriptor,

        const Descriptor = system.FileDescriptor;

        pub fn is_valid(fd: File) bool {
            return system.fd_is_valid(fd.fd);
        }

        pub const OpenFlags = packed struct {
            truncate: u1 = 0,
            execute: u1 = 0,
            write: u1 = 0,
            read: u1 = 0,
            create: u1 = 0,
            directory: u1 = 0,
        };

        pub const Permissions = packed struct {
            read: u1 = 1,
            write: u1 = 1,
            execute: u1 = 0,
        };

        pub fn open(path: [*:0]const u8, flags: OpenFlags, permissions: Permissions) File {
            switch (builtin.os.tag) {
                .windows => @compileError("TODO"),
                else => {
                    const o = posix.O{
                        .ACCMODE = if (flags.read | flags.write != 0) .RDWR else if (flags.read != 0) .RDONLY else if (flags.write != 0) .WRONLY else unreachable,
                        .TRUNC = flags.truncate,
                        .CREAT = flags.create,
                        .DIRECTORY = flags.directory,
                    };
                    const mode: posix.mode_t = if (permissions.execute != 0) 0o755 else 0o644;

                    const fd = posix.open(path, o, mode);
                    return File{
                        .fd = fd,
                    };
                },
            }
        }

        pub fn close(fd: File) void {
            switch (builtin.os.tag) {
                .windows => {
                    @compileError("TODO");
                },
                else => {
                    const result = posix.close(fd.fd);
                    assert(result == 0);
                },
            }
        }

        pub fn get_size(fd: File) u64 {
            switch (builtin.os.tag) {
                .windows => {
                    @compileError("TODO");
                },
                else => {
                    var stat: posix.Stat = undefined;
                    const result = posix.fstat(fd.fd, &stat);
                    assert(result == 0);
                    return @intCast(stat.size);
                },
            }
        }

        pub fn write_partially(fd: File, content: []const u8) usize {
            switch (builtin.os.tag) {
                .windows => {
                    @compileError("TODO");
                },
                else => {
                    const syscall_result = posix.write(fd.fd, content.ptr, content.len);
                    if (syscall_result <= 0) {
                        abort();
                    } else {
                        return @intCast(syscall_result);
                    }
                },
            }
        }

        pub fn write(fd: File, content: []const u8) void {
            var it = content;
            while (it.len != 0) {
                const written_bytes = fd.write_partially(it);
                it.ptr += written_bytes;
                it.len -= written_bytes;
            }
        }

        pub fn read_partially(fd: File, buffer: [*]u8, byte_count: usize) usize {
            switch (builtin.os.tag) {
                .windows => {
                    @compileError("TODO");
                },
                else => {
                    const syscall_result = posix.read(fd.fd, buffer, byte_count);
                    if (syscall_result <= 0) {
                        abort();
                    } else {
                        return @intCast(syscall_result);
                    }
                },
            }
        }

        pub fn read(fd: File, buffer: []u8, byte_count: usize) void {
            assert(byte_count <= buffer.len);
            var it_byte_count: usize = 0;
            while (it_byte_count < byte_count) {
                const read_bytes = fd.read_partially(buffer.ptr + it_byte_count, byte_count - it_byte_count);
                it_byte_count += read_bytes;
            }
        }
    };

    pub fn is_being_debugged() bool {
        var result = false;
        switch (builtin.os.tag) {
            .linux => {
                if (linux.ptrace(0, 0, 0, 0) == -1) {
                    result = errno() == Error.PERM;
                }
            },
            .windows => IsDebuggerPresent(),
            .macos => {},
            else => @compileError("TODO"),
        }

        return result;
    }

    const linux = struct {
        const FileDescriptor = c_int;

        fn fd_is_valid(fd: FileDescriptor) bool {
            return fd >= 0;
        }

        pub const uid_t = u32;
        pub const gid_t = u32;
        pub const off_t = i64;
        pub const ino_t = u64;
        pub const dev_t = u64;

        pub const timespec = extern struct {
            seconds: isize,
            nanoseconds: isize,
        };

        // The `stat` definition used by the Linux kernel.
        pub const Stat = extern struct {
            dev: dev_t,
            ino: ino_t,
            nlink: usize,

            mode: u32,
            uid: uid_t,
            gid: gid_t,
            __pad0: u32,
            rdev: dev_t,
            size: off_t,
            blksize: isize,
            blocks: i64,

            atim: timespec,
            mtim: timespec,
            ctim: timespec,
            __unused: [3]isize,
        };

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

        pub const ACCMODE = enum(u2) {
            RDONLY = 0,
            WRONLY = 1,
            RDWR = 2,
        };

        const O = packed struct(u32) {
            ACCMODE: ACCMODE,
            _2: u4 = 0,
            CREAT: u1 = 0,
            EXCL: u1 = 0,
            NOCTTY: u1 = 0,
            TRUNC: u1 = 0,
            APPEND: u1 = 0,
            NONBLOCK: u1 = 0,
            DSYNC: u1 = 0,
            ASYNC: u1 = 0,
            DIRECT: u1 = 0,
            _15: u1 = 0,
            DIRECTORY: u1 = 0,
            NOFOLLOW: u1 = 0,
            NOATIME: u1 = 0,
            CLOEXEC: u1 = 0,
            SYNC: u1 = 0,
            PATH: u1 = 0,
            TMPFILE: u1 = 0,
            _: u9 = 0,
        };

        extern "c" fn ptrace(c_int, c_int, usize, usize) c_long;
        extern "c" fn mmap(usize, usize, PROT, MAP, c_int, isize) *align(4096) anyopaque;
        extern "c" fn mprotect(*anyopaque, usize, PROT) c_int;
        extern "c" fn open(path: [*:0]const u8, oflag: O, ...) c_int;
        extern "c" fn close(fd: system.FileDescriptor) c_int;
        extern "c" fn fstat(fd: system.FileDescriptor, stat: *Stat) c_int;
        extern "c" fn read(fd: system.FileDescriptor, pointer: [*]u8, byte_count: usize) isize;
        extern "c" fn write(fd: system.FileDescriptor, pointer: [*]const u8, byte_count: usize) isize;

        const mode_t = usize;

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

    const windows = struct {
        const HANDLE = ?*anyopaque;
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
            libc.exit(1);
        }
    }
};

pub const libc = struct {
    pub extern "c" fn exit(c_int) noreturn;
    pub extern "c" fn memcmp(a: [*]const u8, b: [*]const u8, byte_count: usize) c_int;
};

pub const string = struct {
    pub fn equal(a: []const u8, b: []const u8) bool {
        var result = a.len == b.len;
        if (result) {
            result = libc.memcmp(a.ptr, b.ptr, a.len) == 0;
        }
        return result;
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

    pub fn duplicate_string(arena: *Arena, str: []const u8) [:0]u8 {
        const memory = arena.allocate_bytes(str.len + 1, 1);
        @memcpy(memory, str);
        memory[str.len] = 0;
        return memory[0..str.len :0];
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
