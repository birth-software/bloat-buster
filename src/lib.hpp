#pragma once

#define global_variable static

#define EXPORT extern "C"
#define fn static
#define unused(x) (void)(x)
#define breakpoint() __builtin_debugtrap()
#define string_literal_length(s) (sizeof(s) - 1)
#define string_literal(s) ((String){ .pointer = (u8*)(s), .length = string_literal_length(s), })
#define split_string_literal(s) (char*)(s), string_literal_length(s)
#define offsetof(S, f) __builtin_offsetof(S, f)

#define array_length(arr) sizeof(arr) / sizeof((arr)[0])
#define array_to_slice(arr) { .pointer = (arr), .length = array_length(arr) }
#define array_to_bytes(arr) { .pointer = (u8*)(arr), .length = sizeof(arr) }
#define backing_type(E) __underlying_type(E)

#define unreachable_raw() __builtin_unreachable()
#define trap() __builtin_trap()
#if BB_DEBUG
#define unreachable() trap()
#else
#define unreachable() unreachable_raw()
#endif
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define expect(x, b) __builtin_expect(!!(x), b)
#define likely(x) expect(x, 1)
#define unlikely(x) expect(x, 0)

#define assert(x) (unlikely(!(x)) ? unreachable() : unused(0))

#define clz(x) __builtin_clzg(x)
#define ctz(x) __builtin_ctzg(x)

#define case_to_name(E,n) case E::n: return string_literal(#n)

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef float f32;
typedef double f64;

fn u64 align_forward(u64 value, u64 alignment)
{
    assert(alignment != 0);
    auto mask = alignment - 1;
    auto result = (value + mask) & ~mask;
    return result;
}

constexpr u64 kb = 1024;
constexpr u64 mb = 1024 * 1024;
constexpr u64 gb = 1024 * 1024 * 1024;

extern "C" [[noreturn]] void exit(s32 status) noexcept(true);
extern "C" void *memcpy (void* __restrict destination, const void *__restrict source, u64 byte_count) noexcept(true);
extern "C" s32 memcmp (const void* a, const void *b, u64 __n) noexcept(true);
extern "C" char* realpath(const char* __restrict path, char* resolved_path) noexcept(true);

struct RawSlice
{
    void* pointer;
    u64 length;
};

fn bool raw_slice_equal(RawSlice a, RawSlice b, u64 size_of_T)
{
    bool result = a.length == b.length;
    if (result)
    {
        if (a.pointer != b.pointer)
        {
            result = memcmp(a.pointer, b.pointer, a.length * size_of_T) == 0;
        }
    }

    return result;
}

fn RawSlice raw_slice_slice(RawSlice s, u64 start, u64 end, u64 size_of_T)
{
    return {(u8*)s.pointer + (size_of_T * start), end - start};
}

template <typename T>
struct Slice
{
    T* pointer;
    u64 length;

    T* begin()
    {
        return pointer;
    }

    T* end() {
        return pointer + length;
    }

    T& operator[](u64 index)
    {
        assert(index < length);
        return pointer[index];
    }

    bool equal(Slice<T> other)
    {
        return raw_slice_equal(*(RawSlice*)this, *(RawSlice*)&other, sizeof(T));
    }

    Slice<T> operator()(u64 start, u64 end)
    {
        return {pointer + start, end - start};
    }

    Slice<T> operator()(u64 start)
    {
        return {pointer + start, length - start};
    }
};

using String = Slice<u8>;
fn const char* cstr(String string)
{
    assert(string.pointer[string.length] == 0);
    return (const char*) string.pointer;
}

fn String c_string_to_slice(const char* cstr)
{
    const auto* end = cstr;
    while (*end)
    {
        end += 1;
    }

    return { (u8*)cstr, u64(end - cstr) };
}

constexpr auto string_no_match = ~(u64)0;

fn u64 string_first_character(String string, u8 ch)
{
    u64 result = string_no_match;

    for (u64 i = 0; i < string.length; i += 1)
    {
        if (string[i] == ch)
        {
            result = i;
            break;
        }
    }

    return result;
}

fn u64 string_last_character(String string, u8 ch)
{
    u64 result = string_no_match;
    u64 i = string.length;

    while (i > 0)
    {
        i -= 1;

        if (string[i] == ch)
        {
            result = i;
            break;
        }
    }

    return result;
}

struct ProtectionFlags
{
    u8 read:1;
    u8 write:1;
    u8 execute:1;
};

struct MapFlags
{
    u8 priv:1;
    u8 anonymous:1;
    u8 no_reserve:1;
    u8 populate:1;
};

struct PROT
{
    u32 read:1;
    u32 write:1;
    u32 execute:1;
    u32 sem:1;
    u32 _:28;
};
static_assert(sizeof(PROT) == sizeof(u32));

struct MAP
{
    enum class Type : u32
    {
        shared = 0,
        priv = 1,
        shared_validate = 2,
    };

    Type type:4;
    u32 fixed:1;
    u32 anonymous:1;
    u32 bit32:1;
    u32 _0: 1;
    u32 grows_down:1;
    u32 _1: 2;
    u32 deny_write:1;
    u32 executable:1;
    u32 locked:1;
    u32 no_reserve:1;
    u32 populate:1;
    u32 non_block:1;
    u32 stack:1;
    u32 huge_tlb:1;
    u32 sync:1;
    u32 fixed_no_replace:1;
    u32 _2:5;
    u32 uninitialized:1;
    u32 _3:5;
};
static_assert(sizeof(MAP) == sizeof(u32));

struct OPEN
{
    enum class AccessMode : u32
    {
        read_only = 0,
        write_only = 1,
        read_write = 2,
    };

    AccessMode access_mode:2;
    u32 _0:4;
    u32 creat:1;
    u32 excl:1;
    u32 no_ctty:1;
    u32 trunc:1;
    u32 append:1;
    u32 non_block:1;
    u32 d_sync:1;
    u32 a_sync:1;
    u32 direct:1;
    u32 _1:1;
    u32 directory:1;
    u32 no_follow:1;
    u32 no_a_time:1;
    u32 cloexec:1;
    u32 sync:1;
    u32 path:1;
    u32 tmp_file:1;
    u32 _2:9;
};
static_assert(sizeof(OPEN) == sizeof(u32));

extern "C" s32* __errno_location() noexcept(true);
extern "C" void* mmap(void*, u64, PROT, MAP, s32, s64);
extern "C" s32 mprotect(void*, u64, PROT);
extern "C" s64 ptrace(s32, s32, u64, u64);
extern "C" s32 open(const char*, OPEN, ...);
extern "C" s32 close(s32);
extern "C" s64 write(s32, const void*, u64);
extern "C" s64 read(s32, void*, u64);
extern "C" s32 mkdir(const char*, u64);

enum class Error : u32
{
    success = 0,
    perm = 1,
};

fn Error errno()
{
    return (Error)*__errno_location();
}

fn void* os_reserve(void* base, u64 size, ProtectionFlags protection, MapFlags map)
{
    auto protection_flags = PROT
    {
        .read = protection.read,
        .write = protection.write,
        .execute = protection.execute,
        .sem = 0,
        ._ = 0,
    };

    auto map_flags = MAP
    {
        .type = map.priv ? MAP::Type::priv : MAP::Type::shared,
        .fixed = 0,
        .anonymous = map.anonymous,
        .bit32 = 0,
        ._0 = 0,
        .grows_down = 0,
        ._1 = 0,
        .deny_write = 0,
        .executable = 0,
        .locked = 0,
        .no_reserve = map.no_reserve,
        .populate = map.populate,
        .non_block = 0,
        .stack = 0,
        .huge_tlb = 0,
        .sync = 0,
        .fixed_no_replace = 0,
        ._2 = 0,
        .uninitialized = 0,
        ._3 = 0,
    };

    auto* address = mmap(base, size, protection_flags, map_flags, -1, 0);
    assert((u64)address != ~(u64)0);

    return address;
}

fn void os_commit(void* address, u64 size, ProtectionFlags protection)
{
    auto protection_flags = PROT
    {
        .read = protection.read,
        .write = protection.write,
        .execute = protection.execute,
        .sem = 0,
        ._ = 0,
    };
    auto result = mprotect(address, size, protection_flags);
    assert(!result);
}

struct OpenFlags
{
    u32 truncate:1;
    u32 execute:1;
    u32 write:1;
    u32 read:1;
    u32 create:1;
    u32 directory:1;
};

struct Permissions
{
    u32 read:1;
    u32 write:1;
    u32 execute:1;
};

fn s32 os_open(String path, OpenFlags flags, Permissions permissions)
{
    OPEN::AccessMode access_mode;
    if (flags.read && flags.write)
    {
        access_mode = OPEN::AccessMode::read_write;
    }
    else if (flags.read)
    {
        access_mode = OPEN::AccessMode::read_only;
    }
    else if (flags.write)
    {
        access_mode = OPEN::AccessMode::read_only;
    }
    else
    {
        unreachable();
    }

    auto o = OPEN {
        .access_mode = access_mode,
        .creat = flags.create,
        .trunc = flags.truncate,
        .directory = flags.directory,
    };

    // TODO:
    auto mode = permissions.execute ? 0755 : 0644;

    auto fd = open(cstr(path), o, mode);
    return fd;
}

fn bool is_file_valid(s32 fd)
{
    return fd >= 0;
}

fn void os_close(s32 fd)
{
    assert(is_file_valid(fd));

    auto result = close(fd);
    assert(result == 0);
}

u64 os_file_size(s32 fd);

fn u64 os_read_partially(s32 fd, u8* buffer, u64 byte_count)
{
    auto result = read(fd, buffer, byte_count);
    assert(result > 0);
    return (u64)result;
}

fn void os_read(s32 fd, String buffer, u64 byte_count)
{
    assert(byte_count <= buffer.length);
    u64 it_byte_count = 0;
    while (it_byte_count < byte_count)
    {
        auto read_byte_count = os_read_partially(fd, buffer.pointer + it_byte_count, byte_count - it_byte_count);
        it_byte_count += read_byte_count;
    }
    assert(it_byte_count == byte_count);
}

fn u64 os_write_partially(s32 fd, u8* buffer, u64 byte_count)
{
    auto result = write(fd, buffer, byte_count);
    assert(result > 0);
    return (u64)result;
}

fn void os_write(s32 fd, String content)
{
    u64 it_byte_count = 0;
    while (it_byte_count < content.length)
    {
        auto written_byte_count = os_write_partially(fd, content.pointer + it_byte_count, content.length - it_byte_count);
        it_byte_count += written_byte_count;
    }
    assert(it_byte_count == content.length);
}

fn String path_absolute_stack(String buffer, String relative_path)
{
    const char* absolute_path = realpath(cstr(relative_path), (char*)buffer.pointer);
    if (absolute_path)
    {
        auto slice = c_string_to_slice(absolute_path);
        assert(slice.length < buffer.length);
        return slice;
    }
    return {};
}

fn bool os_is_debugger_present()
{
    bool result = false;
    if (ptrace(0, 0, 0, 0) == -1)
    {
        auto errno_error = errno();
        result = errno_error == Error::perm;
    }

    return result;
}

fn void make_directory(const char* path)
{
    auto result = mkdir(path, 0755);
    unused(result);
}

fn void print(String string)
{
    os_write(1, string);
}

struct ArenaInitialization
{
    u64 reserved_size;
    u64 granularity;
    u64 initial_size;
};

struct Arena
{
    u64 reserved_size;
    u64 position;
    u64 os_position;
    u64 granularity;
    u8 reserved[32];
};

constexpr u64 arena_minimum_position = sizeof(Arena);

fn Arena* arena_initialize(ArenaInitialization i)
{
    ProtectionFlags protection_flags = {
        .read = 1,
        .write = 1,
    };
    MapFlags map_flags = {
        .priv = 1,
        .anonymous = 1,
        .no_reserve = 1,
    };

    auto* arena = (Arena*)os_reserve(0, i.reserved_size, protection_flags, map_flags);
    os_commit(arena, i.initial_size, { .read = 1, .write = 1 });

    *arena = {
        .reserved_size = i.reserved_size,
        .position = arena_minimum_position,
        .os_position = i.initial_size,
        .granularity = i.granularity,
    };

    return arena;
}

fn inline Arena* arena_initialize_default(u64 initial_size)
{
    ArenaInitialization i = {
        .reserved_size = 4 * gb,
        .granularity = 4 * kb,
        .initial_size = initial_size,
    };
    return arena_initialize(i);
}

fn void* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment)
{
    void* result = 0;

    if (size)
    {
        auto aligned_offset = align_forward(arena->position, alignment);
        auto aligned_size_after = aligned_offset + size;

        if (aligned_size_after > arena->os_position)
        {
            unreachable();
        }

        result = (u8*)arena + aligned_offset;
        arena->position = aligned_size_after;
        assert(arena->position <= arena->os_position);
    }

    return result;
}

template <typename T>
fn Slice<T> arena_allocate(Arena* arena, u64 count)
{
    return { (T*)arena_allocate_bytes(arena, sizeof(T) * count, alignof(T)), count };
}

fn String arena_join_string(Arena* arena, Slice<String> pieces)
{
    u64 size = 0;
    for (auto piece : pieces)
    {
        size += piece.length;
    }

    auto* pointer = (u8*)arena_allocate_bytes(arena, size + 1, 1);
    u64 i = 0;
    for (auto piece : pieces)
    {
        memcpy(pointer + i, piece.pointer, piece.length);
        i += piece.length;
    }

    assert(i == size);
    pointer[i] = 0;

    return { pointer, size };
}

fn String arena_duplicate_string(Arena* arena, String string)
{
    auto memory = (u8*)arena_allocate_bytes(arena, string.length + 1, 1);
    memcpy(memory, string.pointer, string.length);
    memory[string.length] = 0;
    return { memory, string.length};
}

fn void arena_restore(Arena* arena, u64 position)
{
    assert(position <= arena->position);
    arena->position = position;
}

fn void arena_reset(Arena* arena)
{
    arena->position = arena_minimum_position;
}

fn String path_absolute(Arena* arena, String relative_path)
{
    u8 buffer[4096];
    auto stack = path_absolute_stack(array_to_slice(buffer), relative_path);
    auto result = arena_duplicate_string(arena, stack);
    return result;
}

fn String file_read(Arena* arena, String file_path)
{
    auto fd = os_open(file_path, { .read = 1 }, { .read = 1 });
    String result = {};

    if (is_file_valid(fd))
    {
        auto file_size = os_file_size(fd);
        result = arena_allocate<u8>(arena, file_size);
        os_read(fd, result, file_size);
        os_close(fd);
    }

    return result;
}

#define bb_fail() os_is_debugger_present() ? trap() : exit(1)
#define bb_fail_with_message(message) (print(message), bb_fail())

fn u64 next_power_of_two(u64 n)
{
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n += 1;
    return n;
}

fn u8 format_integer_decimal(String buffer, u64 v)
{
    u8 byte_count = 0;
    auto value = v;

    if (value != 0)
    {
        u8 reverse_buffer[64];
        u8 reverse_index = 0;

        while (value != 0)
        {
            auto digit_value = (u8)(value % 10);
            auto ascii_character = digit_value + '0';
            value /= 10;
            reverse_buffer[reverse_index] = ascii_character;
            reverse_index += 1;
        }

        while (reverse_index != 0)
        {
            reverse_index -= 1;
            buffer[byte_count] = reverse_buffer[reverse_index];
            byte_count += 1;
        }
    }
    else
    {
        buffer[0] = '0';
        byte_count = 1;
    }

    return byte_count;
}

enum class ExecuteStandardStreamPolicy : u8
{
    inherit,
    pipe,
    ignore,
};

global_variable constexpr u64 standard_stream_count = 2;

struct ExecuteOptions
{
    ExecuteStandardStreamPolicy policies[standard_stream_count]; // INDICES: stdout = 0, stderr = 1
    s32 null_file_descriptor = -1;
};

enum class TerminationKind : u8
{
    unknown,
    exit,
    signal,
    stop,
};

struct Execution
{
    String stdout;
    String stderr;
    TerminationKind termination_kind;
    u32 termination_code;
};

Execution os_execute(Arena* arena, Slice<char* const> arguments, Slice<char* const> environment, ExecuteOptions options);
