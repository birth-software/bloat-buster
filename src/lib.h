#pragma once

#define array_length(x) (sizeof(x) / sizeof((x)[0]))

#define let __auto_type
#define STRUCT(n) typedef struct n n; struct n
#define UNION(n) typedef union n n; union n
#define trap() __builtin_trap()
#define breakpoint() __builtin_debugtrap()
#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

#if __APPLE__ &&  __aarch64__
#define CACHE_LINE_GUESS (128)
#else
#define CACHE_LINE_GUESS (64)
#endif


#ifdef NDEBUG
#define UNREACHABLE() __builtin_unreachable()
#else
#define UNREACHABLE() __builtin_trap()
#endif

#include <stdint.h>
#include <string.h>
#include <assert.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef signed __int128 s128;

typedef float f32;
typedef double f64;
#ifndef _WIN32
typedef __float128 f128;
#endif

#define GB(x) 1024ull * MB(x)
#define MB(x) 1024ull * KB(x)
#define KB(x) 1024ull * (x)

STRUCT(str)
{
    char* pointer;
    u64 length;
};

STRUCT(StringSlice)
{
    str* pointer;
    u64 length;
};

STRUCT(SliceOfStringSlice)
{
    StringSlice* pointer;
    u64 length;
};

#define S(strlit) (str) { (char*)strlit, strlen(strlit) }
#define string_array_to_slice(arr) (StringSlice) { arr, array_length(arr) }

static str str_from_pointers(char* start, char* end)
{
    assert(end >= start);
    u64 len = end - start;
    return (str) { start, len };
}

static str str_from_ptr_len(char* ptr, u64 len)
{
    return (str) { ptr, len };
}

static str str_from_ptr_start_end(char* ptr, u64 start, u64 end)
{
    return (str) { ptr + start, end - start };
}

static str str_slice_start(str s, u64 start)
{
    s.pointer += start;
    s.length -= start;
    return s;
}

static bool memory_compare(void* a, void* b, u64 i)
{
    bool result = 1;

    let p1 = (u8*)a;
    let p2 = (u8*)b;

    while (i--)
    {
        bool is_equal = *p1 == *p2;
        if (!is_equal)
        {
            result = 0;
            break;
        }

        p1 += 1;
        p2 += 1;
    }

    return result;
}

static str str_slice(str s, u64 start, u64 end)
{
    s.pointer += start;
    s.length = end - start;
    return s;
}

static bool str_equal(str s1, str s2)
{
    bool is_equal = s1.length == s2.length;
    if (is_equal & (s1.length != 0))
    {
        is_equal = memory_compare(s1.pointer, s2.pointer, s1.length);
    }

    return is_equal;
}

static u64 align_forward(u64 n, u64 a)
{
    let mask = a - 1;
    let result = (n + mask) & ~mask;
    return result;
}

STRUCT(OpenFlags)
{
    u64 truncate:1;
    u64 execute:1;
    u64 write:1;
    u64 read:1;
    u64 create:1;
    u64 directory:1;
};

STRUCT(OpenPermissions)
{
    u64 read:1;
    u64 write:1;
    u64 execute:1;
};


STRUCT(Arena)
{
    u64 reserved_size;
    u64 position;
    u64 os_position;
    u64 granularity;
    u8 reserved[CACHE_LINE_GUESS - (sizeof(u64) * 4)];
};

STRUCT(ArenaInitialization)
{
    u64 reserved_size;
    u64 granularity;
    u64 initial_size;
};

typedef struct FileDescriptor FileDescriptor;

typedef 
#ifdef _WIN32
u64
#else
u128
#endif
TimeDataType;

void os_init();
Arena* arena_initialize(ArenaInitialization initialization);
void arena_set_position(Arena* arena, u64 position);
void arena_reset_to_start(Arena* arena);
void* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment);
str arena_join_string(Arena* arena, StringSlice strings);

FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions);
u64 os_file_get_size(FileDescriptor* file_descriptor);
void os_file_write(FileDescriptor* file_descriptor, str buffer);
void os_file_close(FileDescriptor* file_descriptor);

#define arena_allocate(arena, T, count) (T*) arena_allocate_bytes(arena, sizeof(T) * count, alignof(T))

str file_read(Arena* arena, str path);

TimeDataType take_timestamp();
u64 ns_between(TimeDataType start, TimeDataType end);

[[noreturn]] void fail();
