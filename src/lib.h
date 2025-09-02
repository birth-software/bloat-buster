#pragma once

#define BB_INCLUDE_TESTS 1

#define array_length(x) (sizeof(x) / sizeof((x)[0]))

#define field_parent_pointer(type, field, pointer) ((type *)((char *)(pointer) - __builtin_offsetof(type, field)))

#define let __auto_type
#define STRUCT(n) typedef struct n n; struct n
#define UNION(n) typedef union n n; union n
#define trap() __builtin_trap()
#define breakpoint() __builtin_debugtrap()
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define unused(x) ((void)(x))

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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

#define test(a, b) do\
{\
    let _b = b;\
    if (unlikely(!_b))\
    {\
        test_error(S(#b), __LINE__, S(__FUNCTION__), S(__FILE__));\
    }\
    result = result & _b;\
} while (0)

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

static inline u64 next_power_of_two(u64 n)
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

STRUCT(str)
{
    char* pointer;
    u64 length;
};

typedef void ShowCallback(void*,str);

typedef struct Arena Arena;
#if BB_INCLUDE_TESTS
STRUCT(TestArguments)
{
    Arena* arena;
    ShowCallback* show;
};
#endif


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

static u64 string_no_match = UINT64_MAX;

static inline bool str_is_zero_terminated(str s)
{
    return s.pointer[s.length] == 0;
}

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
    assert(a != b);
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

static u64 str_last_ch(str s, u8 ch)
{
    let result = string_no_match;

    let pointer = s.pointer + s.length;

    do
    {
        pointer -= 1;
        if (*pointer == ch)
        {
            result = pointer - s.pointer;
            break;
        }
    } while (pointer - s.pointer);

    return result;
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
};

STRUCT(ArenaInitialization)
{
    u64 reserved_size;
    u64 granularity;
    u64 initial_size;
    u64 count;
};

STRUCT(FileReadOptions)
{
    u32 start_padding;
    u32 start_alignment;
    u32 end_padding;
    u32 end_alignment;
};

typedef enum IntegerFormat
{
    INTEGER_FORMAT_DECIMAL,
    INTEGER_FORMAT_HEXADECIMAL,
    INTEGER_FORMAT_OCTAL,
    INTEGER_FORMAT_BINARY,
} IntegerFormat;

STRUCT(FormatIntegerOptions)
{
    u64 value;
    IntegerFormat format;
    bool treat_as_signed;
    bool prefix;
};

typedef struct FileDescriptor FileDescriptor;

typedef 
#ifdef _WIN32
u64
#else
u128
#endif
TimeDataType;

typedef enum TerminationKind : u8
{
    TERMINATION_KIND_UNKNOWN,
    TERMINATION_KIND_EXIT,
    TERMINATION_KIND_SIGNAL,
    TERMINATION_KIND_STOP,
} TerminationKind;

#define STREAM_COUNT (2)

STRUCT(ExecutionResult)
{
    str streams[STREAM_COUNT];
    u32 termination_code;
    TerminationKind termination_kind;
};

typedef enum StreamPolicy : u8
{
    STREAM_POLICY_INHERIT,
    STREAM_POLICY_PIPE,
    STREAM_POLICY_IGNORE,
} StreamPolicy;

STRUCT(ExecutionOptions)
{
    StreamPolicy policies[STREAM_COUNT];
    FileDescriptor* null_file_descriptor;
};

void os_init();
Arena* arena_create(ArenaInitialization initialization);
bool arena_destroy(Arena* arena, u64 count);
void arena_set_position(Arena* arena, u64 position);
void arena_reset_to_start(Arena* arena);
void* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment);
str arena_duplicate_string(Arena* arena, str str, bool zero_terminate);
str arena_join_string(Arena* arena, StringSlice strings, bool zero_terminate);
void* arena_current_pointer(Arena* arena, u64 alignment);

FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions);
u64 os_file_get_size(FileDescriptor* file_descriptor);
void os_file_write(FileDescriptor* file_descriptor, str buffer);
void os_file_close(FileDescriptor* file_descriptor);

#define arena_allocate(arena, T, count) (T*) arena_allocate_bytes(arena, sizeof(T) * (count), alignof(T))

str file_read(Arena* arena, str path, FileReadOptions options);

TimeDataType take_timestamp();
u64 ns_between(TimeDataType start, TimeDataType end);

str path_absolute(Arena* arena, const char* restrict relative_file_path);

str format_integer_stack(str buffer, FormatIntegerOptions options);
str format_integer(Arena* arena, FormatIntegerOptions options, bool zero_terminate);
ExecutionResult os_execute(Arena* arena, char** arguments, char** environment, ExecutionOptions options);

[[noreturn]] void fail();

#if BB_INCLUDE_TESTS
bool lib_tests(TestArguments* restrict arguments);
#endif
