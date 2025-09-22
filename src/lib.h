#pragma once

#define _CRT_SECURE_NO_WARNINGS
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define BB_INCLUDE_TESTS 1

#if defined(__cplusplus)
#define EXPORT extern "C"
#else
#define EXPORT extern
#endif

#if UNITY_BUILD
#define PUB_DECL static
#define PUB_IMPL static
#else
#define PUB_DECL
#define PUB_IMPL
#endif

#define LOCAL static

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
#include <stdlib.h>
#include <stdbool.h>

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
#if defined (__SIZEOF_FLOAT128__)
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
typedef struct ThreadHandle ThreadHandle;

STRUCT(ThreadCreateOptions)
{
};

typedef
#if defined(__linux__) || defined(__APPLE__)
void*
#elif defined(_WIN32)
unsigned long
#endif
ThreadReturnType;

typedef ThreadReturnType ThreadCallback(void*);

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

STRUCT(IntegerParsing)
{
    u64 value;
    u64 i;
};

PUB_DECL void os_init();
PUB_DECL Arena* arena_create(ArenaInitialization initialization);
PUB_DECL bool arena_destroy(Arena* arena, u64 count);
PUB_DECL void arena_set_position(Arena* arena, u64 position);
PUB_DECL void arena_reset_to_start(Arena* arena);
PUB_DECL void* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment);
PUB_DECL str arena_duplicate_string(Arena* arena, str str, bool zero_terminate);
PUB_DECL str arena_join_string(Arena* arena, StringSlice strings, bool zero_terminate);
PUB_DECL void* arena_current_pointer(Arena* arena, u64 alignment);

PUB_DECL FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions);
PUB_DECL u64 os_file_get_size(FileDescriptor* file_descriptor);
PUB_DECL void os_file_write(FileDescriptor* file_descriptor, str buffer);
PUB_DECL void os_file_close(FileDescriptor* file_descriptor);

#define arena_allocate(arena, T, count) (T*) arena_allocate_bytes(arena, sizeof(T) * (count), alignof(T))

PUB_DECL str file_read(Arena* arena, str path, FileReadOptions options);

PUB_DECL TimeDataType take_timestamp();
PUB_DECL u64 ns_between(TimeDataType start, TimeDataType end);

PUB_DECL str path_absolute(Arena* arena, const char* restrict relative_file_path);

PUB_DECL ExecutionResult os_execute(Arena* arena, char** arguments, char** environment, ExecutionOptions options);

PUB_DECL str format_integer_stack(str buffer, FormatIntegerOptions options);
PUB_DECL str format_integer(Arena* arena, FormatIntegerOptions options, bool zero_terminate);

PUB_DECL u64 parse_integer_decimal_assume_valid(str string);
PUB_DECL IntegerParsing parse_hexadecimal_scalar(const char* restrict p);
PUB_DECL IntegerParsing parse_decimal_scalar(const char* restrict p);
PUB_DECL IntegerParsing parse_octal_scalar(const char* restrict p);
PUB_DECL IntegerParsing parse_binary_scalar(const char* restrict p);
#ifdef __AVX512F__
PUB_DECL IntegerParsing parse_hexadecimal_vectorized(const char* restrict p);
PUB_DECL IntegerParsing parse_decimal_vectorized(const char* restrict p);
PUB_DECL IntegerParsing parse_octal_vectorized(const char* restrict p);
PUB_DECL IntegerParsing parse_binary_vectorized(const char* restrict p);
#endif

PUB_DECL FileDescriptor* os_get_stdout();

PUB_DECL ThreadHandle* os_thread_create(ThreadCallback* callback, ThreadCreateOptions options);
PUB_DECL u32 os_thread_join(ThreadHandle* handle);
[[noreturn]] PUB_DECL void fail();

PUB_DECL u64 next_power_of_two(u64 n);

constexpr u64 string_no_match = UINT64_MAX;

PUB_DECL bool str_is_zero_terminated(str s);
PUB_DECL str str_from_pointers(char* start, char* end);
PUB_DECL str str_from_ptr_len(const char* ptr, u64 len);
PUB_DECL str str_from_ptr_start_end(char* ptr, u64 start, u64 end);
PUB_DECL str str_slice_start(str s, u64 start);
PUB_DECL bool memory_compare(void* a, void* b, u64 i);
PUB_DECL str str_slice(str s, u64 start, u64 end);
PUB_DECL bool str_equal(str s1, str s2);
PUB_DECL u64 str_last_ch(str s, u8 ch);
PUB_DECL u64 align_forward(u64 n, u64 a);
PUB_DECL bool is_space(char ch);
PUB_DECL bool is_decimal(char ch);
PUB_DECL bool is_octal(char ch);
PUB_DECL bool is_binary(char ch);
PUB_DECL bool is_hexadecimal_alpha_lower(char ch);
PUB_DECL bool is_hexadecimal_alpha_upper(char ch);
PUB_DECL bool is_hexadecimal_alpha(char ch);
PUB_DECL bool is_hexadecimal(char ch);
PUB_DECL bool is_identifier_start(char ch);
PUB_DECL bool is_identifier(char ch);

#if BB_INCLUDE_TESTS
PUB_DECL bool lib_tests(TestArguments* restrict arguments);
#endif
