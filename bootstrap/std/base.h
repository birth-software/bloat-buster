#pragma once 

#if _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#define LINK_LIBC 1

#ifdef NDEBUG
#define BB_DEBUG 0
#else
#define BB_DEBUG 1
#endif

#define BB_INCLUDE_INTRINSIC 0
#if BB_DEBUG == 0
#undef BB_INCLUDE_INTRINSIC
#define BB_INCLUDE_INTRINSIC 1
#endif
#if BB_INCLUDE_INTRINSIC
#if defined(__x86_64__)
#include <immintrin.h>
#endif
#endif
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#define BB_SAFETY BB_DEBUG

#define STRUCT_FORWARD_DECL(S) typedef struct S S
#define STRUCT(S) STRUCT_FORWARD_DECL(S); struct S
#define UNION_FORWARD_DECL(U) typedef union U U
#define UNION(U) UNION_FORWARD_DECL(U); union U

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define CLAMP(a, x, b) (((a)>(x))?(a):((b)<(x))?(b):(x))

#ifdef __TINYC__
#define declare_vector_type #error
#else
#ifdef __clang__
#define declare_vector_type(T, count, name) typedef T name __attribute__((ext_vector_type(count)))
#else
#define declare_vector_type(T, count, name) typedef T name __attribute__((vector_size(count)))
#endif
#endif
#define array_length(arr) sizeof(arr) / sizeof((arr)[0])
#define KB(n) ((n) * 1024)
#define MB(n) ((n) * 1024 * 1024)
#define GB(n) ((u64)(n) * 1024 * 1024 * 1024)
#define TB(n) ((u64)(n) * 1024 * 1024 * 1024 * 1024)
#define unused(x) (void)(x)
#if _MSC_VER
#define BB_NORETURN __declspec(noreturn)
#define BB_COLD __declspec(noinline)
#elif defined(__TINYC__)
#define BB_NORETURN __attribute__((noreturn))
#define BB_COLD __attribute__((cold))
#else
#define BB_NORETURN [[noreturn]]
#define BB_COLD [[gnu::cold]]
#endif
#define TRUNCATE(Destination, source) (Destination)(source)

#if _MSC_VER
#define ENUM_START(EnumName, T) typedef T EnumName; typedef enum EnumName ## Flags
#define ENUM_END(EnumName) EnumName ## Flags
#else
#define ENUM_START(EnumName, T) typedef enum EnumName : T
#define ENUM_END(EnumName) EnumName
#endif

#define ENUM(EnumName, T, ...) \
ENUM_START(EnumName, T)\
{\
    __VA_ARGS__\
} ENUM_END(EnumName)

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#if defined (__TINYC__) || defined(_MSC_VER)
UNION(u128)
{
    struct
    {
        u64 low;
        u64 high;
    };
    u64 v[2];
};
#else
typedef __uint128_t u128;
#endif
typedef unsigned int uint;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
#if !defined(__TINYC__) && !defined(_MSC_VER)
typedef __int128_t s128;
#endif

typedef size_t usize;

#if !defined(__TINYC__) && !defined(_MSC_VER)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef _Float16 f16;
#pragma GCC diagnostic pop
#endif
typedef float f32;
typedef double f64;

typedef u32 Hash32;
typedef u64 Hash64;

#define Slice(T) Slice_ ## T
#define SliceP(T) SliceP_ ## T
#define declare_slice_ex(T, StructName) STRUCT(StructName) \
{\
    T* pointer;\
    u64 length;\
}

#define declare_slice(T) declare_slice_ex(T, Slice(T))
#define declare_slice_p(T) declare_slice_ex(T*, SliceP(T))

declare_slice(u8);
declare_slice(u16);
declare_slice(u32);
declare_slice(u64);
declare_slice(s8);
declare_slice(s16);
declare_slice(s32);
declare_slice(s64);

declare_slice_p(char);
declare_slice_p(void);

typedef Slice(u8) String;
declare_slice(String);

#if BB_DEBUG
#define assert(x) (unlikely(!(x)) ? panic("Assert failed: \"" # x "\" at {cstr}:{u32}\n", __FILE__, __LINE__) : unused(0))
#else
#define assert(x) unused(likely(x))
#endif

#ifndef __cplusplus
#if _MSC_VER
#define unreachable_raw() __assume(0)
#else
#define unreachable_raw() __builtin_unreachable()
#endif
// Undefine unreachable if needed to provide a more safe-guard implementation
#ifdef unreachable
#undef unreachable
#endif
#if BB_DEBUG
#define unreachable() panic("Unreachable triggered\n", __FILE__, __LINE__)
#else
#define unreachable() unreachable_raw()
#endif
#define fix_unreachable() unreachable_raw()

#ifndef static_assert
#define static_assert(x) _Static_assert((x), "Static assert failed!")
#endif
#define alignof(x) _Alignof(x)
#else
#define restrict __restrict
#endif
#ifndef BB_INFINITY
#define BB_INFINITY __builtin_inff()
#endif
#ifndef BB_NAN
#define BB_NAN __builtin_nanf("")
#endif
#define fn static
#define method __attribute__((visibility("internal")))
#define global_variable static
#define forceinline __attribute__((always_inline))
#if _MSC_VER
#define expect(x, b) (!!(x))
#else
#define expect(x, b) __builtin_expect(!!(x), b)
#endif
#define likely(x) expect(x, 1)
#define unlikely(x) expect(x, 0)
#define breakpoint() __builtin_debugtrap()
#define failed_execution() panic("Failed execution at {cstr}:{u32}\n", __FILE__, __LINE__)
#define todo() panic("TODO at {cstr}:{u32}\n", __FILE__, __LINE__); fix_unreachable()

fn void print(const char* format, ...);
BB_NORETURN BB_COLD fn void os_exit(u32 exit_code);

#if _MSC_VER
#define trap() __fastfail(1)
#elif __has_builtin(__builtin_trap)
#define trap() __builtin_trap()
#else
extern BB_NORETURN BB_COLD void abort(void);
fn BB_NORETURN BB_COLD void trap_ext()
{
#ifdef __x86_64__
    asm volatile("ud2");
#else
    abort();
#endif
}
#define trap() (trap_ext(), __builtin_unreachable())
#endif

#define panic(format, ...) (print(format, __VA_ARGS__), os_exit(1))

#define let_pointer_cast(PointerChildType, var_name, value) PointerChildType* var_name = (PointerChildType*)(value)
#if defined(__TINYC__) || defined(_MSC_VER)
#define let(name, value) typeof(value) name = (value)
#else
#define let(name, value) __auto_type name = (value)
#endif
#define let_cast(T, name, value) T name = cast_to(T, value)
#define assign_cast(to, from) to = cast_to(typeof(to), from)
#define let_va_arg(T, name, args) T name = va_arg(args, T)
#define transmute(D, source) *(D*)&source

#if BB_SAFETY
#define cast_to(T, value) (assert((typeof(value)) (T) (value) == (value) && ((value) > 0) == ((T) (value) > 0)), (T) (value))
#else
#define cast_to(T, value) (T)(value)
#endif

typedef enum Corner
{
    CORNER_00,
    CORNER_01,
    CORNER_10,
    CORNER_11,
    CORNER_COUNT,
} Corner;

typedef enum Axis2
{
    AXIS2_X,
    AXIS2_Y,
    AXIS2_COUNT,
} Axis2;

// #ifdef __cplusplus
// #define EXPORT extern "C"
// #else
// #define EXPORT
// #endif

#if defined(__cplusplus) && defined(__linux__)
#define NO_EXCEPT __THROW
#else
#define NO_EXCEPT
#endif

#define NamedEnumMemberEnum(e, enum_member) e ## _ ## enum_member
#define NamedEnumMemberString(e, enum_member) strlit(#enum_member)

typedef SliceP(char) CStringSlice;

#ifdef _WIN32
typedef void* FileDescriptor;
#else
typedef int FileDescriptor;
#endif

#define FOR_N(it, start, end) \
for (u32 it = (start), end__ = (end); it < end__; ++it)

#define FOR_REV_N(it, start, end) \
for (u32 it = (end), start__ = (start); (it--) > start__;)

#define FOR_BIT(it, start, bits) \
for (typeof(bits) _bits_ = (bits), it = (start); _bits_; _bits_ >>= 1, ++it) if (_bits_ & 1)

#define FOREACH_SET(it, set) \
FOR_N(_i, 0, ((set)->arr.capacity + 63) / 64) FOR_BIT(it, _i*64, (set)->arr.pointer[_i])

#define size_until_end(T, field_name) (sizeof(T) - offsetof(T, field_name))
#define SWAP(a, b) \
    do {\
        static_assert(typeof(a) == typeof(b));\
        let(temp, a);\
        a = b;\
        b = temp;\
    } while (0)

#define slice_from_pointer_range(T, start, end) (Slice(T)) { .pointer = start, .length = (u64)(end - start), }

#define strlit_len(s) (sizeof(s) - 1)
#define strlit(s) (String){ .pointer = (u8*)(s), .length = strlit_len(s), }
#define ch_to_str(ch) (String){ .pointer = &ch, .length = 1 }
#define array_to_slice(arr) { .pointer = (arr), .length = array_length(arr) }
#define array_to_bytes(arr) { .pointer = (u8*)(arr), .length = sizeof(arr) }
#define pointer_to_bytes(p) (String) { .pointer = (u8*)(p), .length = sizeof(*p) }
#define scalar_to_bytes(s) pointer_to_bytes(&(s))
#define string_to_c(s) ((char*)((s).pointer))
#define cstr(s) ((String) { .pointer = (u8*)(s), .length = strlen((char*)s), } )

#define case_to_name(prefix, e) case prefix ## e: return strlit(#e)

global_variable const u8 brace_open = '{';
global_variable const u8 brace_close = '}';

global_variable const u8 parenthesis_open = '(';
global_variable const u8 parenthesis_close = ')';

global_variable const u8 bracket_open = '[';
global_variable const u8 bracket_close = ']';

#define s_get(s, i) (s).pointer[i]
#define s_get_pointer(s, i) &((s).pointer[i])
#define s_get_slice(T, s, start, end) (Slice(T)){ .pointer = ((s).pointer) + (start), .length = (end) - (start) }
#define s_equal(a, b) ((a).length == (b).length && memcmp((a).pointer, (b).pointer, sizeof(*((a).pointer)) * (a).length) == 0)

fn u64 align_forward(u64 value, u64 alignment);
fn u64 align_backward(u64 value, u64 alignment);
fn u8 log2_alignment(u64 alignment);
fn u8 is_power_of_two(u64 value);
fn u8 first_bit_set_32(u32 value);
fn u64 first_bit_set_64(u64 value);

fn u32 format_decimal(String buffer, u64 decimal);
fn u32 format_hexadecimal(String buffer, u64 hexadecimal);
fn u64 format_float(String buffer, f64 value_double);

fn u64 is_decimal_digit(u8 ch);
fn u32 is_space(u8 ch, u8 next_ch);
fn u8 get_next_ch_safe(String string, u64 index);
fn u64 is_identifier_start(u8 ch);
fn u64 is_identifier_ch(u8 ch);
fn u64 is_alphabetic(u8 ch);

fn u64 parse_decimal(String string);

global_variable const Hash64 fnv_offset = 14695981039346656037ull;
global_variable const u64 fnv_prime = 1099511628211ull;

fn Hash32 hash32_fib_end(Hash32 hash);
fn Hash32 hash64_fib_end(Hash64 hash);

fn Hash64 hash_byte(Hash64 source, u8 ch);
fn Hash64 hash_bytes(String bytes);
fn Hash32 hash64_to_hash32(Hash64 hash64);

fn u64 round_up_to_next_power_of_2(u64 n);

STRUCT(TextureIndex)
{
    u32 value;
};

fn u64 safe_flag(u64 value, u64 flag)
{
    u64 result = value & ((u64)0 - flag);
    return result;
}

#define member_from_offset(pointer, type, memory_offset) (*(type*)((u8*)pointer + memory_offset))
#if _MSC_VER
#define offset_of(T, member) offsetof(T, member)
#else
#define offset_of(T, member) __builtin_offsetof(T, member)
#endif

