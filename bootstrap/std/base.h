#pragma once 

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

#define BB_SAFETY BB_DEBUG

#define STRUCT_FORWARD_DECL(S) typedef struct S S
#define STRUCT(S) STRUCT_FORWARD_DECL(S); struct S
#define UNION_FORWARD_DECL(U) typedef union U U
#define UNION(U) UNION_FORWARD_DECL(U); union U

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define CLAMP(a, x, b) (((a)>(x))?(a):((b)<(x))?(b):(x))

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
typedef _Float16 f16;
#endif
typedef float f32;
typedef double f64;

typedef u32 Hash32;
typedef u64 Hash64;

#if BB_DEBUG
#define assert(x) if (unlikely(!(x))) { my_panic("Assert failed: \"" # x "\" at {cstr}:{u32}\n", __FILE__, __LINE__); }
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
#define unreachable() my_panic("Unreachable triggered\n", __FILE__, __LINE__)
#else
#define unreachable() unreachable_raw()
#endif
#ifdef __TINYC__
#define fix_unreachable() unreachable_raw()
#else
#define fix_unreachable()
#endif


#define static_assert(x) _Static_assert((x), "Static assert failed!")
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
#define failed_execution() my_panic("Failed execution at {cstr}:{u32}\n", __FILE__, __LINE__)
#define todo() my_panic("TODO at {cstr}:{u32}\n", __FILE__, __LINE__)

fn void print(const char* format, ...);
fn u8 os_is_being_debugged();
fn void os_exit(u32 exit_code);

#define my_panic(...) do \
{\
    print(__VA_ARGS__);\
    if (os_is_being_debugged())\
    {\
        trap();\
        fix_unreachable();\
    }\
    else\
    {\
        os_exit(1);\
        fix_unreachable();\
    }\
} while (0)

#if _MSC_VER
#define trap() __fastfail(1)
#elif __has_builtin(__builtin_trap)
#define trap() __builtin_trap()
#else
fn void trap()
{
    asm volatile("ud2");
}
#endif

#define let_pointer_cast(PointerChildType, var_name, value) PointerChildType* var_name = (PointerChildType*)(value)
#if defined(__TINYC__) || defined(_MSC_VER)
#define let(name, value) typeof(value) name = (value)
#else
#define let(name, value) __auto_type name = (value)
#endif
#define let_cast_unchecked(name, T, value) T name = (T)(value)
#define let_cast(T, name, value) T name = cast_to(T, value)
#define let_va_arg(T, name, args) T name = va_arg(args, T)
#define assign_cast(to, from) to = cast_to(typeof(to), from)
#define transmute(D, source) *(D*)&source

UNION(SafeInteger)
{
    s64 signed_value;
    u64 unsigned_value;
};

fn SafeInteger safe_integer_cast(SafeInteger value, u64 to_size, u64 to_signedness, u64 from_size, u64 from_signedness)
{
    SafeInteger result;
    let(shifter, to_size * 8 - to_signedness);
    let(to_max, (u64)(1 << shifter) - 1);
    // A fix for 64-bit wrapping
    to_max = to_max == 0 ? UINT64_MAX : to_max;
    let(to_signed_min, -((s64)1 << shifter));
    if (from_signedness == to_signedness)
    {
        if (to_size < from_size)
        {
            switch (to_signedness)
            {
                case 0:
                    {
                        if (value.unsigned_value > to_max)
                        {
                            todo();
                        }
                    } break;
                case 1:
                    {
                        if (value.signed_value < to_signed_min)
                        {
                            todo();
                        }
                        if (value.signed_value > (s64)to_max)
                        {
                            todo();
                        }
                    }
            }
        }
    }
    else
    {
        if (from_signedness)
        {
            if (value.signed_value < 0)
            {
                todo();
            }
            else if (value.unsigned_value > to_max)
            {
                todo();
            }
        }
        else
        {
            if (value.unsigned_value > to_max)
            {
                todo();
            }
        }
    }

    result = value;

    return result;
}

#define type_is_signed(T) ((T)(-1) < 0)
#if BB_SAFETY
#define safe_integer_cast_function(To, value) (To) ((value) < 0 ? (safe_integer_cast((SafeInteger) { .signed_value = (value) }, sizeof(To), type_is_signed(To), sizeof(typeof(value)), type_is_signed(typeof(value)))).signed_value : (safe_integer_cast((SafeInteger) { .signed_value = (value) }, sizeof(To), type_is_signed(To), sizeof(typeof(value)), type_is_signed(typeof(value)))).unsigned_value)
#endif

#if BB_SAFETY
#define cast_to(T, value) safe_integer_cast_function(T, value)
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
#ifdef __clang__
#define may_be_unused __attribute__((unused))
#else
#define may_be_unused
#endif
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

const may_be_unused global_variable u8 brace_open = '{';
const may_be_unused global_variable u8 brace_close = '}';

const may_be_unused global_variable u8 parenthesis_open = '(';
const may_be_unused global_variable u8 parenthesis_close = ')';

const may_be_unused global_variable u8 bracket_open = '[';
const may_be_unused global_variable u8 bracket_close = ']';

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

fn u8 cast_u32_to_u8(u32 source, const char* name, int line);
fn u16 cast_u32_to_u16(u32 source, const char* name, int line);
fn s16 cast_u32_to_s16(u32 source, const char* name, int line);
fn s32 cast_u32_to_s32(u32 source, const char* name, int line);
fn u8 cast_u64_to_u8(u64 source, const char* name, int line);
fn u16 cast_u64_to_u16(u64 source, const char* name, int line);
fn u32 cast_u64_to_u32(u64 source, const char* name, int line);
fn s32 cast_u64_to_s32(u64 source, const char* name, int line);
fn s64 cast_u64_to_s64(u64 source, const char* name, int line);
fn u8 cast_s32_to_u8(s32 source, const char* name, int line);
fn u16 cast_s32_to_u16(s32 source, const char* name, int line);
fn u32 cast_s32_to_u32(s32 source, const char* name, int line);
fn u64 cast_s32_to_u64(s32 source, const char* name, int line);
fn s16 cast_s32_to_s16(s32 source, const char* name, int line);
fn u16 cast_s64_to_u16(s64 source, const char* name, int line);
fn u32 cast_s64_to_u32(s64 source, const char* name, int line);
fn u64 cast_s64_to_u64(s64 source, const char* name, int line);
fn s32 cast_s64_to_s32(s64 source, const char* name, int line);

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

