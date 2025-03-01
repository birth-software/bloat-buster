#include <complex.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static void require(bool ok)
{
    if (!ok)
    {
        __builtin_trap();
    }
}

#ifndef memcpy
void* memcpy(void* dst_ptr, const void* src_ptr, size_t count)
{
    uint8_t* dst = (uint8_t*)dst_ptr;
    uint8_t* src = (uint8_t*)src_ptr;

    for (size_t i = 0; i < count; i += 1)
    {
        dst[i] = src[i];
    }

    return dst;
}
#endif

#ifndef memset
void* memset(void* dst_ptr, int value, size_t count)
{
    uint8_t ch = (uint8_t) value;
    uint8_t* ptr = (uint8_t*) dst_ptr;
    for (size_t i = 0; i < count; i += 1) {
        ptr[i] = ch;
    }

    return ptr;
}
#endif

#if defined __powerpc__ && !defined _ARCH_PPC64
#  define ZIG_PPC32
#endif

#ifdef __riscv
#  ifdef _ILP32
#    define ZIG_RISCV32
#  else
#    define ZIG_RISCV64
#  endif
#endif

#if defined(__aarch64__) && defined(__linux__)
// TODO: https://github.com/ziglang/zig/issues/14908
#define ZIG_BUG_14908
#endif

#ifdef __i386__
#  define ZIG_NO_I128
#endif

#ifdef __arm__
#  define ZIG_NO_I128
#endif

#ifdef __mips__
#  define ZIG_NO_I128
#endif

#ifdef ZIG_PPC32
#  define ZIG_NO_I128
#endif

#ifdef ZIG_RISCV32
#  define ZIG_NO_I128
#endif

#ifdef __i386__
#  define ZIG_NO_COMPLEX
#endif

#ifdef __mips__
#  define ZIG_NO_COMPLEX
#endif

#ifdef __arm__
#  define ZIG_NO_COMPLEX
#endif

#ifdef __powerpc__
#  define ZIG_NO_COMPLEX
#endif

#ifdef __riscv
#  define ZIG_NO_COMPLEX
#endif

#ifdef __x86_64__
#define ZIG_NO_RAW_F16
#endif

#ifdef __i386__
#define ZIG_NO_RAW_F16
#endif

#ifdef __mips__
#define ZIG_NO_RAW_F16
#endif

#ifdef __riscv
#define ZIG_NO_RAW_F16
#endif

#ifdef __wasm__
#define ZIG_NO_RAW_F16
#endif

#ifdef __powerpc__
#define ZIG_NO_RAW_F16
#endif

#ifdef __aarch64__
#define ZIG_NO_F128
#endif

#ifdef __arm__
#define ZIG_NO_F128
#endif

#ifdef __mips__
#define ZIG_NO_F128
#endif

#ifdef __riscv
#define ZIG_NO_F128
#endif

#ifdef __powerpc__
#define ZIG_NO_F128
#endif

#ifdef __APPLE__
#define ZIG_NO_F128
#endif

#ifndef ZIG_NO_I128
// struct i128 {
//     __int128 value;
// };

// struct u128 {
//     unsigned __int128 value;
// };
#endif

void bb_u8(uint8_t);
void bb_u16(uint16_t);
void bb_u32(uint32_t);
void bb_u64(uint64_t);
// #ifndef ZIG_NO_I128
// void bb_struct_u128(struct u128);
// #endif
void bb_s8(int8_t);
void bb_s16(int16_t);
void bb_s32(int32_t);
void bb_s64(int64_t);
// #ifndef ZIG_NO_I128
// void bb_struct_i128(struct i128);
// #endif
void bb_five_integers(int32_t, int32_t, int32_t, int32_t, int32_t);

// void bb_f32(float);
// void bb_f64(double);
// void bb_longdouble(long double);
// void bb_fivesfloats(float, float, float, float, float);

bool bb_ret_bool();
uint8_t bb_ret_u8();
uint16_t bb_ret_u16();
uint32_t bb_ret_u32();
uint64_t bb_ret_u64();
int8_t bb_ret_s8();
int16_t bb_ret_s16();
int32_t bb_ret_s32();
int64_t bb_ret_s64();

void bb_ptr(void *);

void bb_bool(bool);

// Note: These two functions match the signature of __mulsc3 and __muldc3 in compiler-rt (and libgcc)
// float complex bb_cmultf_comp(float a_r, float a_i, float b_r, float b_i);
// double complex bb_cmultd_comp(double a_r, double a_i, double b_r, double b_i);
//
// float complex bb_cmultf(float complex a, float complex b);
// double complex bb_cmultd(double complex a, double complex b);

struct Struct_u64_u64 {
    uint64_t a;
    uint64_t b;
};

struct Struct_u64_u64 bb_ret_struct_u64_u64(void);

void bb_struct_u64_u64_0(struct Struct_u64_u64);
void bb_struct_u64_u64_1(size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_2(size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_3(size_t, size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_4(size_t, size_t, size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_5(size_t, size_t, size_t, size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_6(size_t, size_t, size_t, size_t, size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_7(size_t, size_t, size_t, size_t, size_t, size_t, size_t, struct Struct_u64_u64);
void bb_struct_u64_u64_8(size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t, struct Struct_u64_u64);

struct Struct_u64_u64 c_ret_struct_u64_u64(void) {
    return (struct Struct_u64_u64){ 21, 22 };
}

void c_struct_u64_u64_0(struct Struct_u64_u64 s) {
    require(s.a == 23);
    require(s.b == 24);
}
void c_struct_u64_u64_1(size_t a, struct Struct_u64_u64 s) {
    require(s.a == 25);
    require(s.b == 26);
}
void c_struct_u64_u64_2(size_t a , size_t b, struct Struct_u64_u64 s) {
    require(s.a == 27);
    require(s.b == 28);
}
void c_struct_u64_u64_3(size_t a, size_t b, size_t c, struct Struct_u64_u64 s) {
    require(s.a == 29);
    require(s.b == 30);
}
void c_struct_u64_u64_4(size_t a, size_t b, size_t c, size_t d, struct Struct_u64_u64 s) {
    require(s.a == 31);
    require(s.b == 32);
}
void c_struct_u64_u64_5(size_t a, size_t b, size_t c, size_t d, size_t e, struct Struct_u64_u64 s) {
    require(s.a == 33);
    require(s.b == 34);
}
void c_struct_u64_u64_6(size_t a, size_t b, size_t c, size_t d, size_t e, size_t f, struct Struct_u64_u64 s) {
    require(s.a == 35);
    require(s.b == 36);
}
void c_struct_u64_u64_7(size_t a, size_t b, size_t c, size_t d, size_t e, size_t f, size_t g, struct Struct_u64_u64 s) {
    require(s.a == 37);
    require(s.b == 38);
}
void c_struct_u64_u64_8(size_t a, size_t b, size_t c, size_t d, size_t e, size_t f, size_t g, size_t h, struct Struct_u64_u64 s) {
    require(s.a == 39);
    require(s.b == 40);
}

struct BigStruct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint8_t e;
};

void bb_big_struct(struct BigStruct);

union BigUnion {
    struct BigStruct a;
};

void bb_big_union(union BigUnion);

struct SmallStructInts {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
};

void bb_small_struct_ints(struct SmallStructInts);
struct SmallStructInts bb_ret_small_struct_ints();

struct MedStructInts {
    int32_t x;
    int32_t y;
    int32_t z;
};

void bb_med_struct_ints(struct MedStructInts);
struct MedStructInts bb_ret_med_struct_ints();

struct MedStructMixed {
    uint32_t a;
    float b;
    float c;
    uint32_t d;
};

void bb_med_struct_mixed(struct MedStructMixed);
struct MedStructMixed bb_ret_med_struct_mixed();

void bb_small_packed_struct(uint8_t);
// #ifndef ZIG_NO_I128
// void bb_big_packed_struct(__int128);
// #endif

struct SplitStructInts {
    uint64_t a;
    uint8_t b;
    uint32_t c;
};
void bb_split_struct_ints(struct SplitStructInts);

struct SplitStructMixed {
    uint64_t a;
    uint8_t b;
    float c;
};
void bb_split_struct_mixed(struct SplitStructMixed);
struct SplitStructMixed bb_ret_split_struct_mixed();

struct BigStruct bb_big_struct_both(struct BigStruct);

typedef float Vector2Float __attribute__((ext_vector_type(2)));
typedef float Vector4Float __attribute__((ext_vector_type(4)));

void c_vector_2_float(Vector2Float vec) {
    require(vec[0] == 1.0);
    require(vec[1] == 2.0);
}

void c_vector_4_float(Vector4Float vec) {
    require(vec[0] == 1.0);
    require(vec[1] == 2.0);
    require(vec[2] == 3.0);
    require(vec[3] == 4.0);
}

Vector2Float c_ret_vector_2_float(void) {
    return (Vector2Float){
        1.0,
        2.0,
    };
}
Vector4Float c_ret_vector_4_float(void) {
    return (Vector4Float){
        1.0,
        2.0,
        3.0,
        4.0,
    };
}

#if defined(ZIG_BACKEND_STAGE2_X86_64) || defined(ZIG_PPC32) || defined(__wasm__)

typedef bool Vector2Bool __attribute__((ext_vector_type(2)));
typedef bool Vector4Bool __attribute__((ext_vector_type(4)));
typedef bool Vector8Bool __attribute__((ext_vector_type(8)));
typedef bool Vector16Bool __attribute__((ext_vector_type(16)));
typedef bool Vector32Bool __attribute__((ext_vector_type(32)));
typedef bool Vector64Bool __attribute__((ext_vector_type(64)));
typedef bool Vector128Bool __attribute__((ext_vector_type(128)));
typedef bool Vector256Bool __attribute__((ext_vector_type(256)));
typedef bool Vector512Bool __attribute__((ext_vector_type(512)));

void c_vector_2_bool(Vector2Bool vec) {
    require(vec[0] == true);
    require(vec[1] == true);
}

void c_vector_4_bool(Vector4Bool vec) {
    require(vec[0] == true);
    require(vec[1] == true);
    require(vec[2] == false);
    require(vec[3] == true);
}

void c_vector_8_bool(Vector8Bool vec) {
    require(vec[0] == true);
    require(vec[1] == false);
    require(vec[2] == true);
    require(vec[3] == true);
    require(vec[4] == true);
    require(vec[5] == true);
    require(vec[6] == false);
    require(vec[7] == true);
}

void c_vector_16_bool(Vector16Bool vec) {
    require(vec[0] == true);
    require(vec[1] == false);
    require(vec[2] == false);
    require(vec[3] == false);
    require(vec[4] == true);
    require(vec[5] == false);
    require(vec[6] == true);
    require(vec[7] == true);
    require(vec[8] == true);
    require(vec[9] == true);
    require(vec[10] == true);
    require(vec[11] == true);
    require(vec[12] == false);
    require(vec[13] == false);
    require(vec[14] == false);
    require(vec[15] == false);
}

void c_vector_32_bool(Vector32Bool vec) {
    require(vec[0] == true);
    require(vec[1] == false);
    require(vec[2] == true);
    require(vec[3] == true);
    require(vec[4] == false);
    require(vec[5] == false);
    require(vec[6] == true);
    require(vec[7] == false);
    require(vec[8] == true);
    require(vec[9] == false);
    require(vec[10] == true);
    require(vec[11] == true);
    require(vec[12] == true);
    require(vec[13] == false);
    require(vec[14] == false);
    require(vec[15] == true);
    require(vec[16] == false);
    require(vec[17] == true);
    require(vec[18] == false);
    require(vec[19] == true);
    require(vec[20] == true);
    require(vec[21] == true);
    require(vec[22] == true);
    require(vec[23] == true);
    require(vec[24] == false);
    require(vec[25] == true);
    require(vec[26] == true);
    require(vec[27] == true);
    require(vec[28] == false);
    require(vec[29] == true);
    require(vec[30] == true);
    require(vec[31] == false);
}

void c_vector_64_bool(Vector64Bool vec) {
    require(vec[0] == true);
    require(vec[1] == true);
    require(vec[2] == true);
    require(vec[3] == false);
    require(vec[4] == true);
    require(vec[5] == false);
    require(vec[6] == false);
    require(vec[7] == false);
    require(vec[8] == true);
    require(vec[9] == false);
    require(vec[10] == false);
    require(vec[11] == false);
    require(vec[12] == false);
    require(vec[13] == true);
    require(vec[14] == true);
    require(vec[15] == true);
    require(vec[16] == true);
    require(vec[17] == false);
    require(vec[18] == false);
    require(vec[19] == true);
    require(vec[20] == false);
    require(vec[21] == true);
    require(vec[22] == false);
    require(vec[23] == true);
    require(vec[24] == true);
    require(vec[25] == true);
    require(vec[26] == true);
    require(vec[27] == true);
    require(vec[28] == true);
    require(vec[29] == true);
    require(vec[30] == false);
    require(vec[31] == false);
    require(vec[32] == true);
    require(vec[33] == true);
    require(vec[34] == false);
    require(vec[35] == true);
    require(vec[36] == false);
    require(vec[37] == false);
    require(vec[38] == true);
    require(vec[39] == true);
    require(vec[40] == true);
    require(vec[41] == false);
    require(vec[42] == false);
    require(vec[43] == true);
    require(vec[44] == true);
    require(vec[45] == false);
    require(vec[46] == true);
    require(vec[47] == false);
    require(vec[48] == true);
    require(vec[49] == false);
    require(vec[50] == false);
    require(vec[51] == true);
    require(vec[52] == false);
    require(vec[53] == true);
    require(vec[54] == true);
    require(vec[55] == true);
    require(vec[56] == true);
    require(vec[57] == true);
    require(vec[58] == false);
    require(vec[59] == false);
    require(vec[60] == true);
    require(vec[61] == false);
    require(vec[62] == true);
    require(vec[63] == false);
}

void c_vector_128_bool(Vector128Bool vec) {
    require(vec[0] == false);
    require(vec[1] == false);
    require(vec[2] == false);
    require(vec[3] == false);
    require(vec[4] == false);
    require(vec[5] == true);
    require(vec[6] == true);
    require(vec[7] == false);
    require(vec[8] == true);
    require(vec[9] == true);
    require(vec[10] == false);
    require(vec[11] == true);
    require(vec[12] == true);
    require(vec[13] == false);
    require(vec[14] == true);
    require(vec[15] == true);
    require(vec[16] == true);
    require(vec[17] == false);
    require(vec[18] == false);
    require(vec[19] == false);
    require(vec[20] == false);
    require(vec[21] == true);
    require(vec[22] == true);
    require(vec[23] == false);
    require(vec[24] == false);
    require(vec[25] == false);
    require(vec[26] == true);
    require(vec[27] == true);
    require(vec[28] == false);
    require(vec[29] == true);
    require(vec[30] == false);
    require(vec[31] == false);
    require(vec[32] == true);
    require(vec[33] == false);
    require(vec[34] == false);
    require(vec[35] == true);
    require(vec[36] == true);
    require(vec[37] == true);
    require(vec[38] == true);
    require(vec[39] == true);
    require(vec[40] == false);
    require(vec[41] == true);
    require(vec[42] == true);
    require(vec[43] == true);
    require(vec[44] == false);
    require(vec[45] == false);
    require(vec[46] == false);
    require(vec[47] == false);
    require(vec[48] == true);
    require(vec[49] == true);
    require(vec[50] == false);
    require(vec[51] == true);
    require(vec[52] == true);
    require(vec[53] == true);
    require(vec[54] == true);
    require(vec[55] == true);
    require(vec[56] == false);
    require(vec[57] == true);
    require(vec[58] == true);
    require(vec[59] == false);
    require(vec[60] == true);
    require(vec[61] == false);
    require(vec[62] == false);
    require(vec[63] == true);
    require(vec[64] == true);
    require(vec[65] == false);
    require(vec[66] == true);
    require(vec[67] == true);
    require(vec[68] == false);
    require(vec[69] == true);
    require(vec[70] == false);
    require(vec[71] == false);
    require(vec[72] == true);
    require(vec[73] == true);
    require(vec[74] == false);
    require(vec[75] == true);
    require(vec[76] == true);
    require(vec[77] == true);
    require(vec[78] == false);
    require(vec[79] == true);
    require(vec[80] == false);
    require(vec[81] == false);
    require(vec[82] == false);
    require(vec[83] == false);
    require(vec[84] == true);
    require(vec[85] == false);
    require(vec[86] == false);
    require(vec[87] == false);
    require(vec[88] == true);
    require(vec[89] == true);
    require(vec[90] == false);
    require(vec[91] == false);
    require(vec[92] == true);
    require(vec[93] == true);
    require(vec[94] == true);
    require(vec[95] == true);
    require(vec[96] == false);
    require(vec[97] == false);
    require(vec[98] == false);
    require(vec[99] == false);
    require(vec[100] == false);
    require(vec[101] == true);
    require(vec[102] == false);
    require(vec[103] == false);
    require(vec[104] == false);
    require(vec[105] == false);
    require(vec[106] == true);
    require(vec[107] == true);
    require(vec[108] == true);
    require(vec[109] == true);
    require(vec[110] == true);
    require(vec[111] == false);
    require(vec[112] == false);
    require(vec[113] == true);
    require(vec[114] == false);
    require(vec[115] == true);
    require(vec[116] == false);
    require(vec[117] == false);
    require(vec[118] == true);
    require(vec[119] == false);
    require(vec[120] == true);
    require(vec[121] == false);
    require(vec[122] == true);
    require(vec[123] == true);
    require(vec[124] == true);
    require(vec[125] == true);
    require(vec[126] == true);
    require(vec[127] == true);
}

// WASM: The following vector functions define too many Wasm locals for wasmtime in debug mode and are therefore disabled for the wasm target.
#if !defined(__wasm__)

void c_vector_256_bool(Vector256Bool vec) {
    require(vec[0] == false);
    require(vec[1] == true);
    require(vec[2] == true);
    require(vec[3] == false);
    require(vec[4] == false);
    require(vec[5] == true);
    require(vec[6] == true);
    require(vec[7] == true);
    require(vec[8] == false);
    require(vec[9] == true);
    require(vec[10] == true);
    require(vec[11] == true);
    require(vec[12] == false);
    require(vec[13] == true);
    require(vec[14] == false);
    require(vec[15] == true);
    require(vec[16] == false);
    require(vec[17] == false);
    require(vec[18] == true);
    require(vec[19] == true);
    require(vec[20] == false);
    require(vec[21] == true);
    require(vec[22] == false);
    require(vec[23] == false);
    require(vec[24] == false);
    require(vec[25] == true);
    require(vec[26] == true);
    require(vec[27] == false);
    require(vec[28] == false);
    require(vec[29] == true);
    require(vec[30] == true);
    require(vec[31] == false);
    require(vec[32] == true);
    require(vec[33] == false);
    require(vec[34] == false);
    require(vec[35] == true);
    require(vec[36] == false);
    require(vec[37] == true);
    require(vec[38] == false);
    require(vec[39] == true);
    require(vec[40] == true);
    require(vec[41] == true);
    require(vec[42] == true);
    require(vec[43] == false);
    require(vec[44] == false);
    require(vec[45] == true);
    require(vec[46] == false);
    require(vec[47] == false);
    require(vec[48] == false);
    require(vec[49] == false);
    require(vec[50] == false);
    require(vec[51] == false);
    require(vec[52] == true);
    require(vec[53] == true);
    require(vec[54] == true);
    require(vec[55] == true);
    require(vec[56] == true);
    require(vec[57] == true);
    require(vec[58] == false);
    require(vec[59] == true);
    require(vec[60] == true);
    require(vec[61] == false);
    require(vec[62] == false);
    require(vec[63] == true);
    require(vec[64] == false);
    require(vec[65] == false);
    require(vec[66] == false);
    require(vec[67] == false);
    require(vec[68] == false);
    require(vec[69] == false);
    require(vec[70] == true);
    require(vec[71] == true);
    require(vec[72] == true);
    require(vec[73] == false);
    require(vec[74] == false);
    require(vec[75] == false);
    require(vec[76] == true);
    require(vec[77] == false);
    require(vec[78] == true);
    require(vec[79] == true);
    require(vec[80] == false);
    require(vec[81] == false);
    require(vec[82] == true);
    require(vec[83] == true);
    require(vec[84] == false);
    require(vec[85] == true);
    require(vec[86] == true);
    require(vec[87] == true);
    require(vec[88] == true);
    require(vec[89] == true);
    require(vec[90] == true);
    require(vec[91] == true);
    require(vec[92] == false);
    require(vec[93] == true);
    require(vec[94] == true);
    require(vec[95] == false);
    require(vec[96] == false);
    require(vec[97] == true);
    require(vec[98] == true);
    require(vec[99] == false);
    require(vec[100] == true);
    require(vec[101] == false);
    require(vec[102] == false);
    require(vec[103] == true);
    require(vec[104] == false);
    require(vec[105] == true);
    require(vec[106] == true);
    require(vec[107] == true);
    require(vec[108] == true);
    require(vec[109] == true);
    require(vec[110] == false);
    require(vec[111] == false);
    require(vec[112] == false);
    require(vec[113] == false);
    require(vec[114] == true);
    require(vec[115] == true);
    require(vec[116] == false);
    require(vec[117] == true);
    require(vec[118] == false);
    require(vec[119] == false);
    require(vec[120] == true);
    require(vec[121] == false);
    require(vec[122] == false);
    require(vec[123] == true);
    require(vec[124] == false);
    require(vec[125] == true);
    require(vec[126] == true);
    require(vec[127] == true);
    require(vec[128] == true);
    require(vec[129] == false);
    require(vec[130] == true);
    require(vec[131] == true);
    require(vec[132] == false);
    require(vec[133] == false);
    require(vec[134] == true);
    require(vec[135] == false);
    require(vec[136] == false);
    require(vec[137] == true);
    require(vec[138] == false);
    require(vec[139] == true);
    require(vec[140] == false);
    require(vec[141] == true);
    require(vec[142] == true);
    require(vec[143] == true);
    require(vec[144] == true);
    require(vec[145] == false);
    require(vec[146] == true);
    require(vec[147] == false);
    require(vec[148] == false);
    require(vec[149] == false);
    require(vec[150] == true);
    require(vec[151] == true);
    require(vec[152] == true);
    require(vec[153] == true);
    require(vec[154] == true);
    require(vec[155] == false);
    require(vec[156] == true);
    require(vec[157] == false);
    require(vec[158] == false);
    require(vec[159] == false);
    require(vec[160] == true);
    require(vec[161] == true);
    require(vec[162] == false);
    require(vec[163] == true);
    require(vec[164] == true);
    require(vec[165] == false);
    require(vec[166] == false);
    require(vec[167] == false);
    require(vec[168] == false);
    require(vec[169] == true);
    require(vec[170] == false);
    require(vec[171] == true);
    require(vec[172] == false);
    require(vec[173] == false);
    require(vec[174] == false);
    require(vec[175] == false);
    require(vec[176] == true);
    require(vec[177] == true);
    require(vec[178] == true);
    require(vec[179] == false);
    require(vec[180] == true);
    require(vec[181] == false);
    require(vec[182] == true);
    require(vec[183] == true);
    require(vec[184] == false);
    require(vec[185] == false);
    require(vec[186] == true);
    require(vec[187] == false);
    require(vec[188] == false);
    require(vec[189] == false);
    require(vec[190] == false);
    require(vec[191] == true);
    require(vec[192] == true);
    require(vec[193] == true);
    require(vec[194] == true);
    require(vec[195] == true);
    require(vec[196] == true);
    require(vec[197] == true);
    require(vec[198] == false);
    require(vec[199] == true);
    require(vec[200] == false);
    require(vec[201] == false);
    require(vec[202] == true);
    require(vec[203] == false);
    require(vec[204] == true);
    require(vec[205] == true);
    require(vec[206] == true);
    require(vec[207] == false);
    require(vec[208] == false);
    require(vec[209] == true);
    require(vec[210] == true);
    require(vec[211] == true);
    require(vec[212] == false);
    require(vec[213] == true);
    require(vec[214] == true);
    require(vec[215] == true);
    require(vec[216] == true);
    require(vec[217] == true);
    require(vec[218] == false);
    require(vec[219] == false);
    require(vec[220] == false);
    require(vec[221] == false);
    require(vec[222] == false);
    require(vec[223] == true);
    require(vec[224] == true);
    require(vec[225] == false);
    require(vec[226] == true);
    require(vec[227] == false);
    require(vec[228] == false);
    require(vec[229] == true);
    require(vec[230] == false);
    require(vec[231] == true);
    require(vec[232] == false);
    require(vec[233] == false);
    require(vec[234] == false);
    require(vec[235] == true);
    require(vec[236] == false);
    require(vec[237] == false);
    require(vec[238] == false);
    require(vec[239] == true);
    require(vec[240] == true);
    require(vec[241] == true);
    require(vec[242] == true);
    require(vec[243] == true);
    require(vec[244] == true);
    require(vec[245] == false);
    require(vec[246] == false);
    require(vec[247] == true);
    require(vec[248] == false);
    require(vec[249] == true);
    require(vec[250] == true);
    require(vec[251] == false);
    require(vec[252] == true);
    require(vec[253] == true);
    require(vec[254] == true);
    require(vec[255] == false);
}

void c_vector_512_bool(Vector512Bool vec) {
    require(vec[0] == true);
    require(vec[1] == true);
    require(vec[2] == true);
    require(vec[3] == true);
    require(vec[4] == true);
    require(vec[5] == false);
    require(vec[6] == false);
    require(vec[7] == true);
    require(vec[8] == true);
    require(vec[9] == true);
    require(vec[10] == true);
    require(vec[11] == false);
    require(vec[12] == true);
    require(vec[13] == true);
    require(vec[14] == false);
    require(vec[15] == false);
    require(vec[16] == false);
    require(vec[17] == true);
    require(vec[18] == true);
    require(vec[19] == true);
    require(vec[20] == true);
    require(vec[21] == true);
    require(vec[22] == false);
    require(vec[23] == false);
    require(vec[24] == true);
    require(vec[25] == true);
    require(vec[26] == false);
    require(vec[27] == false);
    require(vec[28] == false);
    require(vec[29] == false);
    require(vec[30] == false);
    require(vec[31] == true);
    require(vec[32] == true);
    require(vec[33] == false);
    require(vec[34] == true);
    require(vec[35] == true);
    require(vec[36] == true);
    require(vec[37] == true);
    require(vec[38] == true);
    require(vec[39] == true);
    require(vec[40] == false);
    require(vec[41] == true);
    require(vec[42] == true);
    require(vec[43] == false);
    require(vec[44] == false);
    require(vec[45] == false);
    require(vec[46] == true);
    require(vec[47] == true);
    require(vec[48] == false);
    require(vec[49] == true);
    require(vec[50] == false);
    require(vec[51] == true);
    require(vec[52] == true);
    require(vec[53] == false);
    require(vec[54] == true);
    require(vec[55] == false);
    require(vec[56] == false);
    require(vec[57] == true);
    require(vec[58] == true);
    require(vec[59] == false);
    require(vec[60] == true);
    require(vec[61] == true);
    require(vec[62] == false);
    require(vec[63] == true);
    require(vec[64] == false);
    require(vec[65] == true);
    require(vec[66] == true);
    require(vec[67] == true);
    require(vec[68] == true);
    require(vec[69] == true);
    require(vec[70] == true);
    require(vec[71] == true);
    require(vec[72] == true);
    require(vec[73] == true);
    require(vec[74] == false);
    require(vec[75] == true);
    require(vec[76] == false);
    require(vec[77] == true);
    require(vec[78] == false);
    require(vec[79] == false);
    require(vec[80] == false);
    require(vec[81] == true);
    require(vec[82] == false);
    require(vec[83] == true);
    require(vec[84] == true);
    require(vec[85] == false);
    require(vec[86] == true);
    require(vec[87] == true);
    require(vec[88] == true);
    require(vec[89] == false);
    require(vec[90] == true);
    require(vec[91] == true);
    require(vec[92] == false);
    require(vec[93] == true);
    require(vec[94] == false);
    require(vec[95] == true);
    require(vec[96] == true);
    require(vec[97] == false);
    require(vec[98] == false);
    require(vec[99] == false);
    require(vec[100] == true);
    require(vec[101] == true);
    require(vec[102] == false);
    require(vec[103] == true);
    require(vec[104] == false);
    require(vec[105] == false);
    require(vec[106] == true);
    require(vec[107] == false);
    require(vec[108] == false);
    require(vec[109] == true);
    require(vec[110] == false);
    require(vec[111] == false);
    require(vec[112] == false);
    require(vec[113] == false);
    require(vec[114] == false);
    require(vec[115] == true);
    require(vec[116] == true);
    require(vec[117] == false);
    require(vec[118] == false);
    require(vec[119] == false);
    require(vec[120] == false);
    require(vec[121] == true);
    require(vec[122] == false);
    require(vec[123] == false);
    require(vec[124] == true);
    require(vec[125] == true);
    require(vec[126] == false);
    require(vec[127] == true);
    require(vec[128] == false);
    require(vec[129] == true);
    require(vec[130] == true);
    require(vec[131] == false);
    require(vec[132] == true);
    require(vec[133] == false);
    require(vec[134] == false);
    require(vec[135] == false);
    require(vec[136] == false);
    require(vec[137] == true);
    require(vec[138] == true);
    require(vec[139] == false);
    require(vec[140] == false);
    require(vec[141] == false);
    require(vec[142] == true);
    require(vec[143] == true);
    require(vec[144] == false);
    require(vec[145] == false);
    require(vec[146] == true);
    require(vec[147] == true);
    require(vec[148] == true);
    require(vec[149] == true);
    require(vec[150] == true);
    require(vec[151] == true);
    require(vec[152] == true);
    require(vec[153] == false);
    require(vec[154] == true);
    require(vec[155] == false);
    require(vec[156] == false);
    require(vec[157] == true);
    require(vec[158] == false);
    require(vec[159] == true);
    require(vec[160] == false);
    require(vec[161] == true);
    require(vec[162] == true);
    require(vec[163] == true);
    require(vec[164] == true);
    require(vec[165] == true);
    require(vec[166] == true);
    require(vec[167] == true);
    require(vec[168] == true);
    require(vec[169] == false);
    require(vec[170] == true);
    require(vec[171] == true);
    require(vec[172] == false);
    require(vec[173] == true);
    require(vec[174] == true);
    require(vec[175] == false);
    require(vec[176] == false);
    require(vec[177] == false);
    require(vec[178] == true);
    require(vec[179] == false);
    require(vec[180] == false);
    require(vec[181] == true);
    require(vec[182] == true);
    require(vec[183] == true);
    require(vec[184] == true);
    require(vec[185] == true);
    require(vec[186] == true);
    require(vec[187] == true);
    require(vec[188] == true);
    require(vec[189] == true);
    require(vec[190] == false);
    require(vec[191] == true);
    require(vec[192] == true);
    require(vec[193] == false);
    require(vec[194] == false);
    require(vec[195] == true);
    require(vec[196] == true);
    require(vec[197] == false);
    require(vec[198] == true);
    require(vec[199] == true);
    require(vec[200] == false);
    require(vec[201] == true);
    require(vec[202] == true);
    require(vec[203] == false);
    require(vec[204] == true);
    require(vec[205] == true);
    require(vec[206] == true);
    require(vec[207] == true);
    require(vec[208] == false);
    require(vec[209] == true);
    require(vec[210] == false);
    require(vec[211] == true);
    require(vec[212] == true);
    require(vec[213] == false);
    require(vec[214] == true);
    require(vec[215] == false);
    require(vec[216] == true);
    require(vec[217] == false);
    require(vec[218] == true);
    require(vec[219] == false);
    require(vec[220] == false);
    require(vec[221] == true);
    require(vec[222] == false);
    require(vec[223] == false);
    require(vec[224] == false);
    require(vec[225] == true);
    require(vec[226] == true);
    require(vec[227] == false);
    require(vec[228] == false);
    require(vec[229] == false);
    require(vec[230] == true);
    require(vec[231] == false);
    require(vec[232] == true);
    require(vec[233] == false);
    require(vec[234] == false);
    require(vec[235] == false);
    require(vec[236] == true);
    require(vec[237] == true);
    require(vec[238] == false);
    require(vec[239] == false);
    require(vec[240] == false);
    require(vec[241] == false);
    require(vec[242] == false);
    require(vec[243] == true);
    require(vec[244] == true);
    require(vec[245] == false);
    require(vec[246] == true);
    require(vec[247] == false);
    require(vec[248] == false);
    require(vec[249] == true);
    require(vec[250] == false);
    require(vec[251] == false);
    require(vec[252] == false);
    require(vec[253] == true);
    require(vec[254] == false);
    require(vec[255] == false);
    require(vec[256] == false);
    require(vec[257] == false);
    require(vec[258] == true);
    require(vec[259] == true);
    require(vec[260] == true);
    require(vec[261] == true);
    require(vec[262] == false);
    require(vec[263] == true);
    require(vec[264] == false);
    require(vec[265] == false);
    require(vec[266] == false);
    require(vec[267] == true);
    require(vec[268] == false);
    require(vec[269] == false);
    require(vec[270] == true);
    require(vec[271] == true);
    require(vec[272] == false);
    require(vec[273] == false);
    require(vec[274] == false);
    require(vec[275] == false);
    require(vec[276] == false);
    require(vec[277] == true);
    require(vec[278] == false);
    require(vec[279] == true);
    require(vec[280] == true);
    require(vec[281] == true);
    require(vec[282] == true);
    require(vec[283] == true);
    require(vec[284] == false);
    require(vec[285] == false);
    require(vec[286] == false);
    require(vec[287] == false);
    require(vec[288] == false);
    require(vec[289] == false);
    require(vec[290] == false);
    require(vec[291] == false);
    require(vec[292] == false);
    require(vec[293] == true);
    require(vec[294] == true);
    require(vec[295] == true);
    require(vec[296] == true);
    require(vec[297] == true);
    require(vec[298] == true);
    require(vec[299] == false);
    require(vec[300] == true);
    require(vec[301] == false);
    require(vec[302] == true);
    require(vec[303] == true);
    require(vec[304] == true);
    require(vec[305] == false);
    require(vec[306] == false);
    require(vec[307] == true);
    require(vec[308] == true);
    require(vec[309] == true);
    require(vec[310] == false);
    require(vec[311] == true);
    require(vec[312] == true);
    require(vec[313] == true);
    require(vec[314] == false);
    require(vec[315] == true);
    require(vec[316] == true);
    require(vec[317] == true);
    require(vec[318] == false);
    require(vec[319] == true);
    require(vec[320] == true);
    require(vec[321] == false);
    require(vec[322] == false);
    require(vec[323] == true);
    require(vec[324] == false);
    require(vec[325] == false);
    require(vec[326] == false);
    require(vec[327] == false);
    require(vec[328] == true);
    require(vec[329] == false);
    require(vec[330] == true);
    require(vec[331] == true);
    require(vec[332] == true);
    require(vec[333] == true);
    require(vec[334] == false);
    require(vec[335] == false);
    require(vec[336] == true);
    require(vec[337] == false);
    require(vec[338] == true);
    require(vec[339] == false);
    require(vec[340] == false);
    require(vec[341] == false);
    require(vec[342] == true);
    require(vec[343] == false);
    require(vec[344] == true);
    require(vec[345] == false);
    require(vec[346] == false);
    require(vec[347] == true);
    require(vec[348] == true);
    require(vec[349] == true);
    require(vec[350] == true);
    require(vec[351] == false);
    require(vec[352] == false);
    require(vec[353] == false);
    require(vec[354] == true);
    require(vec[355] == true);
    require(vec[356] == false);
    require(vec[357] == true);
    require(vec[358] == false);
    require(vec[359] == false);
    require(vec[360] == true);
    require(vec[361] == false);
    require(vec[362] == true);
    require(vec[363] == false);
    require(vec[364] == true);
    require(vec[365] == true);
    require(vec[366] == false);
    require(vec[367] == false);
    require(vec[368] == true);
    require(vec[369] == true);
    require(vec[370] == true);
    require(vec[371] == true);
    require(vec[372] == false);
    require(vec[373] == false);
    require(vec[374] == true);
    require(vec[375] == false);
    require(vec[376] == true);
    require(vec[377] == true);
    require(vec[378] == false);
    require(vec[379] == true);
    require(vec[380] == true);
    require(vec[381] == false);
    require(vec[382] == true);
    require(vec[383] == true);
    require(vec[384] == true);
    require(vec[385] == false);
    require(vec[386] == true);
    require(vec[387] == true);
    require(vec[388] == true);
    require(vec[389] == false);
    require(vec[390] == false);
    require(vec[391] == true);
    require(vec[392] == false);
    require(vec[393] == true);
    require(vec[394] == true);
    require(vec[395] == true);
    require(vec[396] == false);
    require(vec[397] == false);
    require(vec[398] == false);
    require(vec[399] == false);
    require(vec[400] == false);
    require(vec[401] == true);
    require(vec[402] == false);
    require(vec[403] == false);
    require(vec[404] == false);
    require(vec[405] == false);
    require(vec[406] == true);
    require(vec[407] == false);
    require(vec[408] == false);
    require(vec[409] == true);
    require(vec[410] == true);
    require(vec[411] == false);
    require(vec[412] == false);
    require(vec[413] == false);
    require(vec[414] == false);
    require(vec[415] == true);
    require(vec[416] == true);
    require(vec[417] == true);
    require(vec[418] == true);
    require(vec[419] == true);
    require(vec[420] == false);
    require(vec[421] == false);
    require(vec[422] == false);
    require(vec[423] == true);
    require(vec[424] == false);
    require(vec[425] == false);
    require(vec[426] == false);
    require(vec[427] == false);
    require(vec[428] == true);
    require(vec[429] == false);
    require(vec[430] == true);
    require(vec[431] == false);
    require(vec[432] == true);
    require(vec[433] == true);
    require(vec[434] == true);
    require(vec[435] == true);
    require(vec[436] == false);
    require(vec[437] == false);
    require(vec[438] == false);
    require(vec[439] == false);
    require(vec[440] == false);
    require(vec[441] == true);
    require(vec[442] == true);
    require(vec[443] == true);
    require(vec[444] == true);
    require(vec[445] == true);
    require(vec[446] == true);
    require(vec[447] == true);
    require(vec[448] == true);
    require(vec[449] == true);
    require(vec[450] == false);
    require(vec[451] == false);
    require(vec[452] == true);
    require(vec[453] == false);
    require(vec[454] == true);
    require(vec[455] == false);
    require(vec[456] == false);
    require(vec[457] == true);
    require(vec[458] == false);
    require(vec[459] == false);
    require(vec[460] == true);
    require(vec[461] == true);
    require(vec[462] == true);
    require(vec[463] == true);
    require(vec[464] == true);
    require(vec[465] == true);
    require(vec[466] == false);
    require(vec[467] == true);
    require(vec[468] == false);
    require(vec[469] == false);
    require(vec[470] == false);
    require(vec[471] == true);
    require(vec[472] == true);
    require(vec[473] == false);
    require(vec[474] == true);
    require(vec[475] == true);
    require(vec[476] == false);
    require(vec[477] == false);
    require(vec[478] == true);
    require(vec[479] == true);
    require(vec[480] == false);
    require(vec[481] == false);
    require(vec[482] == true);
    require(vec[483] == true);
    require(vec[484] == false);
    require(vec[485] == true);
    require(vec[486] == false);
    require(vec[487] == true);
    require(vec[488] == true);
    require(vec[489] == true);
    require(vec[490] == true);
    require(vec[491] == true);
    require(vec[492] == true);
    require(vec[493] == true);
    require(vec[494] == true);
    require(vec[495] == true);
    require(vec[496] == false);
    require(vec[497] == true);
    require(vec[498] == true);
    require(vec[499] == true);
    require(vec[500] == false);
    require(vec[501] == false);
    require(vec[502] == true);
    require(vec[503] == false);
    require(vec[504] == false);
    require(vec[505] == false);
    require(vec[506] == true);
    require(vec[507] == true);
    require(vec[508] == false);
    require(vec[509] == true);
    require(vec[510] == false);
    require(vec[511] == true);
}

#endif

Vector2Bool c_ret_vector_2_bool(void) {
    return (Vector2Bool){
        true,
        false,
    };
}

Vector4Bool c_ret_vector_4_bool(void) {
    return (Vector4Bool){
        true,
        false,
        true,
        false,
    };
}

Vector8Bool c_ret_vector_8_bool(void) {
    return (Vector8Bool){
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
    };
}

Vector16Bool c_ret_vector_16_bool(void) {
    return (Vector16Bool){
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
    };
}

Vector32Bool c_ret_vector_32_bool(void) {
    return (Vector32Bool){
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
    };
}

Vector64Bool c_ret_vector_64_bool(void) {
    return (Vector64Bool){
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
    };
}

Vector128Bool c_ret_vector_128_bool(void) {
    return (Vector128Bool){
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        true,
    };
}

Vector256Bool c_ret_vector_256_bool(void) {
    return (Vector256Bool){
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
    };
}

Vector512Bool c_ret_vector_512_bool(void) {
    return (Vector512Bool){
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        true,
        true,
        false,
        true,
        false,
    };
}

void bb_vector_2_bool(Vector2Bool vec);
void bb_vector_4_bool(Vector4Bool vec);
void bb_vector_8_bool(Vector8Bool vec);
void bb_vector_16_bool(Vector16Bool vec);
void bb_vector_32_bool(Vector32Bool vec);
void bb_vector_64_bool(Vector64Bool vec);
void bb_vector_128_bool(Vector128Bool vec);
void bb_vector_256_bool(Vector256Bool vec);
void bb_vector_512_bool(Vector512Bool vec);

Vector2Bool bb_ret_vector_2_bool(void);
Vector4Bool bb_ret_vector_4_bool(void);
Vector8Bool bb_ret_vector_8_bool(void);
Vector16Bool bb_ret_vector_16_bool(void);
Vector32Bool bb_ret_vector_32_bool(void);
Vector64Bool bb_ret_vector_64_bool(void);
Vector128Bool bb_ret_vector_128_bool(void);
Vector256Bool bb_ret_vector_256_bool(void);
Vector512Bool bb_ret_vector_512_bool(void);

#endif

typedef struct Vector3 {
    float x;
    float y;
    float z;
} Vector3;

typedef struct Vector5 {
    float x;
    float y;
    float z;
    float w;
    float q;
} Vector5;

typedef struct Rect {
    uint32_t left;
    uint32_t right;
    uint32_t top;
    uint32_t bottom;
} Rect;

void bb_multiple_struct_ints(struct Rect, struct Rect);

typedef struct FloatRect {
    float left;
    float right;
    float top;
    float bottom;
} FloatRect;

void bb_multiple_struct_floats(struct FloatRect, struct FloatRect);

void run_c_tests(void) {
    bb_u8(0xff);
    bb_u16(0xfffe);
    bb_u32(0xfffffffd);
    bb_u64(0xfffffffffffffffc);

// #ifndef ZIG_NO_I128
//     {
//         struct u128 s = {0xfffffffffffffffc};
//         bb_struct_u128(s);
//     }
// #endif

#ifndef ZIG_BUG_14908
    bb_s8(-1);
    bb_s16(-2);
#endif
    bb_s32(-3);
    bb_s64(-4);

// #ifndef ZIG_NO_I128
//     {
//         struct i128 s = {-6};
//         bb_struct_i128(s);
//     }
// #endif

    bb_five_integers(12, 34, 56, 78, 90);

    // bb_f32(12.34f);
    // bb_f64(56.78);
    // bb_longdouble(12.34l);
    // bb_five_floats(1.0f, 2.0f, 3.0f, 4.0f, 5.0f);

    bb_ptr((void *)0xdeadbeefL);

    bb_bool(true);

#ifndef ZIG_NO_COMPLEX
    // TODO: Resolve https://github.com/ziglang/zig/issues/8465
    //{
    //    float complex a = 1.25f + I * 2.6f;
    //    float complex b = 11.3f - I * 1.5f;
    //    float complex z = bb_cmultf(a, b);
    //    require(creal(z) == 1.5f);
    //    require(cimag(z) == 13.5f);
    //}

    // {
    //     double complex a = 1.25 + I * 2.6;
    //     double complex b = 11.3 - I * 1.5;
    //     double complex z = bb_cmultd(a, b);
    //     require(creal(z) == 1.5);
    //     require(cimag(z) == 13.5);
    // }

    // {
    //     float a_r = 1.25f;
    //     float a_i = 2.6f;
    //     float b_r = 11.3f;
    //     float b_i = -1.5f;
    //     float complex z = bb_cmultf_comp(a_r, a_i, b_r, b_i);
    //     require(creal(z) == 1.5f);
    //     require(cimag(z) == 13.5f);
    // }

    // {
    //     double a_r = 1.25;
    //     double a_i = 2.6;
    //     double b_r = 11.3;
    //     double b_i = -1.5;
    //     double complex z = bb_cmultd_comp(a_r, a_i, b_r, b_i);
    //     require(creal(z) == 1.5);
    //     require(cimag(z) == 13.5);
    // }
#endif

#if !defined(__mips__) && !defined(ZIG_PPC32)
    {
        struct Struct_u64_u64 s = bb_ret_struct_u64_u64();
        require(s.a == 1);
        require(s.b == 2);
        bb_struct_u64_u64_0((struct Struct_u64_u64){ .a = 3, .b = 4 });
        bb_struct_u64_u64_1(0, (struct Struct_u64_u64){ .a = 5, .b = 6 });
        bb_struct_u64_u64_2(0, 1, (struct Struct_u64_u64){ .a = 7, .b = 8 });
        bb_struct_u64_u64_3(0, 1, 2, (struct Struct_u64_u64){ .a = 9, .b = 10 });
        bb_struct_u64_u64_4(0, 1, 2, 3, (struct Struct_u64_u64){ .a = 11, .b = 12 });
        bb_struct_u64_u64_5(0, 1, 2, 3, 4, (struct Struct_u64_u64){ .a = 13, .b = 14 });
        bb_struct_u64_u64_6(0, 1, 2, 3, 4, 5, (struct Struct_u64_u64){ .a = 15, .b = 16 });
        bb_struct_u64_u64_7(0, 1, 2, 3, 4, 5, 6, (struct Struct_u64_u64){ .a = 17, .b = 18 });
        bb_struct_u64_u64_8(0, 1, 2, 3, 4, 5, 6, 7, (struct Struct_u64_u64){ .a = 19, .b = 20 });
    }
#endif

#if !defined __mips__ && !defined ZIG_PPC32
    {
        struct BigStruct s = {1, 2, 3, 4, 5};
        bb_big_struct(s);
    }
#endif

#if !defined __i386__ && !defined __arm__ && !defined __aarch64__ && \
    !defined __mips__ && !defined __powerpc__ && !defined ZIG_RISCV64
    {
        struct SmallStructInts s = {1, 2, 3, 4};
        bb_small_struct_ints(s);
    }
#endif

#if !defined __i386__ && !defined __arm__ && !defined __aarch64__ && \
    !defined __mips__ && !defined __powerpc__ && !defined ZIG_RISCV64
    {
        struct MedStructInts s = {1, 2, 3};
        bb_med_struct_ints(s);
    }
#endif

// #ifndef ZIG_NO_I128
//     {
//         __int128 s = 0;
//         s |= 1 << 0;
//         s |= (__int128)2 << 64;
//         bb_big_packed_struct(s);
//     }
// #endif

    {
        uint8_t s = 0;
        s |= 0 << 0;
        s |= 1 << 2;
        s |= 2 << 4;
        s |= 3 << 6;
        bb_small_packed_struct(s);
    }

#if !defined __i386__ && !defined __arm__ && !defined __mips__ && \
    !defined ZIG_PPC32 && !defined _ARCH_PPC64
    {
        struct SplitStructInts s = {1234, 100, 1337};
        bb_split_struct_ints(s);
    }
#endif

// #if !defined __arm__ && !defined ZIG_PPC32 && !defined _ARCH_PPC64
//     {
//         struct MedStructMixed s = {1234, 100.0f, 1337.0f};
//         bb_med_struct_mixed(s);
//     }
// #endif
//
// #if !defined __i386__ && !defined __arm__ && !defined __mips__ && \
//     !defined ZIG_PPC32 && !defined _ARCH_PPC64
//     {
//         struct SplitStructMixed s = {1234, 100, 1337.0f};
//         bb_split_struct_mixed(s);
//     }
// #endif

#if !defined __mips__ && !defined ZIG_PPC32
    {
        struct BigStruct s = {30, 31, 32, 33, 34};
        struct BigStruct res = bb_big_struct_both(s);
        require(res.a == 20);
        require(res.b == 21);
        require(res.c == 22);
        require(res.d == 23);
        require(res.e == 24);
    }
#endif

#if !defined ZIG_PPC32 && !defined _ARCH_PPC64
    {
        struct Rect r1 = {1, 21, 16, 4};
        struct Rect r2 = {178, 189, 21, 15};
        bb_multiple_struct_ints(r1, r2);
    }
#endif

// #if !defined __mips__ && !defined ZIG_PPC32
//     {
//         struct FloatRect r1 = {1, 21, 16, 4};
//         struct FloatRect r2 = {178, 189, 21, 15};
//         bb_multiple_struct_floats(r1, r2);
//     }
// #endif

    {
        require(bb_ret_bool() == 1);

        
        require(bb_ret_u8() == 0xff);
        require(bb_ret_u16() == 0xffff);
        require(bb_ret_u32() == 0xffffffff);
        require(bb_ret_u64() == 0xffffffffffffffff);

        require(bb_ret_s8() == -1);
        require(bb_ret_s16() == -1);
        require(bb_ret_s32() == -1);
        require(bb_ret_s64() == -1);
    }

#if defined(ZIG_BACKEND_STAGE2_X86_64) || defined(ZIG_PPC32)
    {
        bb_vector_2_bool((Vector2Bool){
            false,
            true,
        });

        Vector2Bool vec = bb_ret_vector_2_bool();
        require(vec[0] == false);
        require(vec[1] == false);
    }
    {
        bb_vector_4_bool((Vector4Bool){
            false,
            false,
            false,
            false,
        });

        Vector4Bool vec = bb_ret_vector_4_bool();
        require(vec[0] == false);
        require(vec[1] == true);
        require(vec[2] == true);
        require(vec[3] == true);
    }
    {
        bb_vector_8_bool((Vector8Bool){
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
        });

        Vector8Bool vec = bb_ret_vector_8_bool();
        require(vec[0] == false);
        require(vec[1] == false);
        require(vec[2] == false);
        require(vec[3] == false);
        require(vec[4] == true);
        require(vec[5] == false);
        require(vec[6] == false);
        require(vec[7] == false);
    }
    {
        bb_vector_16_bool((Vector16Bool){
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
        });

        Vector16Bool vec = bb_ret_vector_16_bool();
        require(vec[0] == false);
        require(vec[1] == true);
        require(vec[2] == false);
        require(vec[3] == false);
        require(vec[4] == false);
        require(vec[5] == true);
        require(vec[6] == false);
        require(vec[7] == false);
        require(vec[8] == true);
        require(vec[9] == false);
        require(vec[10] == false);
        require(vec[11] == false);
        require(vec[12] == false);
        require(vec[13] == true);
        require(vec[14] == false);
        require(vec[15] == false);
    }
    {
        bb_vector_32_bool((Vector32Bool){
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
        });

        Vector32Bool vec = bb_ret_vector_32_bool();
        require(vec[0] == false);
        require(vec[1] == true);
        require(vec[2] == false);
        require(vec[3] == false);
        require(vec[4] == true);
        require(vec[5] == false);
        require(vec[6] == true);
        require(vec[7] == true);
        require(vec[8] == true);
        require(vec[9] == true);
        require(vec[10] == true);
        require(vec[11] == true);
        require(vec[12] == false);
        require(vec[13] == false);
        require(vec[14] == false);
        require(vec[15] == false);
        require(vec[16] == false);
        require(vec[17] == false);
        require(vec[18] == true);
        require(vec[19] == true);
        require(vec[20] == true);
        require(vec[21] == false);
        require(vec[22] == true);
        require(vec[23] == false);
        require(vec[24] == true);
        require(vec[25] == false);
        require(vec[26] == false);
        require(vec[27] == true);
        require(vec[28] == false);
        require(vec[29] == false);
        require(vec[30] == true);
        require(vec[31] == true);
    }
    {
        bb_vector_64_bool((Vector64Bool){
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
        });

        Vector64Bool vec = bb_ret_vector_64_bool();
        require(vec[0] == true);
        require(vec[1] == false);
        require(vec[2] == true);
        require(vec[3] == false);
        require(vec[4] == false);
        require(vec[5] == true);
        require(vec[6] == false);
        require(vec[7] == true);
        require(vec[8] == true);
        require(vec[9] == false);
        require(vec[10] == true);
        require(vec[11] == false);
        require(vec[12] == true);
        require(vec[13] == false);
        require(vec[14] == false);
        require(vec[15] == true);
        require(vec[16] == false);
        require(vec[17] == false);
        require(vec[18] == true);
        require(vec[19] == true);
        require(vec[20] == false);
        require(vec[21] == false);
        require(vec[22] == true);
        require(vec[23] == false);
        require(vec[24] == false);
        require(vec[25] == true);
        require(vec[26] == true);
        require(vec[27] == true);
        require(vec[28] == true);
        require(vec[29] == true);
        require(vec[30] == false);
        require(vec[31] == false);
        require(vec[32] == true);
        require(vec[33] == true);
        require(vec[34] == true);
        require(vec[35] == true);
        require(vec[36] == false);
        require(vec[37] == true);
        require(vec[38] == false);
        require(vec[39] == true);
        require(vec[40] == true);
        require(vec[41] == true);
        require(vec[42] == true);
        require(vec[43] == true);
        require(vec[44] == false);
        require(vec[45] == false);
        require(vec[46] == false);
        require(vec[47] == true);
        require(vec[48] == true);
        require(vec[49] == true);
        require(vec[50] == false);
        require(vec[51] == true);
        require(vec[52] == true);
        require(vec[53] == true);
        require(vec[54] == false);
        require(vec[55] == false);
        require(vec[56] == false);
        require(vec[57] == true);
        require(vec[58] == false);
        require(vec[59] == false);
        require(vec[60] == true);
        require(vec[61] == false);
        require(vec[62] == true);
        require(vec[63] == false);
    }
    {
        bb_vector_128_bool((Vector128Bool){
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
        });

        Vector128Bool vec = bb_ret_vector_128_bool();
        require(vec[0] == true);
        require(vec[1] == true);
        require(vec[2] == false);
        require(vec[3] == false);
        require(vec[4] == false);
        require(vec[5] == true);
        require(vec[6] == true);
        require(vec[7] == false);
        require(vec[8] == false);
        require(vec[9] == true);
        require(vec[10] == false);
        require(vec[11] == false);
        require(vec[12] == false);
        require(vec[13] == true);
        require(vec[14] == false);
        require(vec[15] == true);
        require(vec[16] == true);
        require(vec[17] == false);
        require(vec[18] == false);
        require(vec[19] == true);
        require(vec[20] == true);
        require(vec[21] == true);
        require(vec[22] == true);
        require(vec[23] == true);
        require(vec[24] == false);
        require(vec[25] == false);
        require(vec[26] == true);
        require(vec[27] == true);
        require(vec[28] == true);
        require(vec[29] == false);
        require(vec[30] == false);
        require(vec[31] == true);
        require(vec[32] == true);
        require(vec[33] == false);
        require(vec[34] == true);
        require(vec[35] == true);
        require(vec[36] == true);
        require(vec[37] == false);
        require(vec[38] == true);
        require(vec[39] == true);
        require(vec[40] == true);
        require(vec[41] == false);
        require(vec[42] == true);
        require(vec[43] == true);
        require(vec[44] == false);
        require(vec[45] == false);
        require(vec[46] == false);
        require(vec[47] == true);
        require(vec[48] == false);
        require(vec[49] == false);
        require(vec[50] == false);
        require(vec[51] == false);
        require(vec[52] == true);
        require(vec[53] == false);
        require(vec[54] == true);
        require(vec[55] == false);
        require(vec[56] == true);
        require(vec[57] == false);
        require(vec[58] == false);
        require(vec[59] == true);
        require(vec[60] == true);
        require(vec[61] == true);
        require(vec[62] == true);
        require(vec[63] == true);
        require(vec[64] == false);
        require(vec[65] == false);
        require(vec[66] == false);
        require(vec[67] == true);
        require(vec[68] == true);
        require(vec[69] == false);
        require(vec[70] == true);
        require(vec[71] == true);
        require(vec[72] == false);
        require(vec[73] == true);
        require(vec[74] == true);
        require(vec[75] == false);
        require(vec[76] == false);
        require(vec[77] == true);
        require(vec[78] == false);
        require(vec[79] == true);
        require(vec[80] == false);
        require(vec[81] == false);
        require(vec[82] == true);
        require(vec[83] == true);
        require(vec[84] == false);
        require(vec[85] == true);
        require(vec[86] == false);
        require(vec[87] == false);
        require(vec[88] == true);
        require(vec[89] == true);
        require(vec[90] == true);
        require(vec[91] == true);
        require(vec[92] == true);
        require(vec[93] == false);
        require(vec[94] == false);
        require(vec[95] == true);
        require(vec[96] == false);
        require(vec[97] == false);
        require(vec[98] == true);
        require(vec[99] == true);
        require(vec[100] == true);
        require(vec[101] == true);
        require(vec[102] == true);
        require(vec[103] == true);
        require(vec[104] == true);
        require(vec[105] == false);
        require(vec[106] == false);
        require(vec[107] == true);
        require(vec[108] == false);
        require(vec[109] == false);
        require(vec[110] == true);
        require(vec[111] == false);
        require(vec[112] == false);
        require(vec[113] == true);
        require(vec[114] == false);
        require(vec[115] == false);
        require(vec[116] == false);
        require(vec[117] == false);
        require(vec[118] == false);
        require(vec[119] == false);
        require(vec[120] == true);
        require(vec[121] == true);
        require(vec[122] == true);
        require(vec[123] == false);
        require(vec[124] == true);
        require(vec[125] == false);
        require(vec[126] == false);
        require(vec[127] == true);
    }
    {
        bb_vector_256_bool((Vector256Bool){
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
        });

        Vector256Bool vec = bb_ret_vector_256_bool();
        require(vec[0] == true);
        require(vec[1] == true);
        require(vec[2] == true);
        require(vec[3] == false);
        require(vec[4] == true);
        require(vec[5] == false);
        require(vec[6] == false);
        require(vec[7] == true);
        require(vec[8] == false);
        require(vec[9] == false);
        require(vec[10] == false);
        require(vec[11] == false);
        require(vec[12] == false);
        require(vec[13] == false);
        require(vec[14] == false);
        require(vec[15] == false);
        require(vec[16] == true);
        require(vec[17] == false);
        require(vec[18] == true);
        require(vec[19] == false);
        require(vec[20] == false);
        require(vec[21] == true);
        require(vec[22] == true);
        require(vec[23] == false);
        require(vec[24] == false);
        require(vec[25] == true);
        require(vec[26] == true);
        require(vec[27] == false);
        require(vec[28] == true);
        require(vec[29] == true);
        require(vec[30] == true);
        require(vec[31] == false);
        require(vec[32] == true);
        require(vec[33] == false);
        require(vec[34] == true);
        require(vec[35] == false);
        require(vec[36] == true);
        require(vec[37] == false);
        require(vec[38] == true);
        require(vec[39] == false);
        require(vec[40] == false);
        require(vec[41] == false);
        require(vec[42] == true);
        require(vec[43] == true);
        require(vec[44] == true);
        require(vec[45] == false);
        require(vec[46] == false);
        require(vec[47] == false);
        require(vec[48] == true);
        require(vec[49] == false);
        require(vec[50] == true);
        require(vec[51] == false);
        require(vec[52] == true);
        require(vec[53] == false);
        require(vec[54] == true);
        require(vec[55] == true);
        require(vec[56] == false);
        require(vec[57] == false);
        require(vec[58] == false);
        require(vec[59] == true);
        require(vec[60] == true);
        require(vec[61] == true);
        require(vec[62] == false);
        require(vec[63] == true);
        require(vec[64] == false);
        require(vec[65] == true);
        require(vec[66] == false);
        require(vec[67] == true);
        require(vec[68] == true);
        require(vec[69] == false);
        require(vec[70] == true);
        require(vec[71] == false);
        require(vec[72] == true);
        require(vec[73] == true);
        require(vec[74] == false);
        require(vec[75] == false);
        require(vec[76] == false);
        require(vec[77] == false);
        require(vec[78] == false);
        require(vec[79] == false);
        require(vec[80] == false);
        require(vec[81] == false);
        require(vec[82] == false);
        require(vec[83] == true);
        require(vec[84] == false);
        require(vec[85] == false);
        require(vec[86] == false);
        require(vec[87] == true);
        require(vec[88] == false);
        require(vec[89] == true);
        require(vec[90] == true);
        require(vec[91] == false);
        require(vec[92] == false);
        require(vec[93] == true);
        require(vec[94] == true);
        require(vec[95] == false);
        require(vec[96] == false);
        require(vec[97] == true);
        require(vec[98] == false);
        require(vec[99] == false);
        require(vec[100] == false);
        require(vec[101] == false);
        require(vec[102] == false);
        require(vec[103] == false);
        require(vec[104] == false);
        require(vec[105] == true);
        require(vec[106] == true);
        require(vec[107] == false);
        require(vec[108] == true);
        require(vec[109] == false);
        require(vec[110] == true);
        require(vec[111] == true);
        require(vec[112] == false);
        require(vec[113] == false);
        require(vec[114] == false);
        require(vec[115] == false);
        require(vec[116] == false);
        require(vec[117] == false);
        require(vec[118] == false);
        require(vec[119] == true);
        require(vec[120] == true);
        require(vec[121] == true);
        require(vec[122] == false);
        require(vec[123] == true);
        require(vec[124] == true);
        require(vec[125] == false);
        require(vec[126] == false);
        require(vec[127] == true);
        require(vec[128] == true);
        require(vec[129] == true);
        require(vec[130] == true);
        require(vec[131] == true);
        require(vec[132] == false);
        require(vec[133] == true);
        require(vec[134] == true);
        require(vec[135] == false);
        require(vec[136] == false);
        require(vec[137] == true);
        require(vec[138] == true);
        require(vec[139] == false);
        require(vec[140] == true);
        require(vec[141] == false);
        require(vec[142] == true);
        require(vec[143] == false);
        require(vec[144] == true);
        require(vec[145] == true);
        require(vec[146] == true);
        require(vec[147] == true);
        require(vec[148] == false);
        require(vec[149] == false);
        require(vec[150] == false);
        require(vec[151] == true);
        require(vec[152] == false);
        require(vec[153] == true);
        require(vec[154] == false);
        require(vec[155] == true);
        require(vec[156] == true);
        require(vec[157] == false);
        require(vec[158] == true);
        require(vec[159] == true);
        require(vec[160] == true);
        require(vec[161] == true);
        require(vec[162] == true);
        require(vec[163] == false);
        require(vec[164] == false);
        require(vec[165] == true);
        require(vec[166] == false);
        require(vec[167] == true);
        require(vec[168] == true);
        require(vec[169] == true);
        require(vec[170] == true);
        require(vec[171] == false);
        require(vec[172] == true);
        require(vec[173] == true);
        require(vec[174] == true);
        require(vec[175] == true);
        require(vec[176] == true);
        require(vec[177] == true);
        require(vec[178] == true);
        require(vec[179] == false);
        require(vec[180] == true);
        require(vec[181] == false);
        require(vec[182] == false);
        require(vec[183] == false);
        require(vec[184] == true);
        require(vec[185] == false);
        require(vec[186] == true);
        require(vec[187] == true);
        require(vec[188] == false);
        require(vec[189] == true);
        require(vec[190] == false);
        require(vec[191] == true);
        require(vec[192] == false);
        require(vec[193] == true);
        require(vec[194] == false);
        require(vec[195] == false);
        require(vec[196] == true);
        require(vec[197] == true);
        require(vec[198] == true);
        require(vec[199] == true);
        require(vec[200] == true);
        require(vec[201] == true);
        require(vec[202] == true);
        require(vec[203] == false);
        require(vec[204] == true);
        require(vec[205] == false);
        require(vec[206] == false);
        require(vec[207] == true);
        require(vec[208] == true);
        require(vec[209] == false);
        require(vec[210] == false);
        require(vec[211] == false);
        require(vec[212] == true);
        require(vec[213] == true);
        require(vec[214] == true);
        require(vec[215] == false);
        require(vec[216] == false);
        require(vec[217] == true);
        require(vec[218] == true);
        require(vec[219] == true);
        require(vec[220] == true);
        require(vec[221] == false);
        require(vec[222] == true);
        require(vec[223] == false);
        require(vec[224] == true);
        require(vec[225] == true);
        require(vec[226] == true);
        require(vec[227] == false);
        require(vec[228] == false);
        require(vec[229] == false);
        require(vec[230] == false);
        require(vec[231] == false);
        require(vec[232] == true);
        require(vec[233] == true);
        require(vec[234] == false);
        require(vec[235] == false);
        require(vec[236] == false);
        require(vec[237] == true);
        require(vec[238] == true);
        require(vec[239] == false);
        require(vec[240] == true);
        require(vec[241] == true);
        require(vec[242] == true);
        require(vec[243] == false);
        require(vec[244] == true);
        require(vec[245] == true);
        require(vec[246] == false);
        require(vec[247] == true);
        require(vec[248] == false);
        require(vec[249] == false);
        require(vec[250] == true);
        require(vec[251] == true);
        require(vec[252] == false);
        require(vec[253] == true);
        require(vec[254] == false);
        require(vec[255] == true);
    }
    {
        bb_vector_512_bool((Vector512Bool){
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            true,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            false,
            false,
            true,
        });

        Vector512Bool vec = bb_ret_vector_512_bool();
        require(vec[0] == true);
        require(vec[1] == true);
        require(vec[2] == true);
        require(vec[3] == true);
        require(vec[4] == false);
        require(vec[5] == true);
        require(vec[6] == false);
        require(vec[7] == true);
        require(vec[8] == true);
        require(vec[9] == true);
        require(vec[10] == false);
        require(vec[11] == true);
        require(vec[12] == false);
        require(vec[13] == false);
        require(vec[14] == false);
        require(vec[15] == true);
        require(vec[16] == true);
        require(vec[17] == false);
        require(vec[18] == false);
        require(vec[19] == false);
        require(vec[20] == true);
        require(vec[21] == true);
        require(vec[22] == false);
        require(vec[23] == false);
        require(vec[24] == false);
        require(vec[25] == false);
        require(vec[26] == true);
        require(vec[27] == false);
        require(vec[28] == false);
        require(vec[29] == false);
        require(vec[30] == true);
        require(vec[31] == true);
        require(vec[32] == true);
        require(vec[33] == true);
        require(vec[34] == false);
        require(vec[35] == false);
        require(vec[36] == false);
        require(vec[37] == true);
        require(vec[38] == true);
        require(vec[39] == true);
        require(vec[40] == false);
        require(vec[41] == false);
        require(vec[42] == true);
        require(vec[43] == false);
        require(vec[44] == false);
        require(vec[45] == true);
        require(vec[46] == false);
        require(vec[47] == false);
        require(vec[48] == true);
        require(vec[49] == true);
        require(vec[50] == true);
        require(vec[51] == true);
        require(vec[52] == false);
        require(vec[53] == false);
        require(vec[54] == false);
        require(vec[55] == true);
        require(vec[56] == false);
        require(vec[57] == true);
        require(vec[58] == false);
        require(vec[59] == true);
        require(vec[60] == true);
        require(vec[61] == false);
        require(vec[62] == false);
        require(vec[63] == true);
        require(vec[64] == true);
        require(vec[65] == false);
        require(vec[66] == true);
        require(vec[67] == false);
        require(vec[68] == false);
        require(vec[69] == false);
        require(vec[70] == true);
        require(vec[71] == true);
        require(vec[72] == true);
        require(vec[73] == true);
        require(vec[74] == true);
        require(vec[75] == false);
        require(vec[76] == true);
        require(vec[77] == false);
        require(vec[78] == true);
        require(vec[79] == true);
        require(vec[80] == true);
        require(vec[81] == true);
        require(vec[82] == true);
        require(vec[83] == false);
        require(vec[84] == true);
        require(vec[85] == true);
        require(vec[86] == false);
        require(vec[87] == true);
        require(vec[88] == false);
        require(vec[89] == false);
        require(vec[90] == true);
        require(vec[91] == false);
        require(vec[92] == true);
        require(vec[93] == false);
        require(vec[94] == false);
        require(vec[95] == false);
        require(vec[96] == true);
        require(vec[97] == true);
        require(vec[98] == false);
        require(vec[99] == true);
        require(vec[100] == true);
        require(vec[101] == false);
        require(vec[102] == true);
        require(vec[103] == false);
        require(vec[104] == true);
        require(vec[105] == false);
        require(vec[106] == true);
        require(vec[107] == false);
        require(vec[108] == false);
        require(vec[109] == true);
        require(vec[110] == false);
        require(vec[111] == false);
        require(vec[112] == true);
        require(vec[113] == false);
        require(vec[114] == true);
        require(vec[115] == false);
        require(vec[116] == true);
        require(vec[117] == false);
        require(vec[118] == false);
        require(vec[119] == true);
        require(vec[120] == true);
        require(vec[121] == true);
        require(vec[122] == false);
        require(vec[123] == true);
        require(vec[124] == false);
        require(vec[125] == false);
        require(vec[126] == true);
        require(vec[127] == true);
        require(vec[128] == false);
        require(vec[129] == true);
        require(vec[130] == true);
        require(vec[131] == false);
        require(vec[132] == true);
        require(vec[133] == true);
        require(vec[134] == false);
        require(vec[135] == true);
        require(vec[136] == true);
        require(vec[137] == false);
        require(vec[138] == false);
        require(vec[139] == false);
        require(vec[140] == true);
        require(vec[141] == false);
        require(vec[142] == true);
        require(vec[143] == false);
        require(vec[144] == false);
        require(vec[145] == false);
        require(vec[146] == true);
        require(vec[147] == false);
        require(vec[148] == true);
        require(vec[149] == false);
        require(vec[150] == false);
        require(vec[151] == true);
        require(vec[152] == false);
        require(vec[153] == true);
        require(vec[154] == true);
        require(vec[155] == false);
        require(vec[156] == true);
        require(vec[157] == true);
        require(vec[158] == false);
        require(vec[159] == true);
        require(vec[160] == true);
        require(vec[161] == false);
        require(vec[162] == false);
        require(vec[163] == false);
        require(vec[164] == true);
        require(vec[165] == false);
        require(vec[166] == true);
        require(vec[167] == true);
        require(vec[168] == true);
        require(vec[169] == true);
        require(vec[170] == false);
        require(vec[171] == true);
        require(vec[172] == false);
        require(vec[173] == false);
        require(vec[174] == true);
        require(vec[175] == true);
        require(vec[176] == true);
        require(vec[177] == false);
        require(vec[178] == false);
        require(vec[179] == false);
        require(vec[180] == true);
        require(vec[181] == false);
        require(vec[182] == false);
        require(vec[183] == true);
        require(vec[184] == true);
        require(vec[185] == false);
        require(vec[186] == true);
        require(vec[187] == false);
        require(vec[188] == true);
        require(vec[189] == true);
        require(vec[190] == true);
        require(vec[191] == true);
        require(vec[192] == true);
        require(vec[193] == true);
        require(vec[194] == true);
        require(vec[195] == false);
        require(vec[196] == false);
        require(vec[197] == false);
        require(vec[198] == false);
        require(vec[199] == false);
        require(vec[200] == true);
        require(vec[201] == false);
        require(vec[202] == true);
        require(vec[203] == false);
        require(vec[204] == true);
        require(vec[205] == true);
        require(vec[206] == false);
        require(vec[207] == false);
        require(vec[208] == false);
        require(vec[209] == true);
        require(vec[210] == true);
        require(vec[211] == true);
        require(vec[212] == false);
        require(vec[213] == false);
        require(vec[214] == true);
        require(vec[215] == true);
        require(vec[216] == true);
        require(vec[217] == false);
        require(vec[218] == false);
        require(vec[219] == true);
        require(vec[220] == false);
        require(vec[221] == true);
        require(vec[222] == true);
        require(vec[223] == false);
        require(vec[224] == true);
        require(vec[225] == false);
        require(vec[226] == false);
        require(vec[227] == true);
        require(vec[228] == false);
        require(vec[229] == false);
        require(vec[230] == true);
        require(vec[231] == true);
        require(vec[232] == false);
        require(vec[233] == true);
        require(vec[234] == true);
        require(vec[235] == true);
        require(vec[236] == true);
        require(vec[237] == true);
        require(vec[238] == false);
        require(vec[239] == true);
        require(vec[240] == false);
        require(vec[241] == false);
        require(vec[242] == true);
        require(vec[243] == false);
        require(vec[244] == true);
        require(vec[245] == false);
        require(vec[246] == true);
        require(vec[247] == false);
        require(vec[248] == true);
        require(vec[249] == true);
        require(vec[250] == true);
        require(vec[251] == true);
        require(vec[252] == true);
        require(vec[253] == false);
        require(vec[254] == false);
        require(vec[255] == false);
        require(vec[256] == false);
        require(vec[257] == false);
        require(vec[258] == false);
        require(vec[259] == true);
        require(vec[260] == true);
        require(vec[261] == true);
        require(vec[262] == true);
        require(vec[263] == false);
        require(vec[264] == false);
        require(vec[265] == false);
        require(vec[266] == true);
        require(vec[267] == false);
        require(vec[268] == true);
        require(vec[269] == false);
        require(vec[270] == true);
        require(vec[271] == true);
        require(vec[272] == true);
        require(vec[273] == true);
        require(vec[274] == true);
        require(vec[275] == true);
        require(vec[276] == false);
        require(vec[277] == false);
        require(vec[278] == true);
        require(vec[279] == true);
        require(vec[280] == false);
        require(vec[281] == false);
        require(vec[282] == false);
        require(vec[283] == false);
        require(vec[284] == true);
        require(vec[285] == true);
        require(vec[286] == true);
        require(vec[287] == false);
        require(vec[288] == false);
        require(vec[289] == false);
        require(vec[290] == true);
        require(vec[291] == false);
        require(vec[292] == true);
        require(vec[293] == true);
        require(vec[294] == false);
        require(vec[295] == true);
        require(vec[296] == true);
        require(vec[297] == true);
        require(vec[298] == false);
        require(vec[299] == true);
        require(vec[300] == true);
        require(vec[301] == false);
        require(vec[302] == false);
        require(vec[303] == true);
        require(vec[304] == false);
        require(vec[305] == false);
        require(vec[306] == true);
        require(vec[307] == true);
        require(vec[308] == true);
        require(vec[309] == true);
        require(vec[310] == false);
        require(vec[311] == false);
        require(vec[312] == false);
        require(vec[313] == false);
        require(vec[314] == false);
        require(vec[315] == true);
        require(vec[316] == false);
        require(vec[317] == false);
        require(vec[318] == true);
        require(vec[319] == false);
        require(vec[320] == false);
        require(vec[321] == true);
        require(vec[322] == true);
        require(vec[323] == true);
        require(vec[324] == true);
        require(vec[325] == false);
        require(vec[326] == false);
        require(vec[327] == false);
        require(vec[328] == true);
        require(vec[329] == true);
        require(vec[330] == false);
        require(vec[331] == true);
        require(vec[332] == true);
        require(vec[333] == false);
        require(vec[334] == false);
        require(vec[335] == true);
        require(vec[336] == true);
        require(vec[337] == false);
        require(vec[338] == true);
        require(vec[339] == true);
        require(vec[340] == true);
        require(vec[341] == false);
        require(vec[342] == false);
        require(vec[343] == false);
        require(vec[344] == true);
        require(vec[345] == true);
        require(vec[346] == false);
        require(vec[347] == true);
        require(vec[348] == false);
        require(vec[349] == true);
        require(vec[350] == false);
        require(vec[351] == false);
        require(vec[352] == true);
        require(vec[353] == false);
        require(vec[354] == true);
        require(vec[355] == false);
        require(vec[356] == false);
        require(vec[357] == false);
        require(vec[358] == false);
        require(vec[359] == false);
        require(vec[360] == true);
        require(vec[361] == true);
        require(vec[362] == false);
        require(vec[363] == false);
        require(vec[364] == false);
        require(vec[365] == false);
        require(vec[366] == true);
        require(vec[367] == false);
        require(vec[368] == true);
        require(vec[369] == false);
        require(vec[370] == true);
        require(vec[371] == true);
        require(vec[372] == false);
        require(vec[373] == true);
        require(vec[374] == true);
        require(vec[375] == true);
        require(vec[376] == true);
        require(vec[377] == true);
        require(vec[378] == false);
        require(vec[379] == true);
        require(vec[380] == false);
        require(vec[381] == true);
        require(vec[382] == true);
        require(vec[383] == true);
        require(vec[384] == true);
        require(vec[385] == true);
        require(vec[386] == false);
        require(vec[387] == true);
        require(vec[388] == true);
        require(vec[389] == false);
        require(vec[390] == true);
        require(vec[391] == false);
        require(vec[392] == true);
        require(vec[393] == false);
        require(vec[394] == true);
        require(vec[395] == false);
        require(vec[396] == true);
        require(vec[397] == false);
        require(vec[398] == false);
        require(vec[399] == true);
        require(vec[400] == true);
        require(vec[401] == true);
        require(vec[402] == true);
        require(vec[403] == false);
        require(vec[404] == false);
        require(vec[405] == true);
        require(vec[406] == false);
        require(vec[407] == false);
        require(vec[408] == false);
        require(vec[409] == true);
        require(vec[410] == false);
        require(vec[411] == true);
        require(vec[412] == true);
        require(vec[413] == false);
        require(vec[414] == true);
        require(vec[415] == true);
        require(vec[416] == false);
        require(vec[417] == true);
        require(vec[418] == true);
        require(vec[419] == false);
        require(vec[420] == false);
        require(vec[421] == true);
        require(vec[422] == false);
        require(vec[423] == false);
        require(vec[424] == true);
        require(vec[425] == false);
        require(vec[426] == true);
        require(vec[427] == false);
        require(vec[428] == false);
        require(vec[429] == true);
        require(vec[430] == false);
        require(vec[431] == true);
        require(vec[432] == true);
        require(vec[433] == false);
        require(vec[434] == true);
        require(vec[435] == false);
        require(vec[436] == true);
        require(vec[437] == false);
        require(vec[438] == true);
        require(vec[439] == false);
        require(vec[440] == false);
        require(vec[441] == true);
        require(vec[442] == true);
        require(vec[443] == false);
        require(vec[444] == true);
        require(vec[445] == true);
        require(vec[446] == false);
        require(vec[447] == true);
        require(vec[448] == true);
        require(vec[449] == false);
        require(vec[450] == false);
        require(vec[451] == false);
        require(vec[452] == false);
        require(vec[453] == false);
        require(vec[454] == true);
        require(vec[455] == false);
        require(vec[456] == false);
        require(vec[457] == true);
        require(vec[458] == false);
        require(vec[459] == true);
        require(vec[460] == false);
        require(vec[461] == false);
        require(vec[462] == false);
        require(vec[463] == true);
        require(vec[464] == false);
        require(vec[465] == true);
        require(vec[466] == false);
        require(vec[467] == false);
        require(vec[468] == false);
        require(vec[469] == false);
        require(vec[470] == true);
        require(vec[471] == true);
        require(vec[472] == false);
        require(vec[473] == true);
        require(vec[474] == true);
        require(vec[475] == false);
        require(vec[476] == false);
        require(vec[477] == true);
        require(vec[478] == true);
        require(vec[479] == true);
        require(vec[480] == false);
        require(vec[481] == false);
        require(vec[482] == true);
        require(vec[483] == false);
        require(vec[484] == false);
        require(vec[485] == false);
        require(vec[486] == true);
        require(vec[487] == true);
        require(vec[488] == false);
        require(vec[489] == false);
        require(vec[490] == false);
        require(vec[491] == false);
        require(vec[492] == false);
        require(vec[493] == true);
        require(vec[494] == true);
        require(vec[495] == true);
        require(vec[496] == true);
        require(vec[497] == false);
        require(vec[498] == false);
        require(vec[499] == false);
        require(vec[500] == true);
        require(vec[501] == false);
        require(vec[502] == true);
        require(vec[503] == true);
        require(vec[504] == true);
        require(vec[505] == true);
        require(vec[506] == false);
        require(vec[507] == false);
        require(vec[508] == true);
        require(vec[509] == true);
        require(vec[510] == false);
        require(vec[511] == false);
    }
#endif
}

void c_u8(uint8_t x) {
    require(x == 0xff);
}

void c_u16(uint16_t x) {
    require(x == 0xfffe);
}

void c_u32(uint32_t x) {
    require(x == 0xfffffffd);
}

void c_u64(uint64_t x) {
    require(x == 0xfffffffffffffffcULL);
}

// #ifndef ZIG_NO_I128
// void c_struct_u128(struct u128 x) {
//     require(x.value == 0xfffffffffffffffcULL);
// }
// #endif

void c_s8(int8_t x) {
    require(x == -1);
}

void c_s16(int16_t x) {
    require(x == -2);
}

void c_s32(int32_t x) {
    require(x == -3);
}

void c_s64(int64_t x) {
    require(x == -4);
}

// #ifndef ZIG_NO_I128
// void c_struct_i128(struct i128 x) {
//     require(x.value == -6);
// }
// #endif

// void c_f32(float x) {
//     require(x == 12.34f);
// }

// void c_f64(double x) {
//     require(x == 56.78);
// }
//
// void c_long_double(long double x) {
//     require(x == 12.34l);
// }

void c_ptr(void *x) {
    require(x == (void *)0xdeadbeefL);
}

void c_bool(bool x) {
    require(x);
}

void c_five_integers(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e) {
    require(a == 12);
    require(b == 34);
    require(c == 56);
    require(d == 78);
    require(e == 90);
}

// void c_five_floats(float a, float b, float c, float d, float e) {
//     require(a == 1.0);
//     require(b == 2.0);
//     require(c == 3.0);
//     require(d == 4.0);
//     require(e == 5.0);
// }
//
// float complex c_cmultf_comp(float a_r, float a_i, float b_r, float b_i) {
//     require(a_r == 1.25f);
//     require(a_i == 2.6f);
//     require(b_r == 11.3f);
//     require(b_i == -1.5f);
//
//     return 1.5f + I * 13.5f;
// }
//
// double complex c_cmultd_comp(double a_r, double a_i, double b_r, double b_i) {
//     require(a_r == 1.25);
//     require(a_i == 2.6);
//     require(b_r == 11.3);
//     require(b_i == -1.5);
//
//     return 1.5 + I * 13.5;
// }
//
// float complex c_cmultf(float complex a, float complex b) {
//     require(creal(a) == 1.25f);
//     require(cimag(a) == 2.6f);
//     require(creal(b) == 11.3f);
//     require(cimag(b) == -1.5f);
//
//     return 1.5f + I * 13.5f;
// }
//
// double complex c_cmultd(double complex a, double complex b) {
//     require(creal(a) == 1.25);
//     require(cimag(a) == 2.6);
//     require(creal(b) == 11.3);
//     require(cimag(b) == -1.5);
//
//     return 1.5 + I * 13.5;
// }

void c_big_struct(struct BigStruct x) {
    require(x.a == 1);
    require(x.b == 2);
    require(x.c == 3);
    require(x.d == 4);
    require(x.e == 5);
}

void c_big_union(union BigUnion x) {
    require(x.a.a == 1);
    require(x.a.b == 2);
    require(x.a.c == 3);
    require(x.a.d == 4);
}

void c_small_struct_ints(struct SmallStructInts x) {
    require(x.a == 1);
    require(x.b == 2);
    require(x.c == 3);
    require(x.d == 4);

    struct SmallStructInts y = bb_ret_small_struct_ints();

    require(y.a == 1);
    require(y.b == 2);
    require(y.c == 3);
    require(y.d == 4);
}

struct SmallStructInts c_ret_small_struct_ints() {
    struct SmallStructInts s = {
        .a = 1,
        .b = 2,
        .c = 3,
        .d = 4,
    };
    return s;
}

void c_med_struct_ints(struct MedStructInts s) {
    require(s.x == 1);
    require(s.y == 2);
    require(s.z == 3);

    struct MedStructInts s2 = bb_ret_med_struct_ints();

    require(s2.x == 1);
    require(s2.y == 2);
    require(s2.z == 3);
}

struct MedStructInts c_ret_med_struct_ints() {
    struct MedStructInts s = {
        .x = 1,
        .y = 2,
        .z = 3,
    };
    return s;
}

// void c_med_struct_mixed(struct MedStructMixed x) {
//     require(x.a == 1234);
//     require(x.b == 100.0f);
//     require(x.c == 1337.0f);
//
//     struct MedStructMixed y = bb_ret_med_struct_mixed();
//
//     require(y.a == 1234);
//     require(y.b == 100.0f);
//     require(y.c == 1337.0f);
// }

struct MedStructMixed c_ret_med_struct_mixed() {
    struct MedStructMixed s = {
        .a = 1234,
        .b = 100.0,
        .c = 1337.0,
    };
    return s;
}

void c_split_struct_ints(struct SplitStructInts x) {
    require(x.a == 1234);
    require(x.b == 100);
    require(x.c == 1337);
}

// void c_split_struct_mixed(struct SplitStructMixed x) {
//     require(x.a == 1234);
//     require(x.b == 100);
//     require(x.c == 1337.0f);
//     struct SplitStructMixed y = bb_ret_split_struct_mixed();
//
//     require(y.a == 1234);
//     require(y.b == 100);
//     require(y.c == 1337.0f);
// }

uint8_t c_ret_small_packed_struct() {
    uint8_t s = 0;
    s |= 0 << 0;
    s |= 1 << 2;
    s |= 2 << 4;
    s |= 3 << 6;
    return s;
}

void c_small_packed_struct(uint8_t x) {
    require(((x >> 0) & 0x3) == 0);
    require(((x >> 2) & 0x3) == 1);
    require(((x >> 4) & 0x3) == 2);
    require(((x >> 6) & 0x3) == 3);
}

// #ifndef ZIG_NO_I128
// __int128 c_ret_big_packed_struct() {
//     __int128 s = 0;
//     s |= 1 << 0;
//     s |= (__int128)2 << 64;
//     return s;
// }

// void c_big_packed_struct(__int128 x) {
//     require(((x >> 0) & 0xFFFFFFFFFFFFFFFF) == 1);
//     require(((x >> 64) & 0xFFFFFFFFFFFFFFFF) == 2);
// }
// #endif

struct SplitStructMixed c_ret_split_struct_mixed() {
    struct SplitStructMixed s = {
        .a = 1234,
        .b = 100,
        .c = 1337.0f,
    };
    return s;
}

struct BigStruct c_big_struct_both(struct BigStruct x) {
    require(x.a == 1);
    require(x.b == 2);
    require(x.c == 3);
    require(x.d == 4);
    require(x.e == 5);
    struct BigStruct y = {10, 11, 12, 13, 14};
    return y;
}

void c_small_struct_floats(Vector3 vec) {
    require(vec.x == 3.0);
    require(vec.y == 6.0);
    require(vec.z == 12.0);
}

// void c_small_struct_floats_extra(Vector3 vec, const char *str) {
//     require(vec.x == 3.0);
//     require(vec.y == 6.0);
//     require(vec.z == 12.0);
//     require(!strcmp(str, "hello"));
// }

void c_big_struct_floats(Vector5 vec) {
    require(vec.x == 76.0);
    require(vec.y == -1.0);
    require(vec.z == -12.0);
    require(vec.w == 69);
    require(vec.q == 55);
}

void c_multiple_struct_ints(Rect x, Rect y) {
    require(x.left == 1);
    require(x.right == 21);
    require(x.top == 16);
    require(x.bottom == 4);
    require(y.left == 178);
    require(y.right == 189);
    require(y.top == 21);
    require(y.bottom == 15);
}

void c_multiple_struct_floats(FloatRect x, FloatRect y) {
    require(x.left == 1);
    require(x.right == 21);
    require(x.top == 16);
    require(x.bottom == 4);
    require(y.left == 178);
    require(y.right == 189);
    require(y.top == 21);
    require(y.bottom == 15);
}

bool c_ret_bool() {
    return 1;
}
uint8_t c_ret_u8() {
    return 0xff;
}
uint16_t c_ret_u16() {
    return 0xffff;
}
uint32_t c_ret_u32() {
    return 0xffffffff;
}
uint64_t c_ret_u64() {
    return 0xffffffffffffffff;
}
int8_t c_ret_s8() {
    return -1;
}
int16_t c_ret_s16() {
    return -1;
}
int32_t c_ret_s32() {
    return -1;
}
int64_t c_ret_s64() {
    return -1;
}

typedef struct {
    uint32_t a;
    uint8_t padding[4];
    uint64_t b;
} StructWithArray;

void c_struct_with_array(StructWithArray x) {
    require(x.a == 1);
    require(x.b == 2);
}

StructWithArray c_ret_struct_with_array() {
    return (StructWithArray){4, {}, 155};
}

typedef struct {
    struct Point {
        double x;
        double y;
    } origin;
    struct Size {
        double width;
        double height;
    } size;
} FloatArrayStruct;

void c_float_array_struct(FloatArrayStruct x) {
    require(x.origin.x == 5);
    require(x.origin.y == 6);
    require(x.size.width == 7);
    require(x.size.height == 8);
}

FloatArrayStruct c_ret_float_array_struct() {
    FloatArrayStruct x;
    x.origin.x = 1;
    x.origin.y = 2;
    x.size.width = 3;
    x.size.height = 4;
    return x;
}

typedef uint32_t SmallVec __attribute__((vector_size(2 * sizeof(uint32_t))));

void c_small_vec(SmallVec vec) {
    require(vec[0] == 1);
    require(vec[1] == 2);
}

SmallVec c_ret_small_vec(void) {
    return (SmallVec){3, 4};
}

typedef size_t MediumVec __attribute__((vector_size(4 * sizeof(size_t))));

void c_medium_vec(MediumVec vec) {
    require(vec[0] == 1);
    require(vec[1] == 2);
    require(vec[2] == 3);
    require(vec[3] == 4);
}

MediumVec c_ret_medium_vec(void) {
    return (MediumVec){5, 6, 7, 8};
}

typedef size_t BigVec __attribute__((vector_size(8 * sizeof(size_t))));

void c_big_vec(BigVec vec) {
    require(vec[0] == 1);
    require(vec[1] == 2);
    require(vec[2] == 3);
    require(vec[3] == 4);
    require(vec[4] == 5);
    require(vec[5] == 6);
    require(vec[6] == 7);
    require(vec[7] == 8);
}

BigVec c_ret_big_vec(void) {
    return (BigVec){9, 10, 11, 12, 13, 14, 15, 16};
}

typedef struct {
    float x, y;
} Vector2;

void c_ptr_size_float_struct(Vector2 vec) {
    require(vec.x == 1);
    require(vec.y == 2);
}
Vector2 c_ret_ptr_size_float_struct(void) {
    return (Vector2){3, 4};
}

/// Tests for Double + Char struct
// struct DC { double v1; char v2; };

// int c_assert_DC(struct DC lv){
//   if (lv.v1 != -0.25) return 1;
//   if (lv.v2 != 15) return 2;
//   return 0;
// }
// struct DC c_ret_DC(){
//     struct DC lv = { .v1 = -0.25, .v2 = 15 };
//     return lv;
// }
// int bb_assert_DC(struct DC);
// int c_send_DC(){
//     return bb_assert_DC(c_ret_DC());
// }
// struct DC bb_ret_DC();
// int c_assert_ret_DC(){
//     return c_assert_DC(bb_ret_DC());
// }

/// Tests for Char + Float + Float struct
struct CFF { char v1; float v2; float v3; };


int c_assert_CFF(struct CFF lv){
  if (lv.v1 != 39) return 1;
  if (lv.v2 != 0.875) return 2;
  if (lv.v3 != 1.0) return 3;
  return 0;
}
struct CFF c_ret_CFF(){
    struct CFF lv = { .v1 = 39, .v2 = 0.875, .v3 = 1.0 };
    return lv;
}
// int bb_assert_CFF(struct CFF);
// int c_send_CFF(){
//     return bb_assert_CFF(c_ret_CFF());
// }
// struct CFF bb_ret_CFF();
// int c_assert_ret_CFF(){
//     return c_assert_CFF(bb_ret_CFF());
// }

// struct PD { void* v1; double v2; };
//
// int c_assert_PD(struct PD lv){
//   if (lv.v1 != 0) return 1;
//   if (lv.v2 != 0.5) return 2;
//   return 0;
// }
// struct PD c_ret_PD(){
//     struct PD lv = { .v1 = 0, .v2 = 0.5 };
//     return lv;
// }
// int bb_assert_PD(struct PD);
// int c_send_PD(){
//     return bb_assert_PD(c_ret_PD());
// }
// struct PD bb_ret_PD();
// int c_assert_ret_PD(){
//     return c_assert_PD(bb_ret_PD());
// }

struct ByRef {
    int val;
    int arr[15];
};
struct ByRef c_modify_by_ref_param(struct ByRef in) {
    in.val = 42;
    return in;
}

struct ByVal {
    struct {
        unsigned long x;
        unsigned long y;
        unsigned long z;
    } origin;
    struct {
        unsigned long width;
        unsigned long height;
        unsigned long depth;
    } size;
};

void c_func_ptr_byval(void *a, void *b, struct ByVal in, unsigned long c, void *d, unsigned long e) {
    require((intptr_t)a == 1);
    require((intptr_t)b == 2);

    require(in.origin.x == 9);
    require(in.origin.y == 10);
    require(in.origin.z == 11);
    require(in.size.width == 12);
    require(in.size.height == 13);
    require(in.size.depth == 14);

    require(c == 3);
    require((intptr_t)d == 4);
    require(e == 5);
}

#ifndef ZIG_NO_RAW_F16
__fp16 c_f16(__fp16 a) {
    require(a == 12);
    return 34;
}
#endif

typedef struct {
    __fp16 a;
} f16_struct;
// f16_struct c_f16_struct(f16_struct a) {
//     require(a.a == 12);
//     return (f16_struct){34};
// }

// #if defined __x86_64__ || defined __i386__
// typedef long double f80;
// f80 c_f80(f80 a) {
//     require((double)a == 12.34);
//     return 56.78;
// }
// typedef struct {
//     f80 a;
// } f80_struct;
// f80_struct c_f80_struct(f80_struct a) {
//     require((double)a.a == 12.34);
//     return (f80_struct){56.78};
// }
// typedef struct {
//     f80 a;
//     int b;
// } f80_extra_struct;
// f80_extra_struct c_f80_extra_struct(f80_extra_struct a) {
//     require((double)a.a == 12.34);
//     require(a.b == 42);
//     return (f80_extra_struct){56.78, 24};
// }
// #endif

// #ifndef ZIG_NO_F128
// __float128 c_f128(__float128 a) {
//     require((double)a == 12.34);
//     return 56.78;
// }
// typedef struct {
//     __float128 a;
// } f128_struct;
// f128_struct c_f128_struct(f128_struct a) {
//     require((double)a.a == 12.34);
//     return (f128_struct){56.78};
// }
// #endif

// void __attribute__((stdcall)) stdcall_scalars(char a, short b, int c, float d, double e) {
//     require(a == 1);
//     require(b == 2);
//     require(c == 3);
//     require(d == 4.0);
//     require(e == 5.0);
// }
//
// typedef struct {
//     short x;
//     short y;
// } Coord2;
//
// Coord2 __attribute__((stdcall)) stdcall_coord2(Coord2 a, Coord2 b, Coord2 c) {
//     require(a.x == 0x1111);
//     require(a.y == 0x2222);
//     require(b.x == 0x3333);
//     require(b.y == 0x4444);
//     require(c.x == 0x5555);
//     require(c.y == 0x6666);
//     return (Coord2){123, 456};
// }
//
// void __attribute__((stdcall)) stdcall_big_union(union BigUnion x) {
//     require(x.a.a == 1);
//     require(x.a.b == 2);
//     require(x.a.c == 3);
//     require(x.a.d == 4);
// }

#ifdef __x86_64__
struct ByRef __attribute__((ms_abi)) c_explict_win64(struct ByRef in) {
    in.val = 42;
    return in;
}

struct ByRef __attribute__((sysv_abi)) c_explict_sys_v(struct ByRef in) {
    in.val = 42;
    return in;
}
#endif


// struct byval_tail_callsite_attr_Point {
//     double x;
//     double y;
// } Point;
// struct byval_tail_callsite_attr_Size {
//     double width;
//     double height;
// } Size;
// struct byval_tail_callsite_attr_Rect {
//     struct byval_tail_callsite_attr_Point origin;
//     struct byval_tail_callsite_attr_Size size;
// };
// double c_byval_tail_callsite_attr(struct byval_tail_callsite_attr_Rect in) {
//     return in.size.width;
// }

