#include <lexer.h>

#include <immintrin.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

static bool is_space(char ch)
{
    return ((ch == ' ') | (ch == '\t')) | ((ch == '\r') | (ch == '\n'));
}

static bool is_decimal(char ch)
{
    return (ch >= '0') & (ch <= '9');
}

static bool is_octal(char ch)
{
    return (ch >= '0') & (ch <= '7');
}

static bool is_binary(char ch)
{
    return (ch == '0') | (ch == '1');
}

static bool is_hexadecimal_alpha_lower(char ch)
{
    return (ch >= 'a') & (ch <= 'f');
}

static bool is_hexadecimal_alpha_upper(char ch)
{
    return (ch >= 'A') & (ch <= 'F');
}

static bool is_hexadecimal_alpha(char ch)
{
    return is_hexadecimal_alpha_upper(ch) | is_hexadecimal_alpha_lower(ch);
}

static bool is_hexadecimal(char ch)
{
    return is_decimal(ch) | is_hexadecimal_alpha(ch);
}

static bool is_identifier_start(char ch)
{
    return (((ch >= 'a') & (ch <= 'z')) | ((ch >= 'A') & (ch <= 'Z'))) | (ch == '_');
}

static bool is_identifier(char ch)
{
    return is_identifier_start(ch) | is_decimal(ch);
}

static u128 accumulate_hexadecimal(u128 accumulator, u8 ch)
{
    u8 value;

    if (is_decimal(ch))
    {
        value = ch - '0';
    }
    else if (is_hexadecimal_alpha_upper(ch))
    {
        value = ch - 'A' + 10;
    }
    else if (is_hexadecimal_alpha_lower(ch))
    {
        value = ch - 'a' + 10;
    }
    else
    {
        UNREACHABLE();
    }

    return (accumulator * 16) + value;
}

static u128 accumulate_decimal(u128 accumulator, u8 ch)
{
    assert(is_decimal(ch));
    return (accumulator * 10) + (ch - '0');
}

static u128 accumulate_octal(u128 accumulator, u8 ch)
{
    assert(is_octal(ch));

    return (accumulator * 8) + (ch - '0');
}

static u128 accumulate_binary(u128 accumulator, u8 ch)
{
    assert(is_binary(ch));

    return (accumulator * 2) + (ch - '0');
}

static u128 parse_integer_decimal_assume_valid(str string)
{
    u128 value = 0;

    for (u64 i = 0; i < string.length; i += 1)
    {
        let ch = string.pointer[i];
        value = accumulate_decimal(value, ch);
    }

    return value;
}

STRUCT(IntegerParsing)
{
    u64 value;
    u64 i;
};


static IntegerParsing parse_hexadecimal(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_hexadecimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_hexadecimal(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

static IntegerParsing parse_hexadecimal_vectorized(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        // let ch = p[i];
        //
        // if (!is_hexadecimal(ch))
        // {
        //     break;
        // }
        //
        // i += 1;
        // value = accumulate_hexadecimal(value, ch);
        trap();
    }

    return (IntegerParsing){ .value = value, .i = i };
}

static IntegerParsing parse_decimal(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_decimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_decimal(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

static IntegerParsing parse_decimal_vectorized(const char* restrict p)
{
    let zero = _mm512_set1_epi8('0');
    let nine = _mm512_set1_epi8('9');
    let chunk = _mm512_loadu_epi8(&p[0]);
    let lower_limit = _mm512_cmpge_epu8_mask(chunk, zero);
    let upper_limit = _mm512_cmple_epu8_mask(chunk, nine);
    let is = _kand_mask64(lower_limit, upper_limit);

    let digit_count = _tzcnt_u64(~_cvtmask64_u64(is));

    let digit_mask = _cvtu64_mask64((1ULL << digit_count) - 1);
    let digit2bin = _mm512_maskz_sub_epi8(digit_mask, chunk, zero);
    let lo0 = _mm512_castsi512_si128(digit2bin);
    let a = _mm512_cvtepu8_epi64(lo0);
    let digit_count_splat = _mm512_set1_epi8((u8)digit_count);

    let to_sub = _mm512_set_epi8(
            64, 63, 62, 61, 60, 59, 58, 57,
            56, 55, 54, 53, 52, 51, 50, 49,
            48, 47, 46, 45, 44, 43, 42, 41,
            40, 39, 38, 37, 36, 35, 34, 33,
            32, 31, 30, 29, 28, 27, 26, 25,
            24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9,
            8, 7, 6, 5, 4, 3, 2, 1);
    let ib = _mm512_maskz_sub_epi8(digit_mask, digit_count_splat, to_sub);
    let asds = _mm512_maskz_permutexvar_epi8(digit_mask, ib, digit2bin);

    let a128_0_0 = _mm512_extracti64x2_epi64(asds, 0);
    let a128_1_0 = _mm512_extracti64x2_epi64(asds, 1);

    let a128_0_1 = _mm_srli_si128(a128_0_0, 8);
    let a128_1_1 = _mm_srli_si128(a128_1_0, 8);

    let a8_0_0 = _mm512_cvtepu8_epi64(a128_0_0);
    let a8_0_1 = _mm512_cvtepu8_epi64(a128_0_1);
    let a8_1_0 = _mm512_cvtepu8_epi64(a128_1_0);

    let powers_of_ten_0_0 = _mm512_set_epi64(
            10000000,
            1000000,
            100000,
            10000,
            1000,
            100,
            10,
            1);
    let powers_of_ten_0_1 = _mm512_set_epi64(
            1000000000000000,
            100000000000000,
            10000000000000,
            1000000000000,
            100000000000,
            10000000000,
            1000000000,
            100000000
            );
    let powers_of_ten_1_0 = _mm512_set_epi64(
            0,
            0,
            0,
            0,
            10000000000000000000ULL,
            1000000000000000000,
            100000000000000000,
            10000000000000000
            );

    let a0_0 = _mm512_mullo_epi64(a8_0_0, powers_of_ten_0_0);
    let a0_1 = _mm512_mullo_epi64(a8_0_1, powers_of_ten_0_1);
    let a1_0 = _mm512_mullo_epi64(a8_1_0, powers_of_ten_1_0);

    let add = _mm512_add_epi64(_mm512_add_epi64(a0_0, a0_1), a1_0);
    let reduce_add = _mm512_reduce_add_epi64(add);
    let value = (u64)reduce_add;

    return (IntegerParsing){ .value = value, .i = digit_count };
}

static IntegerParsing parse_octal(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_octal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_octal(value, ch);
    }

    return (IntegerParsing) { .value = value, .i = i };
}

static IntegerParsing parse_octal_vectorized(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let chunk = _mm512_loadu_epi8(&p[i]);
        let lower_limit = _mm512_cmpge_epu8_mask(chunk, _mm512_set1_epi8('0'));
        let upper_limit = _mm512_cmple_epu8_mask(chunk, _mm512_set1_epi8('7'));
        let is_octal = _kand_mask64(lower_limit, upper_limit);
        let octal_mask = _cvtu64_mask64(_tzcnt_u64(~_cvtmask64_u64(is_octal)));

        trap();

        // if (!is_octal(ch))
        // {
        //     break;
        // }
        //
        // i += 1;
        // value = accumulate_octal(value, ch);
    }

    return (IntegerParsing) { .value = value, .i = i };
}

static IntegerParsing parse_binary(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_binary(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_binary(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

static inline IntegerParsing parse_binary_vectorized(const char* restrict f)
{
    u64 value = 0;

    let chunk = _mm512_loadu_epi8(f);
    let zero = _mm512_set1_epi8('0');
    let is0 = _mm512_cmpeq_epu8_mask(chunk, zero);
    let is1 = _mm512_cmpeq_epu8_mask(chunk, _mm512_set1_epi8('1'));
    let is_binary_chunk = _kor_mask64(is0, is1);
    u64 i = _tzcnt_u64(~_cvtmask64_u64(is_binary_chunk));
    let digit2bin = _mm512_maskz_sub_epi8(is_binary_chunk, chunk, zero);
    let rotated = _mm512_permutexvar_epi8(digit2bin,
            _mm512_set_epi8(
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31,
                32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47,
                48, 49, 50, 51, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61, 62, 63
                ));
    let mask = _mm512_test_epi8_mask(rotated, rotated);
    let mask_int = _cvtmask64_u64(mask);

    return (IntegerParsing) { .value = value, .i = i };
}

static u8 escape_character(u8 ch)
{
    switch (ch)
    {
        break; case 'n': return '\n';
        break; case 't': return '\t';
        break; case 'r': return '\r';
        break; case '\'': return '\'';
        break; case '\\': return '\\';
        break; default: return 0;
    }
}

static inline u32 str4(str str)
{
    assert(str.length <= 4);
    assert(str.length > 0);

    u32 value = 0;

    value |= str.pointer[0] << 0;
    value |= str.length >= 2 ? str.pointer[1] << 8 : 0;
    value |= str.length >= 3 ? str.pointer[2] << 16 : 0;
    value |= str.length >= 4 ? str.pointer[3] << 24 : 0;

    return value;
}

static inline u64 str8(str str)
{
    assert(str.length <= 8);

    u64 value = 0;

    value |= str.pointer[0] << 0;
    value |= str.length >= 2 ? str.pointer[1] << 8 : 0;
    value |= str.length >= 3 ? str.pointer[2] << 16 : 0;
    value |= str.length >= 4 ? str.pointer[3] << 24 : 0;
    value |= str.length >= 5 ? (u64)str.pointer[4] << 32 : 0;
    value |= str.length >= 6 ? (u64)str.pointer[5] << 40 : 0;
    value |= str.length >= 7 ? (u64)str.pointer[6] << 48 : 0;
    value |= str.length >= 8 ? (u64)str.pointer[7] << 56 : 0;

    return value;
}

static inline u64 identifier_character_count(__m512i chunk)
{
    let a = _mm512_set1_epi8('a');
    let z = _mm512_set1_epi8('z');
    let A = _mm512_set1_epi8('A');
    let Z = _mm512_set1_epi8('Z');
    let zero = _mm512_set1_epi8('0');
    let nine = _mm512_set1_epi8('9');
    let underscore = _mm512_set1_epi8('_');

    let cmp_a = _mm512_cmpge_epu8_mask(chunk, a);
    let cmp_z = _mm512_cmple_epu8_mask(chunk, z);
    let cmp_A = _mm512_cmpge_epu8_mask(chunk, A);
    let cmp_Z = _mm512_cmple_epu8_mask(chunk, Z);
    let cmp_zero = _mm512_cmpge_epu8_mask(chunk, zero);
    let cmp_nine = _mm512_cmple_epu8_mask(chunk, nine);
    let cmp_u = _mm512_cmpeq_epu8_mask(chunk, underscore);

    let is_lower = _kand_mask64(cmp_a, cmp_z);
    let is_upper = _kand_mask64(cmp_A, cmp_Z);
    let is_decimal = _kand_mask64(cmp_zero, cmp_nine);
    let is_identifier_mask = _kor_mask64(_kor_mask64(is_lower, is_upper), _kor_mask64(is_decimal, cmp_u));

    let is_identifier_int = _cvtmask64_u64(is_identifier_mask);
    let result = _tzcnt_u64(~is_identifier_int);
    return result;
}

using AlignedCharPointer = const char* restrict __attribute((align_value(64)));

STRUCT(FileSlice)
{
    AlignedCharPointer pointer;
    u64 length;
};

static_assert(sizeof(FileSlice) == sizeof(u64) * 2);

STRUCT(VU)
{
    __m512i v;

    [[gnu::always_inline]] VU() : v(_mm512_setzero_si512()) {}
    [[gnu::always_inline]] VU(__m512i x) : v(x) {}

    [[gnu::always_inline]] operator __m512i()
    {
        return v;
    }
};

constexpr u64 element_count = 8;

STRUCT(V)
{
    VU v[element_count];

    [[gnu::always_inline]] V(__m512i v0, __m512i v1, __m512i v2, __m512i v3, __m512i v4, __m512i v5, __m512i v6, __m512i v7) : v{v0, v1, v2, v3, v4, v5, v6, v7} {}
    [[gnu::always_inline]] V() : v(
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512(),
            _mm512_setzero_si512()
        )
    {
    }

    [[gnu::always_inline]] V(AlignedCharPointer p) : v(
            _mm512_load_si512(p + (64 * 0)),
            _mm512_load_si512(p + (64 * 1)),
            _mm512_load_si512(p + (64 * 2)),
            _mm512_load_si512(p + (64 * 3)),
            _mm512_load_si512(p + (64 * 4)),
            _mm512_load_si512(p + (64 * 5)),
            _mm512_load_si512(p + (64 * 6)),
            _mm512_load_si512(p + (64 * 7))
        )
    {
    }

    [[gnu::always_inline]] VU operator[](size_t index)
    {
        return v[index];
    }

    [[gnu::always_inline]] VU equal(u8 ch, VU mask)
    {
        let ch_splat = _mm512_set1_epi8(ch);
        let r0 = _mm512_cmpeq_epu8_mask(v[0], ch_splat);
        let r1 = _mm512_cmpeq_epu8_mask(v[1], ch_splat);
        let r2 = _mm512_cmpeq_epu8_mask(v[2], ch_splat);
        let r3 = _mm512_cmpeq_epu8_mask(v[3], ch_splat);
        let r4 = _mm512_cmpeq_epu8_mask(v[4], ch_splat);
        let r5 = _mm512_cmpeq_epu8_mask(v[5], ch_splat);
        let r6 = _mm512_cmpeq_epu8_mask(v[6], ch_splat);
        let r7 = _mm512_cmpeq_epu8_mask(v[7], ch_splat);
        let r = _mm512_setr_epi64(r0, r1, r2, r3, r4, r5, r6, r7);
        let result = _mm512_and_si512(r, mask);
        return result;
    }

    [[gnu::always_inline]] VU greater_equal(u8 ch, VU mask)
    {
        let ch_splat = _mm512_set1_epi8(ch);
        let r0 = _mm512_cmpge_epu8_mask(v[0], ch_splat);
        let r1 = _mm512_cmpge_epu8_mask(v[1], ch_splat);
        let r2 = _mm512_cmpge_epu8_mask(v[2], ch_splat);
        let r3 = _mm512_cmpge_epu8_mask(v[3], ch_splat);
        let r4 = _mm512_cmpge_epu8_mask(v[4], ch_splat);
        let r5 = _mm512_cmpge_epu8_mask(v[5], ch_splat);
        let r6 = _mm512_cmpge_epu8_mask(v[6], ch_splat);
        let r7 = _mm512_cmpge_epu8_mask(v[7], ch_splat);
        let r = _mm512_setr_epi64(r0, r1, r2, r3, r4, r5, r6, r7);
        let result = _mm512_and_si512(r, mask);
        return result;
    }
};

STRUCT(Carry)
{
    __m512i is_slash;
    __m512i is_backslash;
    __m512i is_carriage;
    __m512i is_at;

    __m512i is_inside_strings_and_comments_including_start;
    __m512i is_next_escaped;
    __m512i is_ended_on_double_char;

    __m512i is_number_or_builtin_end;
    __m512i is_identifier_end;

    __m512i is_inside_double_quotes_incl_start_and_carry;
    __m512i is_inside_single_quotes_incl_start_and_carry;
    __m512i is_inside_comments;
    __m512i is_inside_line_strings;
};

[[gnu::always_inline]] static __m512i shl1(__m512i v)
{
    return _mm512_shldi_epi64(v, _mm512_alignr_epi64(v, _mm512_setzero_si512(), 7), 1);
}

[[gnu::always_inline]] static __m512i shr1(__m512i v)
{
    return _mm512_shldi_epi64(_mm512_alignr_epi64(_mm512_setzero_si512(), v, 1), v, 63);
}

[[gnu::always_inline]] static __m512i sub(__m512i a, __m512i b)
{
    let cmp1 = _mm512_cmple_epu64_mask(a, b);
    let s = _mm512_sub_epi64(a, b);
    let cmp2 = _mm512_cmpeq_epu64_mask(a, b);
    let ks = _kshiftli_mask16(cmp1, 1);
    let kadd0 = _kadd_mask16(ks, cmp2);
    let kadd1 = _kadd_mask8(cmp2, kadd0);
    let t1 = _mm512_ternarylogic_epi64(a, a, a, 0xff);
    let add = _mm512_maskz_add_epi64(kadd1, s, t1);
    return add;
}

[[gnu::always_inline]] static __mmask8 extract_16_0_8(__mmask16 m)
{
    return (__mmask8)(m << 8);
}

[[gnu::always_inline]] static __m512i isolate_msb(__m512i v)
{
#if 0
    let mask = _mm_cmpge_epu8_mask(
        extract_16_0_8(_mm_srlv_epi64(
            _mm_set1_epi64x(1ULL << 63),
            _mm_lzcnt_epi64(
                _mm_set_epi64x(
                    _mm512_test_epi64_mask(v, v) ? 0xff : 0,
                    0
                )
            )
        )), 
        _mm_set1_epi8(0x80)
    );
    let a = _mm512_srlv_epi64(_mm512_set1_epi64((u64)1 << 63), _mm512_lzcnt_epi64(v));
    let b = _mm512_setzero_si512();

    let result = _mm512_mask_mov_epi64(b, mask, a);
    trap();
#else
    // Step 1: zero mask
    __mmask8 nonzero_mask = _mm512_test_epi64_mask(v, v); // 1 if element != 0

    // Step 2: clz per 64-bit element (AVX-512 has VPLZCNTQ)
    __m512i lz = _mm512_lzcnt_epi64(v);

    // Step 3: compute (1ULL << 63) >> lz
    __m512i oneshift = _mm512_set1_epi64(1ULL << 63);
    __m512i msb = _mm512_srlv_epi64(oneshift, lz);

    // Step 4: select(msb, 0) based on mask
    return _mm512_maskz_mov_epi64(nonzero_mask, msb);
#endif
}

[[gnu::always_inline]] static bool isolate_last_bit(__m512i v)
{
    return (bool)(_mm256_extract_epi64(_mm512_extracti64x4_epi64(v, 1), 3) >> 63);
}

TokenList lex(Arena* stable_arena, Arena* else_arena, AlignedCharPointer p, u64 l, LexerError* error)
{
#define MEASURE_LEXING 1
#if MEASURE_LEXING
    let lexing_start = take_timestamp();
#endif
    assert(l);

    let allocation_size = align_forward(sizeof(Token) * (l + 64), 0x1000);

    let allocation = mmap(0, allocation_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (allocation == MAP_FAILED)
    {
        trap();
    }

    Carry carry = {};

    let current = (FileSlice){ p, l };
    let previous_chunk = V{};
    u32 previously_carried_length = 0;

    while (1)
    {
        _mm_prefetch(current.pointer, _MM_HINT_NTA);

        let iota = _mm512_slli_epi64(_mm512_setr_epi64(0, 1, 2, 3, 4, 5, 6, 7), 6);
        let before_eofs = _mm512_sllv_epi64(~_mm512_setzero_si512(), _mm512_sub_epi64(_mm512_max_epu64(_mm512_set1_epi64(current.length), iota), iota));

        let chunk = V(current.pointer);

        let all_starts = VU{};
        let all_ends = VU{};

        let is_carriage = chunk.equal('\r', before_eofs);
        let is_line_feed = chunk.equal('\n', before_eofs);
        let is_slash = chunk.equal('/', before_eofs);
        let is_backslash = chunk.equal('\\', before_eofs);
        let is_double_quote = chunk.equal('"', before_eofs);
        let is_single_quote = chunk.equal('\'', before_eofs);
        let non_ascii = chunk.greater_equal(0x80, before_eofs);

        let bad_carriage_returns = _mm512_ternarylogic_epi64(is_line_feed, shl1(is_carriage), _mm512_srli_epi64(carry.is_carriage, 63), 0x0e);
        if (_mm512_test_epi64_mask(bad_carriage_returns, bad_carriage_returns))
        {
            trap();
        }

        let is_carriage_or_line_feed = _mm512_or_si512(is_carriage, is_line_feed);
        let is_carriage_or_line_feed_or_eof = _mm512_or_si512(is_carriage_or_line_feed, ~before_eofs);

        __m512i is_escaped;
        {
            let odd_bits = _mm512_set1_epi8(0xaa);
            let is_next_escaped = _mm512_srli_epi64(carry.is_next_escaped, 63);
            let is_potential_escape = _mm512_and_epi64(is_backslash, ~is_next_escaped);
            let is_maybe_escaped = shl1(is_potential_escape);
            let is_even_series_codes_and_odd_bits = sub(_mm512_or_epi64(is_maybe_escaped, odd_bits), is_potential_escape);
            let is_escape_and_terminal_code = _mm512_xor_epi64(is_even_series_codes_and_odd_bits, odd_bits);
            is_escaped = _mm512_xor_epi64(is_escape_and_terminal_code, _mm512_or_epi64(is_backslash, is_next_escaped));
            carry.is_next_escaped = _mm512_and_epi64(is_escape_and_terminal_code, is_backslash);
        }

        let is_unescaped_double_quote = _mm512_and_epi64(is_double_quote, ~is_escaped);
        let is_unescaped_single_quote = _mm512_and_epi64(is_single_quote, ~is_escaped);

        let is_double_slash_start = _mm512_and_epi64(is_slash, _mm512_or_epi64(shr1(is_slash), _mm512_srli_epi64(carry.is_slash, 63)));
        let is_double_backslash_start = _mm512_and_epi64(is_backslash, _mm512_or_epi64(shr1(is_backslash), _mm512_srli_epi64(carry.is_backslash, 63)));

        let is_comment_bounds_incl_carry = _mm512_or_epi64(is_double_slash_start, _mm512_srli_epi64(carry.is_inside_comments, 63));
        let is_line_string_bounds_incl_carry = _mm512_or_epi64(is_double_backslash_start, _mm512_srli_epi64(carry.is_inside_line_strings, 63));

        let is_first_char_end_string = _mm512_or_epi64(
            _mm512_and_epi64(is_unescaped_double_quote, _mm512_srli_epi64(carry.is_inside_double_quotes_incl_start_and_carry, 63)),
            _mm512_and_epi64(is_unescaped_single_quote, _mm512_srli_epi64(carry.is_inside_single_quotes_incl_start_and_carry, 63))
        );

        all_starts = _mm512_or_epi64(all_starts, is_first_char_end_string);
        all_ends = _mm512_or_epi64(all_ends, is_first_char_end_string);

        let is_double_quote_incl_carry = _mm512_xor_epi64(is_unescaped_double_quote, _mm512_srli_epi64(carry.is_inside_double_quotes_incl_start_and_carry, 63));
        let is_single_quote_incl_carry = _mm512_xor_epi64(is_unescaped_single_quote, _mm512_srli_epi64(carry.is_inside_single_quotes_incl_start_and_carry, 63));

        let iter = _mm512_and_epi64(~is_carriage_or_line_feed, ~shl1(~is_carriage_or_line_feed));
        let is_all_bounds_incl_carry = _mm512_or_epi64(_mm512_or_epi64(is_double_quote_incl_carry, is_single_quote_incl_carry), _mm512_or_epi64(is_comment_bounds_incl_carry, is_line_string_bounds_incl_carry));

        while (1)
        {
            let is_start = _mm512_and_epi64(is_all_bounds_incl_carry, ~sub(_mm512_or_epi64(is_all_bounds_incl_carry, is_carriage_or_line_feed_or_eof), iter)); 
            all_starts = _mm512_or_epi64(all_starts, is_start);

            let interleaved = _mm512_and_epi64(
                    _mm512_or_epi64(
                        _mm512_or_epi64(
                            _mm512_and_epi64(
                                is_double_quote_incl_carry,
                                sub(
                                    is_carriage_or_line_feed_or_eof,
                                    _mm512_and_epi64(is_start, is_double_quote_incl_carry)
                                )
                            ),
                            _mm512_and_epi64(
                                is_single_quote_incl_carry,
                                sub(
                                    is_carriage_or_line_feed_or_eof,
                                    _mm512_and_epi64(is_start, is_single_quote_incl_carry)
                                )
                            )
                        ),
                        is_carriage_or_line_feed_or_eof
                    ),
                    ~is_start);

            let is_current_end = _mm512_and_epi64(interleaved, ~sub(interleaved, is_start));
            all_ends = _mm512_or_epi64(all_ends, is_current_end);

            iter = _mm512_and_epi64(is_current_end, ~is_carriage_or_line_feed_or_eof);
            assert(_mm512_cmpeq_epu8_mask(_mm512_and_epi64(is_all_bounds_incl_carry, iter), iter) == UINT64_MAX);
            is_all_bounds_incl_carry = _mm512_xor_epi64(is_all_bounds_incl_carry, iter);

            if (likely(_mm512_test_epi64_mask(iter, iter) == 0))
            {
                break;
            }
        }

        let is_inside_strings_and_comments_including_start = sub(all_ends, all_starts);
        let is_first_char_inside_string_or_comment = _mm512_and_epi64(_mm512_srli_epi64(carry.is_inside_strings_and_comments_including_start, 63), _mm512_and_epi64(~is_first_char_end_string, ~is_carriage_or_line_feed_or_eof));

        let is_inside_strings_or_comments = _mm512_or_epi64(_mm512_and_epi64(is_inside_strings_and_comments_including_start, ~all_starts), is_first_char_inside_string_or_comment);

        let is_last_start = isolate_msb(all_starts);
        let is_end_inside_string_or_comment = isolate_last_bit(is_inside_strings_or_comments);

        {
            // TODO: truly implement this
            
            //carry.is_inside_double_quotes_incl_start_and_carry = _mm512_and
            //carry.is_inside_single_quotes_incl_start_and_carry = _mm512_setzero_si512();
            //carry.is_inside_comments = _mm512_setzero_si512();
            //carry.is_inside_line_strings = _mm512_setzero_si512();
        }

        trap();
        previous_chunk = chunk;
    }

    trap();

#if MEASURE_LEXING
    let lexing_end = take_timestamp();

    // let lexing_ns = ns_between(lexing_start, lexing_end);
    // let gbytes_per_s = (f64)(l * 1000000000ULL) / (lexing_ns * 1024 * 1024 * 1024);
    // let lines = line_offset + 1;
    // let millions_lines_s = (f64)(lines * 1000) / lexing_ns;
    // printf("Lexing: %lu ns. %f GB/s. %f MLOCs/s\n", lexing_ns, gbytes_per_s, millions_lines_s);
#endif

    // return (TokenList) { .pointer = tokens, .length = token_count };
    trap();
}
