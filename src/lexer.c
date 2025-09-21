#pragma once

#include <lexer.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif
#include <stdio.h>

#define SCALAR 1

LOCAL u8 escape_character(u8 ch)
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

LOCAL inline u32 str4(str string)
{
    check(string.length <= 4);
    check(string.length > 0);

    u32 value = 0;

    value |= string.pointer[0] << 0;
    value |= string.length >= 2 ? string.pointer[1] << 8 : 0;
    value |= string.length >= 3 ? string.pointer[2] << 16 : 0;
    value |= string.length >= 4 ? string.pointer[3] << 24 : 0;

    return value;
}

LOCAL inline u64 str8(str string)
{
    check(string.length <= 8);

    u64 value = 0;

    value |= string.pointer[0] << 0;
    value |= string.length >= 2 ? string.pointer[1] << 8 : 0;
    value |= string.length >= 3 ? string.pointer[2] << 16 : 0;
    value |= string.length >= 4 ? string.pointer[3] << 24 : 0;
    value |= string.length >= 5 ? (u64)string.pointer[4] << 32 : 0;
    value |= string.length >= 6 ? (u64)string.pointer[5] << 40 : 0;
    value |= string.length >= 7 ? (u64)string.pointer[6] << 48 : 0;
    value |= string.length >= 8 ? (u64)string.pointer[7] << 56 : 0;

    return value;
}

#ifdef __AVX512F__
LOCAL inline u64 identifier_character_count(__m512i chunk)
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
#endif

#define LEFT_BRACKET '['
#define RIGHT_BRACKET ']'
#define LEFT_BRACE '{'
#define RIGHT_BRACE '}'

LOCAL bool is_good_finishing_decimal_character(u8 ch)
{
    return is_space(ch) | ((ch >= '!') & (ch <= '/')) | ((ch >= ':') & (ch <= '@')) | ((ch >= LEFT_BRACKET) & (ch <= '`')) | ((ch >= LEFT_BRACE) & (ch <= '~'));
}

TokenList lex(CompileUnit* unit, File* file)
{
#define MEASURE_LEXING 0

#if MEASURE_LEXING
    let lexing_start = take_timestamp();
#endif
    char* restrict p = file->content.pointer;
    let l = file->content.length;
    let token_arena = unit_arena(unit, UNIT_ARENA_TOKEN);
    let string_arena = unit_arena(unit, UNIT_ARENA_STRING);

    Token* tokens = (Token*)((u8*)token_arena + align_forward(token_arena->position, alignof(Token)));
    u64 token_count = 0;
    u64 i = 0;
    u64 line_offset = 0;
    u64 previous_line_offset = 0;
    u64 line_character_offset = 0;

    while (1)
    {
        // Skipping whitespace
        {
#if SCALAR
            let ch0 = (p + i)[0];
            let ch1 = (p + i)[1];
            let ch2 = (p + i)[2];
            let ch3 = (p + i)[3];
#else
            let chunk64 = _mm512_loadu_epi8(&p[i]);
            let chunk32 = _mm512_extracti32x8_epi32(chunk64, 0);
            let chunk16 = _mm256_extracti128_si256(chunk32, 0);
            let chunk4 = _mm_extract_epi32(chunk16, 0);

            let ch0 = ((u8*)&chunk4)[0];
            let ch1 = ((u8*)&chunk4)[1];
            let ch2 = ((u8*)&chunk4)[2];
            let ch3 = ((u8*)&chunk4)[3];
#endif

            if (is_space(ch0) | ((ch0 == '/') & (ch1 == '/')))
            {
#if SCALAR
                bool skip_space = 1;

                while (skip_space)
                {
                    let iteration_offset = i;
                    bool space = 1;
                    while ((i < l) & space)
                    {
                        let ch = p[i];
                        let is_line_feed = ch == '\n';
                        space = is_space(ch);
                        i += space;

                        line_offset += is_line_feed;
                        line_character_offset = is_line_feed ? i : line_character_offset;
                    }
                    let is_comment = (i + 1 < l) & (p[i] == '/') & (p[i + 1] == '/');

                    if (is_comment)
                    {
                        while ((i < l) & (p[i] != '\n'))
                        {
                            i += 1;
                        }

                        i += 1;
                        line_offset += 1;
                        line_character_offset = i;
                    }

                    skip_space = (i - iteration_offset) != 0;
                }
#else
#define OPTIMIZE_FOR_COMMON_CASE 1
#if OPTIMIZE_FOR_COMMON_CASE
                if (!is_space(ch1) & !((ch1 == '/') & (ch2 == '/')))
                {
                    i += 1;
                    line_offset += ch0 == '\n';
                    line_character_offset = ch0 == '\n' ? i : line_character_offset;
                }
                else
#endif
                {
                    u64 skipped_ws_count = 1;

                    let line_feed = _mm512_set1_epi8('\n');
                    let r = _mm512_set1_epi8('\r');
                    let t = _mm512_set1_epi8('\t');
                    let space = _mm512_set1_epi8(' ');
                    let slash = _mm512_set1_epi8('/');

                    while (skipped_ws_count)
                    {
                        let ws_start = i;
                        let chunk = _mm512_loadu_epi8(&p[i]);
                        u64 left = l - i;
                        u64 clamped_int_mask = left < 64 ? (1 << left) - 1 : UINT64_MAX;
                        u64 clamped_slash_int_mask = 0b11 & (clamped_int_mask);
                        let clamped_mask = _cvtu64_mask64(clamped_int_mask);
                        let clamped_slash_mask = _cvtu64_mask64(clamped_slash_int_mask);

                        let is_line_feed = _mm512_mask_cmpeq_epu8_mask(clamped_mask, chunk, line_feed);
                        let is_space = _mm512_mask_cmpeq_epu8_mask(clamped_mask, chunk, space);
                        let is_r = _mm512_mask_cmpeq_epu8_mask(clamped_mask, chunk, r);
                        let is_t = _mm512_mask_cmpeq_epu8_mask(clamped_mask, chunk, t);

                        let traditional_ws_mask = _kor_mask64(_kor_mask64(is_line_feed, is_space), _kor_mask64(is_r, is_t));
                        let traditional_ws_int = _cvtmask64_u64(traditional_ws_mask);
                        let traditional_ws = _tzcnt_u64(~traditional_ws_int);

                        let is_line_feed_int = _cvtmask64_u64(is_line_feed);
                        let is_line_feed_int_mask = (1 << traditional_ws) - 1;
                        let line_bit_mask = is_line_feed_int & is_line_feed_int_mask;
                        let traditional_line_counts = _mm_popcnt_u64(line_bit_mask);
                        let character_after_line_offset = 64 - _lzcnt_u64(line_bit_mask);

                        let original_i = i;
                        i = original_i + traditional_ws;
                        line_offset += traditional_line_counts;
                        line_character_offset = traditional_line_counts ? (original_i + character_after_line_offset) : line_character_offset;

                        let is_first_slash = _mm512_mask_cmpeq_epu8_mask(_cvtu64_mask64(3), _mm512_loadu_epi8(&p[i]), slash);

                        let is_comment_int = _cvtmask64_u64(is_first_slash);
                        check((is_comment_int & 3) == is_comment_int);
                        let is_next_comment = is_comment_int == 3;
                        let offset = i + 2;

                        u64 not_line_count = (u64)is_next_comment << 6;
                        while (not_line_count == 64)
                        {
                            let chunk = _mm512_loadu_epi8(&p[offset]);
                            let is_line_feed = _mm512_cmpeq_epu8_mask(chunk, line_feed);
                            let is_line_feed_int = _cvtmask64_u64(is_line_feed);
                            let advance = _tzcnt_u64(is_line_feed_int);
                            not_line_count = advance;
                            offset += advance;
                        }

                        i = is_next_comment ? offset + 1: i;
                        skipped_ws_count = i - ws_start;
                        line_offset += is_next_comment ? 1 : 0;
                        line_character_offset = is_next_comment ? i : line_character_offset;
                    }
                }
#endif
            }
        }

        let start_index = i;
        let start_line = line_offset + 1;
        let start_column_offset = start_index - line_character_offset;
        let start_column = start_column_offset + 1;

        if (unlikely(i == l))
        {
            break;
        }

        if (line_offset != previous_line_offset)
        {
            Token* line_byte_offset = arena_allocate(token_arena, Token, 2);
            Token* line_number_offset = line_byte_offset + 1;
            token_count += 2;
            *line_byte_offset = (Token) {
                .offset = line_character_offset,
                .id = TOKEN_ID_LINE_BYTE_OFFSET,
            };
            *line_number_offset = (Token) {
                .offset = line_offset,
                .id = TOKEN_ID_LINE_NUMBER_OFFSET,
            };
        }

#if SCALAR
        let ch0 = (p + i)[0];
        let ch1 = (p + i)[1];
        let ch2 = (p + i)[2];
        let ch3 = (p + i)[3];
        let ch4 = (p + i)[4];
        let ch5 = (p + i)[5];
        let ch6 = (p + i)[6];
        let ch7 = (p + i)[7];
#else
        let chunk64 = _mm512_loadu_epi8(&p[start_index]);
        let chunk32 = _mm512_extracti32x8_epi32(chunk64, 0);
        let chunk16 = _mm256_extracti128_si256(chunk32, 0);
        let chunk4_0 = _mm_extract_epi32(chunk16, 0);
        let chunk4_1 = _mm_extract_epi32(chunk16, 1);

        static_assert(sizeof(chunk4_0) == 4);
        static_assert(sizeof(chunk4_1) == 4);
        let ch0 = ((u8*)&chunk4_0)[0];
        let ch1 = ((u8*)&chunk4_0)[1];
        let ch2 = ((u8*)&chunk4_0)[2];
        let ch3 = ((u8*)&chunk4_0)[3];
        let ch4 = ((u8*)&chunk4_1)[0];
        let ch5 = ((u8*)&chunk4_1)[1];
        let ch6 = ((u8*)&chunk4_1)[2];
        let ch7 = ((u8*)&chunk4_1)[3];
#endif

        Token* token = arena_allocate(token_arena, Token, 1);
        *token = (Token) {
            .offset = start_column_offset,
            .id = TOKEN_ID_NONE,
        };
        token_count += 1;

        if (is_identifier_start(ch0))
        {
#ifdef __AVX512F__
            u64 count = 64;

            while (count == 64)
            {
                let chunk = _mm512_loadu_epi8(&p[i]);
                count = identifier_character_count(chunk);
                i += count;
            }
#else
            while (1)
            {
                let ch = p[i];
                let is_id_ch = is_identifier(ch);
                if (!is_id_ch)
                {
                    break;
                }
                i += 1;
            }
#endif

            let candidate_identifier = str_from_ptr_start_end((char*)p, start_index, i);
            if (candidate_identifier.length == 0) UNREACHABLE();

            if (unlikely(candidate_identifier.length > UINT16_MAX))
            {
                token->id = TOKEN_ID_ERROR_IDENTIFIER_TOO_LONG;
                return (TokenList){ tokens, token_count };
            }

            let identifier_length = (u16)candidate_identifier.length;

            let is_signed = ch0 == 's';
            let is_unsigned = ch0 == 'u';
            let is_plausible_primitive_type = (identifier_length > 1) & (identifier_length <= 4);
            let is_float_type = (ch0 == 'f') & is_plausible_primitive_type;
            let is_integer_type = (is_signed | is_unsigned) & is_plausible_primitive_type;

            let is_decimal1 = is_decimal(ch1) & ((identifier_length != 2) | is_good_finishing_decimal_character(ch2));
            let is_decimal2 = identifier_length > 2 ? (is_decimal(ch2) & ((identifier_length != 3) | is_good_finishing_decimal_character(ch3))) : 1;
            let is_decimal3 = identifier_length > 3 ? (is_decimal(ch3) & ((identifier_length != 4) | is_good_finishing_decimal_character(ch4))) : 1;

            is_integer_type = (is_integer_type & is_decimal1) & (is_decimal2 & is_decimal3);
            is_float_type = (is_float_type & is_decimal1) & (is_decimal2 & is_decimal3);

            if (is_integer_type | is_float_type)
            {
                let bit_count_128 = parse_integer_decimal_assume_valid(str_slice_start(candidate_identifier, 1));
                check(bit_count_128 < UINT64_MAX);
                let bit_count = (u64)bit_count_128;

                str type_name = is_signed ? S("signed integer") : (is_unsigned ? S("unsigned integer") : S("float"));

                if (bit_count == 0)
                {
                    str parts[] = {
                        type_name,
                        S(" type cannot have 0 bit count"),
                    };
                    token->id = TOKEN_ID_ERROR_PRIMITIVE_TYPE_0_BIT_COUNT;

                    return (TokenList){ tokens, token_count };
                }

                if ((bit_count > 64) & (bit_count != 128))
                {
                    str parts[] = {
                        type_name,
                        S(" type cannot have that bit count"),
                    };
                    token->id = TOKEN_ID_ERROR_PRIMITIVE_TYPE_UNKNOWN_BIT_COUNT;

                    return (TokenList){ tokens, token_count };
                }

                if (is_integer_type)
                {
                    // token.content = (TokenContent) {
                    //     .integer_type = {
                    //         .bit_count = bit_count,
                    //         .is_signed = is_signed,
                    //     },
                    // };
                    token->id = TOKEN_ID_KEYWORD_TYPE_INTEGER;
                }
                else
                {
                    token->id = TOKEN_ID_KEYWORD_TYPE_FLOAT;
                }
            }
            else
            {
                str candidate_strings[] = {
                    S("type"),
                    S("void"),
                    S("noreturn"),
                    S("enum"),
                    S("struct"),
                    S("bits"),
                    S("union"),
                    S("fn"),
                    S("alias"),
                    S("vector"),
                    S("enum_array"),
                    S("opaque"),

                    S("_"),
                    S("return"),
                    S("if"),
                    S("when"),
                    S("for"),
                    S("while"),
                    S("switch"),
                    S("break"),
                    S("continue"),
                    S("unreachable"),
                    S("else"),

                    S("undefined"),
                    S("zero"),
                    
                    S("and"),
                    S("or"),
                    S("and?"),
                    S("or?"),
                };

#if SCALAR
                TokenId candidate_ids[] = {
                    TOKEN_ID_KEYWORD_TYPE,
                    TOKEN_ID_KEYWORD_TYPE_VOID,
                    TOKEN_ID_KEYWORD_TYPE_NORETURN,
                    TOKEN_ID_KEYWORD_TYPE_ENUM,
                    TOKEN_ID_KEYWORD_TYPE_STRUCT,
                    TOKEN_ID_KEYWORD_TYPE_BITS,
                    TOKEN_ID_KEYWORD_TYPE_UNION,
                    TOKEN_ID_KEYWORD_TYPE_FN,
                    TOKEN_ID_KEYWORD_TYPE_ALIAS,
                    TOKEN_ID_KEYWORD_TYPE_VECTOR,
                    TOKEN_ID_KEYWORD_TYPE_ENUM_ARRAY,
                    TOKEN_ID_KEYWORD_TYPE_OPAQUE,

                    TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE,
                    TOKEN_ID_KEYWORD_STATEMENT_RETURN,
                    TOKEN_ID_KEYWORD_STATEMENT_IF,
                    TOKEN_ID_KEYWORD_STATEMENT_WHEN,
                    TOKEN_ID_KEYWORD_STATEMENT_FOR,
                    TOKEN_ID_KEYWORD_STATEMENT_WHILE,
                    TOKEN_ID_KEYWORD_STATEMENT_SWITCH,
                    TOKEN_ID_KEYWORD_STATEMENT_BREAK,
                    TOKEN_ID_KEYWORD_STATEMENT_CONTINUE,
                    TOKEN_ID_KEYWORD_STATEMENT_UNREACHABLE,
                    TOKEN_ID_KEYWORD_STATEMENT_ELSE,

                    TOKEN_ID_KEYWORD_VALUE_UNDEFINED,
                    TOKEN_ID_KEYWORD_VALUE_ZERO,

                    TOKEN_ID_KEYWORD_OPERATOR_AND,
                    TOKEN_ID_KEYWORD_OPERATOR_OR,
                    TOKEN_ID_KEYWORD_OPERATOR_AND_SHORTCIRCUIT,
                    TOKEN_ID_KEYWORD_OPERATOR_OR_SHORTCIRCUIT,
                };
#else

                TokenId candidate_ids[] = {
                    TOKEN_ID_KEYWORD_TYPE,
                    TOKEN_ID_KEYWORD_TYPE_VOID,
                    TOKEN_ID_KEYWORD_TYPE_ENUM,
                    TOKEN_ID_KEYWORD_TYPE_BITS,
                    TOKEN_ID_KEYWORD_STATEMENT_WHEN,
                    TOKEN_ID_KEYWORD_STATEMENT_ELSE,
                    TOKEN_ID_KEYWORD_VALUE_ZERO,
                    TOKEN_ID_KEYWORD_OPERATOR_AND_SHORTCIRCUIT,

                    TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE,

                    TOKEN_ID_KEYWORD_TYPE_FN,
                    TOKEN_ID_KEYWORD_STATEMENT_IF,
                    TOKEN_ID_KEYWORD_OPERATOR_OR,

                    TOKEN_ID_KEYWORD_STATEMENT_FOR,
                    TOKEN_ID_KEYWORD_OPERATOR_AND,
                    TOKEN_ID_KEYWORD_OPERATOR_OR_SHORTCIRCUIT,

                    TOKEN_ID_KEYWORD_TYPE_UNION,
                    TOKEN_ID_KEYWORD_TYPE_ALIAS,
                    TOKEN_ID_KEYWORD_STATEMENT_WHILE,
                    TOKEN_ID_KEYWORD_STATEMENT_BREAK,

                    TOKEN_ID_KEYWORD_TYPE_STRUCT,
                    TOKEN_ID_KEYWORD_TYPE_VECTOR,
                    TOKEN_ID_KEYWORD_TYPE_OPAQUE,
                    TOKEN_ID_KEYWORD_STATEMENT_RETURN,
                    TOKEN_ID_KEYWORD_STATEMENT_SWITCH,

                    TOKEN_ID_KEYWORD_TYPE_NORETURN,
                    TOKEN_ID_KEYWORD_STATEMENT_CONTINUE,

                    TOKEN_ID_KEYWORD_VALUE_UNDEFINED,
                    TOKEN_ID_KEYWORD_TYPE_ENUM_ARRAY,
                    TOKEN_ID_KEYWORD_STATEMENT_UNREACHABLE,
                };

                static_assert(array_length(candidate_strings) == array_length(candidate_ids));
#endif

                u64 max_string_length = 0;
                for (u64 i = 0; i < array_length(candidate_strings); i += 1)
                {
                    let candidate_string = candidate_strings[i];
                    max_string_length = candidate_string.length > max_string_length ? candidate_string.length : max_string_length;
                }

                let is_and_sc = ((ch0 == 'a') & (ch1 == 'n')) & ((ch2 == 'd') & (ch3 == '?')) & candidate_identifier.length == 3;
                let is_or_sc = ((ch0 == 'o') & (ch1 == 'r')) & ((ch2 == '?') & (candidate_identifier.length == 2));
                candidate_identifier.length += (is_and_sc | is_or_sc);

                check(candidate_identifier.length <= UINT16_MAX);
                u32 search_index = candidate_identifier.length > max_string_length ? array_length(candidate_ids) : 0;
#if SCALAR
                for (; search_index < array_length(candidate_strings); search_index += 1)
                {
                    str candidate_string = candidate_strings[search_index];
                    if (str_equal(candidate_identifier, candidate_string))
                    {
                        break;
                    }
                }
#else
                if (candidate_identifier.length <= max_string_length)
                {
                    // Candidate 4

                    let candidates4 = _mm512_setr_epi32(
                            // 4-bit candidates
                            str4(S("type")),
                            str4(S("void")),
                            str4(S("enum")),
                            str4(S("bits")),
                            str4(S("when")),
                            str4(S("else")),
                            str4(S("zero")),
                            str4(S("and?")),
                            // 1-bit candidates
                            str4(S("_")),
                            // 2-bit candidates
                            str4(S("fn")),
                            str4(S("if")),
                            str4(S("or")),
                            // 3-bit candidates
                            str4(S("for")),
                            str4(S("and")),
                            str4(S("or?")),
                            // unre-achable start
                            str4(S("unre"))
                                );

                    __mmask64 mov_mask4 = _cvtu64_mask64((0xf777ULL << 48) | (0x333ULL << 36) | (1ULL << 32) | 0xffffffff);
                    let candidate4 = _mm512_maskz_mov_epi8(mov_mask4, _mm512_set1_epi32(chunk4_0));

                    __mmask16 candidate_mask4 = (u16)(((u32)(candidate_identifier.length == 11) << 16) - 1) & 0x8000 | (u16)(((u32)(candidate_identifier.length == 3) << 16) - 1) & 0x7000 | (((u16)(candidate_identifier.length == 2) << (9 + 3)) - 1) & 0xe00 | ((candidate_identifier.length == 1) << 8) | (((u16)(candidate_identifier.length) << 8) - 1);
                    let is_candidate4 = _mm512_mask_cmpeq_epi32_mask(candidate_mask4, candidates4, candidate4);

                    // =========================================================
                    // Candidate 8
                    // =========================================================

                    let candidate8 = _mm512_broadcast_i32x2(chunk16);
                    let candidate8_shr4 = _mm_bsrli_si128(chunk16, 4);
                    let candidate8_shr8 = _mm_bsrli_si128(chunk16, 8);

                    let candidates8_0 = _mm512_setr_epi64(
                            // 5-bit candidates
                            str8(S("union")),
                            str8(S("alias")),
                            str8(S("while")),
                            str8(S("break")),
                            // Split
                            str8(S("undefine")),
                            str8(S("d")),
                            str8(S("enum_arr")),
                            str8(S("ay"))
                            );
                    let candidate8_0_shr8_512 = _mm512_broadcast_i32x2(candidate8_shr8);
                    let candidate8_0_second_part = _mm512_maskz_mov_epi8(_cvtu64_mask64(1ULL << 40 | 3ULL << 56), candidate8_0_shr8_512);
                    let candidate8_0_before_masking = _mm512_mask_mov_epi64(candidate8, _cvtu32_mask8(1 << 7 | 1 << 5), candidate8_0_second_part);

                    __mmask64 mov_mask8_0 = _cvtu64_mask64((3ULL << 56) | (0xffULL << 48) | (1ULL << 40) | (0xffULL << 32) | 0x1f1f1f1f);
                    let candidate_8_0 = _mm512_maskz_mov_epi8(mov_mask8_0, candidate8_0_before_masking);
                    __mmask8 candidate_mask8_0 = ((u8)(((candidate_identifier.length == 10) << 8) - 1) & 0xc0) | ((((candidate_identifier.length == 9) << 6) - 1) & 0x30) | (((candidate_identifier.length == 5) << 4) - 1);
                    let is_candidate8_0 = _mm512_mask_cmpeq_epi64_mask(candidate_mask8_0, candidates8_0, candidate_8_0);

                    let candidates8_1 = _mm512_setr_epi64(
                            // 6-bit candidates
                            str8(S("struct")),
                            str8(S("vector")),
                            str8(S("opaque")),
                            str8(S("return")),
                            str8(S("switch")),
                            // 8-bit candidates
                            str8(S("noreturn")),
                            str8(S("continue")),
                            // unreachable second half
                            str8(S("achable"))
                            );

                    let candidate8_1_shr4_512 = _mm512_broadcast_i32x2(candidate8_shr4);
                    let candidate8_1_second_part = _mm512_maskz_mov_epi8(_cvtu64_mask64(0x7fULL << 56), candidate8_1_shr4_512);
                    let candidate8_1_before_masking = _mm512_mask_mov_epi64(candidate8, _cvtu32_mask8(1 << 7), candidate8_1_second_part);

                    __mmask64 mov_mask8_1 = _cvtu64_mask64(0x7fULL << 56 | (0xffffULL << 40) | 0x3f3f3f3f3f);
                    let candidate_8_1 = _mm512_maskz_mov_epi8(mov_mask8_1, candidate8_1_before_masking);
                    __mmask8 candidate_mask8_1 = ((u8)(((candidate_identifier.length == 11) << 8) - 1) & 0xc0) | ((((candidate_identifier.length == 8) << 7) - 1) & 0x60) | (((candidate_identifier.length == 6) << 5) - 1);
                    let is_candidate8_1 = _mm512_mask_cmpeq_epi64_mask(candidate_mask8_1, candidates8_1, candidate_8_1);

                    let is_candidate4_int = _cvtmask16_u32(is_candidate4);
                    let is_candidate8_0_int = _cvtmask8_u32(is_candidate8_0);
                    let is_candidate8_1_int = _cvtmask8_u32(is_candidate8_1);

                    bool is_unreachable = ((is_candidate4_int & (1 << 15)) != 0) & ((is_candidate8_1_int & (1 << 7)) != 0);
                    bool is_undefined = ((is_candidate8_0_int & (1 << 4)) != 0) & ((is_candidate8_0_int & (1 << 5)) != 0);
                    bool is_enum_array = ((is_candidate8_0_int & (1 << 6)) != 0) & ((is_candidate8_0_int & (1 << 7)) != 0);

                    let is_candidate_mask = (is_candidate4_int & 0x7fff) | ((is_candidate8_0_int & 0xf) << 15) | ((is_candidate8_1_int & 0x7f) << 19) | ((u32)is_undefined << 26) | ((u32)is_enum_array << 27) | ((u32)is_unreachable << 28);
                    search_index = _tzcnt_u32(is_candidate_mask);
                }
#endif
                if (search_index < array_length(candidate_strings))
                {
                    let candidate_id = candidate_ids[search_index];
                    token->id = candidate_id;
                }
                else
                {
                    token->id = TOKEN_ID_IDENTIFIER_START;

                    Token* end_token = arena_allocate(token_arena, Token, 1);
                    token_count += 1;

                    *end_token = (Token) {
                        .offset = i - line_character_offset,
                        .id = TOKEN_ID_IDENTIFIER_END,
                    };
                }
            }
        }
        else if (is_decimal(ch0))
        {
            let is_first_zero = ch0 == '0';

            let prefix_ch = ch0;
            let is_valid_prefix_ch = ((prefix_ch == 'x') | (prefix_ch == 'd')) | ((prefix_ch == 'o') | (prefix_ch == 'b'));
            let is_valid_prefix = is_first_zero & is_valid_prefix_ch;

            i += 1 + is_valid_prefix + (-!is_valid_prefix);

            TokenId token_id = TOKEN_ID_INTEGER_START_DECIMAL_INFERRED;

            if (is_valid_prefix)
            {
                switch (prefix_ch)
                {
                    break; case 'x': token_id = TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED;
                    break; case 'd': token_id = TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED;
                    break; case 'o': token_id = TOKEN_ID_INTEGER_START_OCTAL_PREFIXED;
                    break; case 'b': token_id = TOKEN_ID_INTEGER_START_BINARY_PREFIXED;
                    break; default:
                        UNREACHABLE();
                }
            }

            let inferred_decimal = !is_valid_prefix;
            u64 value = 0;
            let before_i = i;

            IntegerParsing r;

            let number_start = &p[i];

            switch (token_id)
            {
#if SCALAR
                break; case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED: r = parse_hexadecimal_scalar(number_start);
                break; case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED: case TOKEN_ID_INTEGER_START_DECIMAL_INFERRED: r = parse_decimal_scalar(number_start);
                break; case TOKEN_ID_INTEGER_START_OCTAL_PREFIXED: r = parse_octal_scalar(number_start);
                break; case TOKEN_ID_INTEGER_START_BINARY_PREFIXED: r = parse_binary_scalar(number_start);
#else
                break; case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED: r = parse_hexadecimal_vectorized(number_start);
                break; case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED: case TOKEN_ID_INTEGER_START_DECIMAL_INFERRED: r = parse_decimal_vectorized(number_start);
                break; case TOKEN_ID_INTEGER_START_OCTAL_PREFIXED: r = parse_octal_vectorized(number_start);
                break; case TOKEN_ID_INTEGER_START_BINARY_PREFIXED: r = parse_binary_vectorized(number_start);
#endif
                break; default: UNREACHABLE();
            }

            value = r.value;
            i += r.i;

            if (unlikely(i == before_i))
            {
                trap();
            }

            let is_float = inferred_decimal & ((p[i] == '.') & (p[i + 1] != '.'));
            if (is_float)
            {
                i += 1;

#if SCALAR
                let r = parse_decimal_scalar(&p[i]);
#else
                let r = parse_decimal_vectorized(&p[i]);
#endif
                let mantissa = r.value;
                i += r.i;

                let float_string_literal = str_from_ptr_start_end((char*)p, start_index, i);
            }

            token->id = is_float ? TOKEN_ID_FLOAT_START : token_id;

            let end = arena_allocate(token_arena, Token, 1);
            token_count += 1;

            *end = (Token) {
                .offset = i - line_character_offset,
                    .id = is_float ? TOKEN_ID_FLOAT_END : TOKEN_ID_INTEGER_END,
            };
        }
        else if (ch0 == '"')
        {
            i += 1;

            let string_literal_start = i;

            u64 escape_character_count = 0;

#if SCALAR
            while (i < l)
            {
                let ch = p[i];

                if (ch == '"')
                {
                    break;
                }

                let is_escape = ch == '\\';
                escape_character_count += is_escape;

                i += 1 + is_escape;
            }
#else

            // Taken from https://lemire.me/blog/2022/09/14/escaping-strings-faster-with-avx-512/
            let escape_ch = _mm512_set1_epi8('\\');
            let double_quote = _mm512_set1_epi8('"');

            u64 string_character_count = 64;

            while (string_character_count == 64)
            {
                let chunk = _mm512_loadu_epi8(&p[i]);
                let is_escape_character = _mm512_cmpeq_epu8_mask(chunk, escape_ch);
                let is_double_quote = _mm512_cmpeq_epu8_mask(chunk, double_quote);
                let first_double_quote = _tzcnt_u64(_cvtmask64_u64(is_double_quote));
                let first_escape = _tzcnt_u64(_cvtmask64_u64(is_escape_character));

                if ((first_escape < first_double_quote) & (_mm_popcnt_u64(_cvtmask64_u64(is_escape_character))))
                {
                    trap();
                }
                else
                {
                    let mask = _cvtmask64_u64(is_double_quote);
                    string_character_count = _tzcnt_u64(_cvtmask64_u64(mask));
                    i += string_character_count;
                }
            }
#endif

            let is_properly_finished = p[i] == '"';
            if (!is_properly_finished)
            {
                token->id = TOKEN_ID_ERROR_STRING_LITERAL_EOF_NO_DOUBLE_QUOTE;
                return (TokenList){ tokens, token_count };
            }

            let string_literal_end = i;

            let length = string_literal_end - start_index - escape_character_count;
            let pointer = arena_allocate_bytes(string_arena, length, 1);
            let original_string_bytes = str_from_ptr_start_end((char*)p, string_literal_start, string_literal_end);
            let string_literal = str_from_ptr_len(pointer, length);

            if (escape_character_count != 0)
            {
                check(original_string_bytes.length < string_literal.length);

                let source_i = start_index;
                u64 destination_i = 0;

                while (source_i < string_literal_end)
                {
                    let ch = p[source_i];

                    if (ch == '\\')
                    {
                        source_i += 1;
                        ch = p[source_i];
                        string_literal.pointer[destination_i] = escape_character(ch);
                        if (!ch)
                        {
                            return (TokenList) { tokens, token_count };
                        }
                    }
                    else
                    {
                        string_literal.pointer[destination_i] = ch;
                    }

                    source_i += 1;
                    destination_i += 1;
                }

                check(i == source_i);
            }
            else
            {
                memcpy(pointer, original_string_bytes.pointer, original_string_bytes.length);
            }

            token->id = TOKEN_ID_STRING_LITERAL_START;

            let end = arena_allocate(token_arena, Token, 1);
            token_count += 1;
            *end = (Token) {
                .offset = i - line_character_offset,
                .id = TOKEN_ID_STRING_LITERAL_END,
            };

            i += 1;
        }
        else if (ch0 == '\'')
        {
            u8 ch;
            let is_escape_character = ch1 == '\\';
            if (is_escape_character)
            {
                ch = escape_character(ch2);
            }
            else
            {
                ch = ch1;
                if (ch1 == '\'')
                {
                    token->id = TOKEN_ID_ERROR_CHARACTER_LITERAL_EMPTY;
                    return (TokenList) { tokens, token_count };
                }
            }

            i += 3 + is_escape_character;
            let terminating_character = is_escape_character ? ch3 : ch2;

            if (terminating_character != '\'')
            {
                token->id = TOKEN_ID_ERROR_CHARACTER_LITERAL_BADLY_TERMINATED;
                return (TokenList) { tokens, token_count };
            }

            token->id = TOKEN_ID_CHARACTER_LITERAL;
        }
        else
        {
            if (ch0 == '=')
            {
                i += 1;

                let is_compare_equal = ch1 == '=';
                let is_switch_token = ch1 == '>';

                i += (is_compare_equal | is_switch_token);

                if (is_compare_equal)
                {
                    token->id = TOKEN_ID_COMPARE_EQUAL;
                }
                else if (is_switch_token)
                {
                    token->id = TOKEN_ID_SWITCH_CASE;
                }
                else
                {
                    token->id = TOKEN_ID_ASSIGN;
                }
            }
            else if (ch0 == '!')
            {
                i += 1;

                let is_compare_not_equal = ch1 == '=';
                i += is_compare_not_equal;

                token->id = is_compare_not_equal ? TOKEN_ID_COMPARE_NOT_EQUAL : TOKEN_ID_EXCLAMATION_DOWN;
            }
            else if (ch0 == '<')
            {
                if (ch1 == '<')
                {
                    if (ch2 == '=')
                    {
                        token->id = TOKEN_ID_SHIFT_LEFT_ASSIGN;
                        i += 3;
                    }
                    else
                    {
                        token->id = TOKEN_ID_SHIFT_LEFT;
                        i += 2;
                    }
                }
                else if (ch1 == '=')
                {
                    token->id = TOKEN_ID_COMPARE_LESS_EQUAL;
                    i += 2;
                }
                else
                {
                    token->id = TOKEN_ID_COMPARE_LESS;
                    i += 1;
                }
            }
            else if (ch0 == '>')
            {
                if (ch1 == '>')
                {
                    if (ch2 == '=')
                    {
                        token->id = TOKEN_ID_SHIFT_RIGHT_ASSIGN;
                        i += 3;
                    }
                    else
                    {
                        token->id = TOKEN_ID_SHIFT_RIGHT;
                        i += 2;
                    }
                }
                else if (ch1 == '=')
                {
                    token->id = TOKEN_ID_COMPARE_GREATER_EQUAL;
                    i += 2;
                }
                else
                {
                    token->id = TOKEN_ID_COMPARE_GREATER;
                    i += 1;
                }
            }
            else if (ch0 == '+')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_ADD_ASSIGN : TOKEN_ID_PLUS;
            }
            else if (ch0 == '-')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_SUB_ASSIGN : TOKEN_ID_DASH;
            }
            else if (ch0 == '*')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_MUL_ASSIGN : TOKEN_ID_ASTERISK;
            }
            else if (ch0 == '/')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_DIV_ASSIGN : TOKEN_ID_FORWARD_SLASH;
            }
            else if (ch0 == '%')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_REM_ASSIGN : TOKEN_ID_PERCENTAGE;
            }
            else if (ch0 == '&')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_BITWISE_AND_ASSIGN : TOKEN_ID_AMPERSAND;
            }
            else if (ch0 == '|')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_BITWISE_OR_ASSIGN : TOKEN_ID_BAR;
            }
            else if (ch0 == '^')
            {
                i += 1;

                let is_assign = ch1 == '=';

                i += is_assign;

                token->id = is_assign ? TOKEN_ID_BITWISE_XOR_ASSIGN : TOKEN_ID_CARET;
            }
            else if (ch0 == '.')
            {
                let is_ch1_dot = ch1 == '.';
                let is_ch1_address = ch1 == '&';
                let is_ch1_question = ch1 == '?';
                let is_ch2_dot = ch2 == '.';

                if (is_ch2_dot & is_ch1_dot)
                {
                    token->id = TOKEN_ID_TRIPLE_DOT;
                    i += 3;
                }
                else if (is_ch1_dot)
                {
                    token->id = TOKEN_ID_DOUBLE_DOT;
                    i += 2;
                }
                else if (is_ch1_address)
                {
                    token->id = TOKEN_ID_POINTER_DEREFERENCE;
                    i += 2;
                }
                else if (is_ch1_question)
                {
                    token->id = TOKEN_ID_OPTIONAL_DEREFERENCE;
                    i += 2;
                }
                else
                {
                    token->id = TOKEN_ID_DOT;
                    i += 1;
                }
            }
            else if (ch0 == ',')
            {
                i += 1;
                token->id = TOKEN_ID_COMMA;
            }
            else if (ch0 == ';')
            {
                i += 1;
                token->id = TOKEN_ID_SEMICOLON;
            }
            else if (ch0 == ':')
            {
                i += 1;
                token->id = TOKEN_ID_COLON;
            }
            else if (ch0 == '?')
            {
                i += 1;
                token->id = TOKEN_ID_QUESTION;
            }
            else if (ch0 == '(')
            {
                i += 1;
                token->id = TOKEN_ID_LEFT_PARENTHESIS;
            }
            else if (ch0 == ')')
            {
                i += 1;
                token->id = TOKEN_ID_RIGHT_PARENTHESIS;
            }
            else if (ch0 == '{')
            {
                i += 1;
                token->id = TOKEN_ID_LEFT_BRACE;
            }
            else if (ch0 == '}')
            {
                i += 1;
                token->id = TOKEN_ID_RIGHT_BRACE;
            }
            else if (ch0 == '[')
            {
                i += 1;
                token->id = TOKEN_ID_LEFT_BRACKET;
            }
            else if (ch0 == ']')
            {
                i += 1;
                token->id = TOKEN_ID_RIGHT_BRACKET;
            }
            else if (ch0 == '@')
            {
                i += 1;
                token->id = TOKEN_ID_AT;
            }
            else if (ch0 == '\\')
            {
                i += 1;
                token->id = TOKEN_ID_BACKSLASH;
            }
            else if (ch0 == '`')
            {
                i += 1;
                token->id = TOKEN_ID_BACKTICK;
            }
            else if (ch0 == '#')
            {
                i += 1;
                token->id = TOKEN_ID_HASH;
            }
            else if (ch0 == '$')
            {
                i += 1;
                token->id = TOKEN_ID_DOLLAR;
            }
            else if (ch0 == '~')
            {
                i += 1;
                token->id = TOKEN_ID_TILDE;
            }
            else if (unlikely(unlikely(ch0 >= 0x7f) | unlikely(ch0 < ' ')))
            {
                if (ch0 > 0x7f)
                {
                    token->id = TOKEN_ID_ERROR_NOT_SUPPORTED_X_ASCII_OR_UNICODE;
                }
                else if (ch0 < ' ')
                {
                    token->id = TOKEN_ID_ERROR_NON_PRINTABLE_ASCII;
                }
                else
                {
                    token->id = TOKEN_ID_ERROR_FOUND_DEL;
                }

                return (TokenList) { tokens, token_count };
            }
            else
            {
                UNREACHABLE();
            }
        }

        check(token->id != TOKEN_ID_NONE);
    }

    let eof = arena_allocate(token_arena, Token, 1);
    *eof = (Token) {
        .offset = i - line_character_offset,
        .id = TOKEN_ID_EOF,
    };
    token_count += 1;

#if MEASURE_LEXING
    let lexing_end = take_timestamp();

    let lexing_ns = ns_between(lexing_start, lexing_end);
    let gbytes_per_s = (f64)(l * 1000000000ULL) / (lexing_ns * 1024 * 1024 * 1024);
    let lines = line_offset + 1;
    let millions_lines_s = (f64)(lines * 1000) / lexing_ns;
    printf("Lexing: %lu ns. %f GB/s. %f MLOCs/s\n", lexing_ns, gbytes_per_s, millions_lines_s);
#endif

    let result = (TokenList) { .pointer = tokens, .length = token_count };

    if (unit->verbose)
    {
        unit_show(unit, token_list_to_string(get_default_arena(unit), result));
    }

    return result;
}

#if BB_INCLUDE_TESTS
bool lexer_tests(TestArguments* restrict arguments)
{
    return 1;
}
#endif

LOCAL str token_id_to_string(TokenId id)
{
    switch (id)
    {
        case TOKEN_ID_NONE: return S("NONE");
        case TOKEN_ID_EOF: return S("EOF");
        case TOKEN_ID_IDENTIFIER_START: return S("id_start");
        case TOKEN_ID_IDENTIFIER_END: return S("id_end");
        case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED: return S("hex_start");
        case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED: return S("decimal_start");
        case TOKEN_ID_INTEGER_START_OCTAL_PREFIXED: return S("octal_start");
        case TOKEN_ID_INTEGER_START_BINARY_PREFIXED: return S("binary_start");
        case TOKEN_ID_INTEGER_START_DECIMAL_INFERRED: return S("inf_decimal_start");
        case TOKEN_ID_INTEGER_END: return S("integer_end");
        case TOKEN_ID_FLOAT_START: return S("float_start");
        case TOKEN_ID_FLOAT_END: return S("float_end");
        case TOKEN_ID_STRING_LITERAL_START: return S("string_literal_start");
        case TOKEN_ID_STRING_LITERAL_END: return S("string_literal_end");
        case TOKEN_ID_CHARACTER_LITERAL: return S("char_literal");
        case TOKEN_ID_KEYWORD_TYPE_INTEGER: return S("type_integer");
        case TOKEN_ID_KEYWORD_TYPE_FLOAT: return S("type_float");
        case TOKEN_ID_KEYWORD_TYPE: return S("type");
        case TOKEN_ID_KEYWORD_TYPE_VOID: return S("type_void");
        case TOKEN_ID_KEYWORD_TYPE_NORETURN: return S("type_noreturn");
        case TOKEN_ID_KEYWORD_TYPE_ENUM: return S("type_enum");
        case TOKEN_ID_KEYWORD_TYPE_STRUCT: return S("type_struct");
        case TOKEN_ID_KEYWORD_TYPE_BITS: return S("type_bits");
        case TOKEN_ID_KEYWORD_TYPE_UNION: return S("type_union");
        case TOKEN_ID_KEYWORD_TYPE_FN: return S("type_fn");
        case TOKEN_ID_KEYWORD_TYPE_ALIAS: return S("type_alias");
        case TOKEN_ID_KEYWORD_TYPE_VECTOR: return S("type_vector");
        case TOKEN_ID_KEYWORD_TYPE_ENUM_ARRAY: return S("type_enum_array");
        case TOKEN_ID_KEYWORD_TYPE_OPAQUE: return S("type_opaque");
        case TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE: return S("st_underscore");
        case TOKEN_ID_KEYWORD_STATEMENT_RETURN: return S("st_return");
        case TOKEN_ID_KEYWORD_STATEMENT_IF: return S("st_if");
        case TOKEN_ID_KEYWORD_STATEMENT_WHEN: return S("st_when");
        case TOKEN_ID_KEYWORD_STATEMENT_FOR: return S("st_for");
        case TOKEN_ID_KEYWORD_STATEMENT_WHILE: return S("st_while");
        case TOKEN_ID_KEYWORD_STATEMENT_SWITCH: return S("st_switch");
        case TOKEN_ID_KEYWORD_STATEMENT_BREAK: return S("st_break");
        case TOKEN_ID_KEYWORD_STATEMENT_CONTINUE: return S("st_continue");
        case TOKEN_ID_KEYWORD_STATEMENT_UNREACHABLE: return S("st_unreachable");
        case TOKEN_ID_KEYWORD_STATEMENT_ELSE: return S("st_else");
        case TOKEN_ID_KEYWORD_VALUE_UNDEFINED: return S("undefined");
        case TOKEN_ID_KEYWORD_VALUE_ZERO: return S("zero");
        case TOKEN_ID_KEYWORD_OPERATOR_AND: return S("and");
        case TOKEN_ID_KEYWORD_OPERATOR_OR: return S("or");
        case TOKEN_ID_KEYWORD_OPERATOR_AND_SHORTCIRCUIT: return S("and?");
        case TOKEN_ID_KEYWORD_OPERATOR_OR_SHORTCIRCUIT: return S("or?");
        case TOKEN_ID_ASSIGN: return S("'='");
        case TOKEN_ID_COMPARE_EQUAL: return S("'=='");
        case TOKEN_ID_SWITCH_CASE: return S("'=>'");
        case TOKEN_ID_EXCLAMATION_DOWN: return S("'!'");
        case TOKEN_ID_COMPARE_NOT_EQUAL: return S("'!='");
        case TOKEN_ID_COMPARE_LESS: return S("'<'");
        case TOKEN_ID_COMPARE_LESS_EQUAL: return S("'<='");
        case TOKEN_ID_SHIFT_LEFT: return S("'<<'");
        case TOKEN_ID_SHIFT_LEFT_ASSIGN: return S("'<<='");
        case TOKEN_ID_COMPARE_GREATER: return S("'>'");
        case TOKEN_ID_COMPARE_GREATER_EQUAL: return S("'>='");
        case TOKEN_ID_SHIFT_RIGHT: return S("'>>'");
        case TOKEN_ID_SHIFT_RIGHT_ASSIGN: return S("'>>='");
        case TOKEN_ID_PLUS: return S("'+'");
        case TOKEN_ID_ADD_ASSIGN: return S("'+='");
        case TOKEN_ID_DASH: return S("'-'");
        case TOKEN_ID_SUB_ASSIGN: return S("'-='");
        case TOKEN_ID_ASTERISK: return S("'*'");
        case TOKEN_ID_MUL_ASSIGN: return S("'*='");
        case TOKEN_ID_FORWARD_SLASH: return S("'/'");
        case TOKEN_ID_DIV_ASSIGN: return S("'/='");
        case TOKEN_ID_PERCENTAGE: return S("'%'");
        case TOKEN_ID_REM_ASSIGN: return S("'%='");
        case TOKEN_ID_AMPERSAND: return S("'&'");
        case TOKEN_ID_BITWISE_AND_ASSIGN: return S("'&='");
        case TOKEN_ID_BAR: return S("'|'");
        case TOKEN_ID_BITWISE_OR_ASSIGN: return S("'|='");
        case TOKEN_ID_CARET: return S("'^'");
        case TOKEN_ID_BITWISE_XOR_ASSIGN: return S("'^='");
        case TOKEN_ID_DOT: return S("'.'");
        case TOKEN_ID_POINTER_DEREFERENCE: return S("'.&'");
        case TOKEN_ID_OPTIONAL_DEREFERENCE: return S("'.?'");
        case TOKEN_ID_DOUBLE_DOT: return S("'..'");
        case TOKEN_ID_TRIPLE_DOT: return S("'...'");
        case TOKEN_ID_LEFT_PARENTHESIS: return S("'('");
        case TOKEN_ID_RIGHT_PARENTHESIS: return S("')'");
        case TOKEN_ID_LEFT_BRACE: return S("'{'");
        case TOKEN_ID_RIGHT_BRACE: return S("'}'");
        case TOKEN_ID_LEFT_BRACKET: return S("'['");
        case TOKEN_ID_RIGHT_BRACKET: return S("']'");
        case TOKEN_ID_COMMA: return S("','");
        case TOKEN_ID_SEMICOLON: return S("';'");
        case TOKEN_ID_COLON: return S("':'");
        case TOKEN_ID_QUESTION: return S("'?'");
        case TOKEN_ID_AT: return S("'@'");
        case TOKEN_ID_BACKTICK: return S("'`'");
        case TOKEN_ID_BACKSLASH: return S("'\\'");
        case TOKEN_ID_HASH: return S("'#'");
        case TOKEN_ID_DOLLAR: return S("'$'");
        case TOKEN_ID_TILDE: return S("'~'");
        case TOKEN_ID_LINE_BYTE_OFFSET: return S("line_byte");
        case TOKEN_ID_LINE_NUMBER_OFFSET: return S("line_number");
        case TOKEN_ID_ERROR_LINE_NUMBER_TOO_HIGH: return S("error_line_number_too_high");
        case TOKEN_ID_ERROR_COLUMN_NUMBER_TOO_HIGH: return S("error_column_number_too_high");
        case TOKEN_ID_ERROR_PRIMITIVE_TYPE_0_BIT_COUNT: return S("error_primitive_type_0_bit_count");
        case TOKEN_ID_ERROR_PRIMITIVE_TYPE_UNKNOWN_BIT_COUNT: return S("error_primitive_type_unknown_bit_count");
        case TOKEN_ID_ERROR_STRING_LITERAL_EOF_NO_DOUBLE_QUOTE: return S("error_string_literal_eof_no_double_quote");
        case TOKEN_ID_ERROR_CHARACTER_LITERAL_EMPTY: return S("error_character_literal_empty");
        case TOKEN_ID_ERROR_CHARACTER_LITERAL_BADLY_TERMINATED: return S("error_character_literal_badly_terminated");
        case TOKEN_ID_ERROR_NOT_SUPPORTED_X_ASCII_OR_UNICODE: return S("error_extended_ascii_or_unicode");
        case TOKEN_ID_ERROR_NON_PRINTABLE_ASCII: return S("error_non_printable_ascii");
        case TOKEN_ID_ERROR_FOUND_DEL: return S("error_del");
        case TOKEN_ID_ERROR_IDENTIFIER_TOO_LONG: return S("error_identifier_too_long1");
        default: UNREACHABLE();
    }
}

str token_list_to_string(Arena* arena, TokenList list)
{
    let start = arena->position;
    Token* restrict p = list.pointer;

    for (u64 i = 0; i < list.length; i += 1)
    {
        let token = p[i];
        u32 offset = token.offset;
        TokenId id = token.id;
        arena_duplicate_string(arena, S("#"), false);
        format_integer(arena, (FormatIntegerOptions){ .value = i }, false);
        arena_duplicate_string(arena, S(" "), false);
        arena_duplicate_string(arena, token_id_to_string(id), false);
        arena_duplicate_string(arena, S(", n: "), false);
        format_integer(arena, (FormatIntegerOptions){ .value = offset }, false);
        arena_duplicate_string(arena, S(",\n"), false);
    }

    let result = (str){(char*)arena + start, arena->position - start };
    return result;
}
