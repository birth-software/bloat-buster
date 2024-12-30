#pragma once

fn u8 log2_alignment(u64 alignment)
{
    assert(alignment != 0);
    assert((alignment & (alignment - 1)) == 0);
    u64 left = (sizeof(alignment) * 8) - 1;
    let_cast(u64, right, __builtin_clzll(alignment));
    let_cast(u8, result, left - right);
    return result;
}

// Lehmer's generator
// https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/
may_be_unused global_variable u128 rn_state;
may_be_unused fn u64 generate_random_number()
{
    rn_state *= 0xda942042e4dd58b5;
    return rn_state >> 64;
}

fn u64 round_up_to_next_power_of_2(u64 n)
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

may_be_unused fn u64 absolute_int(s64 n)
{
    return n < 0 ? cast_to(u64, -n) : cast_to(u64, n);
}

fn u64 parse_decimal(String string)
{
    u64 value = 0;
    for (u64 i = 0; i < string.length; i += 1)
    {
        u8 ch = s_get(string, i);
        assert(((ch >= '0') & (ch <= '9')));
        value = (value * 10) + (ch - '0');
    }

    return value;
}

fn u8 get_next_ch_safe(String string, u64 index)
{
    u64 next_index = index + 1;
    u64 is_in_range = next_index < string.length;
    u64 safe_index = safe_flag(next_index, is_in_range);
    u8 unsafe_result = string.pointer[safe_index];
    u64 safe_result = safe_flag(unsafe_result, is_in_range);
    assert(safe_result < 256);
    return (u8)safe_result;
}

fn u32 is_space(u8 ch, u8 next_ch)
{
    u32 is_comment = (ch == '/') & (next_ch == '/');
    u32 is_whitespace = ch == ' ';
    u32 is_vertical_tab = ch == 0x0b;
    u32 is_horizontal_tab = ch == '\t';
    u32 is_line_feed = ch == '\n';
    u32 is_carry_return = ch == '\r';
    u32 result = (((is_vertical_tab | is_horizontal_tab) | (is_line_feed | is_carry_return)) | (is_comment | is_whitespace));
    return result;
}

fn u64 is_lower(u8 ch)
{
    return (ch >= 'a') & (ch <= 'z');
}

fn u64 is_upper(u8 ch)
{
    return (ch >= 'A') & (ch <= 'Z');
}

fn u64 is_alphabetic(u8 ch)
{
    return is_lower(ch) | is_upper(ch);
}

fn u64 is_decimal_digit(u8 ch)
{
    return (ch >= '0') & (ch <= '9');
}

fn u64 is_hex_digit(u8 ch)
{
    return (is_decimal_digit(ch) | ((ch == 'a' | ch == 'A') | (ch == 'b' | ch == 'B'))) | (((ch == 'c' | ch == 'C') | (ch == 'd' | ch == 'D')) | ((ch == 'e' | ch == 'E') | (ch == 'f' | ch == 'F')));
}

fn u64 is_identifier_start(u8 ch)
{
    u64 alphabetic = is_alphabetic(ch);
    u64 is_underscore = ch == '_';
    return alphabetic | is_underscore;
}

fn u64 is_identifier_ch(u8 ch)
{
    u64 identifier_start = is_identifier_start(ch);
    u64 decimal = is_decimal_digit(ch);
    return identifier_start | decimal;
}

fn Hash64 hash_byte(Hash64 source, u8 ch)
{
    source ^= ch;
    source *= fnv_prime;
    return source;
}

fn Hash64 hash_bytes(String bytes)
{
    u64 result = fnv_offset;
    for (u64 i = 0; i < bytes.length; i += 1)
    {
        result = hash_byte(result, bytes.pointer[i]);
    }

    return result;
}

fn Hash32 hash64_to_hash32(Hash64 hash64)
{
    Hash32 low = hash64 & 0xffff;
    Hash32 high = (hash64 >> 32) & 0xffff;
    Hash32 result = (high << 16) | low;
    return result;
}

fn u64 align_forward(u64 value, u64 alignment)
{
    u64 mask = alignment - 1;
    u64 result = (value + mask) & ~mask;
    return result;
}

fn u64 align_backward(u64 value, u64 alignment)
{
    u64 result = value & ~(alignment - 1);
    return result;
}

fn u8 is_power_of_two(u64 value)
{
    return (value & (value - 1)) == 0;
}

fn u8 first_bit_set_32(u32 value)
{
    auto result = (u8)__builtin_ffs((s32)value);
    result -= result != 0;
    return result;
}

fn u64 first_bit_set_64(u64 value)
{
    auto result = (u8) __builtin_ffs((s64)value);
    result -= result != 0;
    return result;
}

fn Hash32 hash32_fib_end(Hash32 hash)
{
    auto result = TRUNCATE(Hash32, ((hash + 1) * 11400714819323198485ull) >> 32);
    return result;
}

fn Hash32 hash64_fib_end(Hash64 hash)
{
    auto result = TRUNCATE(Hash32, ((hash + 1) * 11400714819323198485ull) >> 32);
    return result;
}
