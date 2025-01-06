#pragma once

#if _MSC_VER
extern u64 _lzcnt_u64(u64);
extern u64 _tzcnt_u64(u64);
#endif

fn u8 log2_alignment(u64 alignment)
{
    assert(alignment != 0);
    assert((alignment & (alignment - 1)) == 0);
    u64 left = (sizeof(alignment) * 8) - 1;
#if _MSC_VER
    let_cast(u64, right, _lzcnt_u64(alignment));
#else
    let_cast(u64, right, __builtin_clzll(alignment));
#endif
    let_cast(u8, result, left - right);
    return result;
}

fn u128 u128_from_u64(u64 n)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    u128 result = { .low = n };
    return result;
#else
    return n;
#endif
}

fn u64 u64_from_u128(u128 n)
{
#if defined (__TINYC__) || defined(_MSC_VER)
    return n.low;
#else
    return (u64)n;
#endif
}

fn u128 u128_shift_right(u128 value, u16 n)
{
#if defined (__TINYC__) || defined(_MSC_VER)
    u128 result = {};

    if (n < 128)
    {
        if (n >= 64)
        {
            // If n >= 64, only the high part contributes to the low part
            result.low = value.high >> (n - 64);
            result.high = 0;
        }
        else
        {
            // Standard case: n < 64
            result.low = (value.low >> n) | (value.high << (64 - n));
            result.high = value.high >> n;
        }
    } 

    return result;
#else
    return value >> n;
#endif
}

fn u128 u128_shift_left(u128 value, u16 n)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    u128 result = {};

    if (n < 128)
    {
        if (n >= 64)
        {
            // If n >= 64, only the low part contributes to the high part
            result.high = value.low << (n - 64);
            result.low = 0;
        }
        else
        {
            // Standard case: n < 64
            result.high = (value.high << n) | (value.low >> (64 - n));
            result.low = value.low << n;
        }
    }

    return result;
#else
    return value << n;
#endif
}

fn u128 u128_u64_or(u128 a, u64 b)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    a.low |= b;
    return a;
#else
    return a | b;
#endif
}

fn u128 u128_u64_add(u128 a, u64 b)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    u128 result;
    
    // Add the lower 64 bits and check for overflow
    result.low = a.low + b;
    u64 carry = (result.low < a.low) ? 1 : 0;

    // Add the carry to the upper 64 bits
    result.high = a.high + carry;

    return result;
#else
    return a + b;
#endif
}

// Multiply two u128 values
fn u128 u128_u64_mul(u128 a, u64 b)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    u128 result = {};

    // Compute low and high parts of the product
    u64 low_low = (a.low & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
    u64 low_high = (a.low >> 32) * (b & 0xFFFFFFFF);
    u64 high_low = (a.low & 0xFFFFFFFF) * (b >> 32);
    u64 high_high = (a.low >> 32) * (b >> 32);

    // Combine partial products for the lower 64 bits
    u64 carry = (low_low >> 32) + (low_high & 0xFFFFFFFF) + (high_low & 0xFFFFFFFF);
    result.low = (low_low & 0xFFFFFFFF) | (carry << 32);

    // Add carry from lower to the high product
    result.high = a.high * b + (low_high >> 32) + (high_low >> 32) + (carry >> 32) + high_high;

    return result;
#else
    return a * b;
#endif
}

fn u64 u128_shift_right_by_64(u128 n)
{
#if defined(__TINYC__) || defined(_MSC_VER)
    return n.high;
#else
    return n >> 64;
#endif
}

// Lehmer's generator
// https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/
global_variable u128 rn_state;
fn u64 generate_random_number()
{
    rn_state = u128_u64_mul(rn_state, 0xda942042e4dd58b5);
    return u128_shift_right_by_64(rn_state);
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

fn u64 absolute_int(s64 n)
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
    return (is_decimal_digit(ch) | (((ch == 'a') | (ch == 'A')) | ((ch == 'b') | (ch == 'B')))) | ((((ch == 'c') | (ch == 'C')) | ((ch == 'd') | (ch == 'D'))) | (((ch == 'e') | (ch == 'E')) | ((ch == 'f') | (ch == 'F'))));
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
#if _MSC_VER
    DWORD result_dword;
    u8 result_u8 = _BitScanForward(&result_dword, value);
    unused(result_u8);
    let_cast(u8, result, result_dword);
#else
    let(result, (u8)__builtin_ffs((s32)value));
#endif
    result -= result != 0;
    return result;
}

fn u64 first_bit_set_64(u64 value)
{
#if _MSC_VER
    DWORD result_dword;
    u8 result_u8 = _BitScanForward64(&result_dword, value);
    unused(result_u8);
    let_cast(u8, result, result_dword);
#else
    let(result, (u8) __builtin_ffs((s64)value));
#endif
    result -= result != 0;
    return result;
}

fn Hash32 hash32_fib_end(Hash32 hash)
{
    let(result, TRUNCATE(Hash32, ((hash + 1) * 11400714819323198485ull) >> 32));
    return result;
}

fn Hash32 hash64_fib_end(Hash64 hash)
{
    let(result, TRUNCATE(Hash32, ((hash + 1) * 11400714819323198485ull) >> 32));
    return result;
}
