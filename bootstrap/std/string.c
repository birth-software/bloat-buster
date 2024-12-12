#include <std/string.h>

s32 string_first_ch(String string, u8 ch)
{
    s32 result = -1;
    for (u64 i = 0; i < string.length; i += 1)
    {
        if (string.pointer[i] == ch)
        {
            result = i;
            break;
        }
    }

    return result;
}

s64 string_last_ch(String string, u8 ch)
{
    s64 result = -1;
    u64 i = string.length;
    while (i > 0)
    {
        i -= 1;
        if (string.pointer[i] == ch)
        {
            result = cast_to(s64, u64, i);
            break;
        }
    }

    return result;
}

u8 string_starts_with(String string, String start)
{
    u8 result = 0;

    if (likely(start.length <= string.length))
    {
        if (unlikely(start.pointer == string.pointer))
        {
            result = 1;
        }
        else
        {
            u64 i;
            for (i = 0; i < start.length; i += 1)
            {
                auto start_ch = start.pointer[i];
                auto string_ch = string.pointer[i];
                if (unlikely(string_ch != start_ch))
                {
                    break;
                }
            }

            result = i == start.length;
        }
    }

    return result;
}

u8 string_ends_with(String string, String end)
{
    u8 result = 0;

    if (likely(end.length <= string.length))
    {
        u64 i;
        u64 offset = string.length - end.length;
        for (i = 0; i < end.length; i += 1)
        {
            auto start_ch = end.pointer[i];
            auto string_ch = string.pointer[i + offset];
            if (unlikely(string_ch != start_ch))
            {
                break;
            }
        }

        result = i == end.length;
    }

    return result;
}

u64 string_first_ocurrence(String string, String substring)
{
    s32 result = UINT64_MAX;

    if (substring.length < string.length)
    {
        for (u64 i = 0; i < string.length; i += 1)
        {
            if ((string.length - i) < substring.length)
            {
                break;
            }

            auto s = s_get_slice(u8, string, i, i + substring.length);
            if (s_equal(s, substring))
            {
                result = i;
                break;
            }
        }
    }
    else if (unlikely(substring.length == string.length))
    {
        if (unlikely(string.pointer == substring.pointer))
        {
            result = 0;
        }
        else if (memcmp(string.pointer, substring.pointer, substring.length) == 0)
        {
            result = 0;
        }
    }

    return result;
}

u64 string_last_ocurrence(String string, String substring)
{
    trap();
}
