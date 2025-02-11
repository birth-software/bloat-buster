#pragma once

STRUCT(StringFormatter)
{
    String buffer;
    u64 index;
};

fn void formatter_append(StringFormatter* formatter, const char* format, ...);
fn void formatter_append_string(StringFormatter* formatter, String string);
fn void formatter_append_character(StringFormatter* formatter, u8 ch);
fn String format_string(String buffer, const char* format, ...);
fn String format_string_va(String buffer, const char* format, va_list args);
