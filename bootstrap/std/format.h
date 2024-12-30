#pragma once

#include <std/base.h>

fn String format_string(String buffer, const char* format, ...);
fn String format_string_va(String buffer, const char* format, va_list args);
