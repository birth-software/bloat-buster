#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

void parse_file(CompileUnit* restrict unit, str path, str content, TokenList tl);
