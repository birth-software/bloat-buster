#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

void parse_file(CompileUnit* restrict unit, File* file, TokenList tl);
