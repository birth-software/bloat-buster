#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

void parse(CompileUnit* restrict unit, File* file, TokenList tl);
