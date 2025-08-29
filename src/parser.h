#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

TopLevelDeclarationReference parse(CompileUnit* restrict unit, File* file, TokenList tl);
