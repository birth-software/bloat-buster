#pragma once

#include <lib.h>

typedef enum ValueId
{
    VALUE_ID_DISCARD,
} ValueId;

STRUCT(Value)
{
    ValueId id;
    Value* next;
};

typedef enum TypeId
{
    TYPE_ID_VOID,
} TypeId;

STRUCT(Type)
{
    TypeId id;
    Type* next;
};

typedef enum ScopeId
{
    SCOPE_ID_GLOBAL,
    SCOPE_ID_FILE,
    SCOPE_ID_FUNCTION,
    SCOPE_ID_BLOCK,
} ScopeId;

STRUCT(Scope)
{
    ScopeId id;
};

STRUCT(File)
{
    str content;
    str path;
    Scope scope;
    File* next;
};

STRUCT(CompileUnit)
{
    Arena* arena;
    Type* free_types;
    Type* free_values;
    File* files;
    u8 cache_padding[CACHE_LINE_GUESS - 4 * sizeof(u64)];
};

void compile_unit(StringSlice paths);
bool compiler_is_single_threaded(void);
bool compiler_main(int argc, const char* argv[], char** envp);
