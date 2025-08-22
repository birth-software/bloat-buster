#pragma once

#include <lib.h>

typedef u32 RawReference;

typedef enum CallingConvention : u8
{
    CALLING_CONVENTION_C,
    CALLING_CONVENTION_COUNT,
} CallingConvention;

typedef enum ValueId : u8
{
    VALUE_ID_DISCARD,
} ValueId;

typedef enum TypeId : u8
{
    TYPE_ID_VOID,
} TypeId;

typedef enum ScopeId : u8
{
    SCOPE_ID_GLOBAL,
    SCOPE_ID_FILE,
    SCOPE_ID_FUNCTION,
    SCOPE_ID_BLOCK,
} ScopeId;

STRUCT(ScopeReference)
{
    RawReference v;
};

STRUCT(FileReference)
{
    RawReference v;
};

STRUCT(TypeReference)
{
    RawReference v;
};

STRUCT(ValueReference)
{
    RawReference v;
};

STRUCT(GlobalReference)
{
    RawReference v;
};

STRUCT(TopLevelDeclarationReference)
{
    RawReference v;
};

STRUCT(Value)
{
    ValueId id;
    ValueReference next;
};

STRUCT(Type)
{
    TypeId id;
    TypeReference next;
};

STRUCT(Scope)
{
    ScopeReference parent;
    ScopeId id;
};

STRUCT(File)
{
    str content;
    str path;
    Scope scope;
    FileReference next;
};

STRUCT(TopLevelWhen)
{
    TopLevelDeclarationReference first_taken;
    TopLevelDeclarationReference first_non_taken;
    ValueReference condition;
};

typedef enum TopLevelDeclarationId : u8
{
    TOP_LEVEL_DECLARATION_TYPE,
    TOP_LEVEL_DECLARATION_GLOBAL,
    TOP_LEVEL_DECLARATION_WHEN,
} TopLevelDeclarationId;

STRUCT(TopLevelDeclaration)
{
    union
    {
        TypeReference type;
        GlobalReference global;
        TopLevelWhen when;
    };
    TopLevelDeclarationReference next;
    TopLevelDeclarationId id;
};

typedef enum UnitArenaKind
{
    UNIT_ARENA_COMPILE_UNIT,
    UNIT_ARENA_TYPE,
    UNIT_ARENA_VALUE,
    UNIT_ARENA_COUNT,
} UnitArenaKind;

STRUCT(CompileUnit)
{
    Scope scope;
    TypeReference free_types;
    ValueReference free_values;
};

static inline Arena* unit_arena(CompileUnit* unit, UnitArenaKind kind)
{
    Arena* arena = (Arena*)unit - 1;
    let result = (Arena*)((u8*)arena + ((s64)kind * arena->reserved_size));
    return result;
}

static inline ScopeReference scope_offset_from_pointer(CompileUnit* restrict unit, Scope* scope)
{
    let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
    let scope_byte_pointer = (u8*)scope;
    let arena_byte_pointer = (u8*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;
    assert(scope_byte_pointer > arena_bottom && scope_byte_pointer < arena_top);
    let sub = scope_byte_pointer - arena_byte_pointer;
    assert(sub < UINT32_MAX);
    return (ScopeReference) {
        .v = (u32)(sub + 1),
    };
}

static FileReference file_offset_from_pointer(CompileUnit* restrict unit, File* restrict file)
{
    let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
    let file_byte_pointer = (u8*)file;
    let arena_byte_pointer = (u8*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;
    assert(file_byte_pointer > arena_bottom && file_byte_pointer < arena_top);
    let sub = file_byte_pointer - arena_byte_pointer;
    assert(sub < UINT32_MAX);
    return (FileReference) {
        .v = (u32)(sub + 1),
    };
}


void compile_unit(StringSlice paths);
bool compiler_is_single_threaded(void);
bool compiler_main(int argc, const char* argv[], char** envp);
