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
    TYPE_ID_NORETURN,
    TYPE_ID_INTEGER,
    TYPE_ID_FLOAT,
    TYPE_ID_FUNCTION,
    TYPE_ID_ENUM,
    TYPE_ID_POINTER,
    TYPE_ID_OPAQUE,
    TYPE_ID_ARRAY,
    TYPE_ID_STRUCT,
    TYPE_ID_UNION,
    TYPE_ID_BITS,
    TYPE_ID_VECTOR,
    TYPE_ID_ENUM_ARRAY,

    TYPE_ID_COUNT,
} TypeId;

typedef enum ScopeId : u8
{
    SCOPE_ID_GLOBAL,
    SCOPE_ID_FILE,
    SCOPE_ID_FUNCTION,
    SCOPE_ID_BLOCK,
} ScopeId;

STRUCT(StringReference)
{
    RawReference v;
};

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

STRUCT(VariableReference)
{
    RawReference v;
};

STRUCT(ArgumentReference)
{
    RawReference v;
};

STRUCT(Value)
{
    ValueId id;
    ValueReference next;
};

STRUCT(TypeInteger)
{
    u64 bit_count;
    bool is_signed;
};

typedef enum TypeFloat : u8
{
    TYPE_FLOAT_F16,
    TYPE_FLOAT_BF16,
    TYPE_FLOAT_F32,
    TYPE_FLOAT_F64,
    TYPE_FLOAT_F128,
    TYPE_FLOAT_COUNT,
} TypeFloat;

STRUCT(Type)
{
    union
    {
        TypeInteger integer;
        TypeFloat fp;
    };
    StringReference name;
    ScopeReference scope;
    TypeReference next;
    TypeId id;
    bool analyzed;
};

STRUCT(Variable)
{
    StringReference name;
    ValueReference storage;
    TypeReference type;
    ScopeReference scope;
    u32 line;
    u32 column;
};

STRUCT(Argument)
{
    Variable variable;
    ArgumentReference next;
    u32 index;
};

STRUCT(Scope)
{
    ScopeReference parent;
    ScopeId id;
};

STRUCT(File)
{
    str content;
    StringReference path;
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
    UNIT_ARENA_TOKEN,
    UNIT_ARENA_STRING,
    UNIT_ARENA_FILE_CONTENT,
    UNIT_ARENA_TYPE,
    UNIT_ARENA_VALUE,
    UNIT_ARENA_COUNT,
} UnitArenaKind;

STRUCT(CompileUnit)
{
    Scope scope;
    FileReference files;
    TypeReference free_types;
    ValueReference free_values;
};

static inline Arena* unit_arena(CompileUnit* unit, UnitArenaKind kind)
{
    Arena* arena = (Arena*)unit - 1;
    let result = (Arena*)((u8*)arena + ((s64)kind * arena->reserved_size));
    return result;
}

#define reference_offset_functions(O, o, AU) \
static inline O ## Reference o ## _reference_from_pointer(CompileUnit* restrict unit, O* restrict o) \
{\
    let arena = unit_arena(unit, AU);\
    let o ## _byte_pointer = (u8*)o;\
    let arena_byte_pointer = (u8*)arena;\
    let arena_bottom = arena_byte_pointer;\
    let arena_top = arena_byte_pointer + arena->position;\
    assert(o ## _byte_pointer > arena_bottom && o ## _byte_pointer < arena_top);\
    let sub = o ## _byte_pointer - arena_byte_pointer;\
    assert(sub < UINT32_MAX);\
    return (O ## Reference) {\
        .v = (u32)(sub + 1),\
    };\
}\
static inline O* restrict o ## _pointer_from_reference(CompileUnit* restrict unit, O ## Reference o_reference) \
{\
    assert(o_reference.v != 0);\
    let arena = unit_arena(unit, AU);\
    let arena_byte_pointer = (u8*)arena;\
    let arena_bottom = arena_byte_pointer;\
    let arena_top = arena_byte_pointer + arena->position;\
    let o ## _byte_pointer = arena_byte_pointer + (o_reference.v - 1);\
    assert(o ## _byte_pointer > arena_bottom && o ## _byte_pointer < arena_top);\
    let o = (O* restrict)o ## _byte_pointer; \
    return o;\
}

reference_offset_functions(Scope, scope, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(File, file, UNIT_ARENA_COMPILE_UNIT)

static inline StringReference string_reference_from_string(CompileUnit* restrict unit, str s)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;
    assert((arena_bottom < s.pointer) & (arena_top > s.pointer));
    let string_top = s.pointer + s.length;
    assert(string_top <= arena_top);
    let length_pointer = (u32*)s.pointer - 1;
    let length = *length_pointer;
    assert(s.length == length);

    let diff = (char*)length_pointer - arena_bottom;
    assert(diff < UINT32_MAX);
    return (StringReference) {
        .v = diff + 1,
    };
}

static inline str string_from_reference(CompileUnit* restrict unit, StringReference reference)
{
    assert(reference.v);

    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_position = arena->position;
    let arena_top = arena_byte_pointer + arena_position;

    let length_offset = reference.v - 1;
    assert(length_offset >= sizeof(Arena));
    assert(length_offset < arena_position);
    let length_byte_pointer = arena_bottom + length_offset;
    let length_pointer = (u32*)length_byte_pointer;
    let string_pointer = (char* restrict) (length_pointer + 1);
    u64 string_length = *length_pointer;
    return (str){ .pointer = string_pointer, .length = string_length };
}


// static FileReference file_offset_from_pointer(CompileUnit* restrict unit, File* restrict file)
// {
//     let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
//     let file_byte_pointer = (u8*)file;
//     let arena_byte_pointer = (u8*)arena;
//     let arena_bottom = arena_byte_pointer;
//     let arena_top = arena_byte_pointer + arena->position;
//     assert(file_byte_pointer > arena_bottom && file_byte_pointer < arena_top);
//     let sub = file_byte_pointer - arena_byte_pointer;
//     assert(sub < UINT32_MAX);
//     return (FileReference) {
//         .v = (u32)(sub + 1),
//     };
// }

void compile_unit(StringSlice paths);
bool compiler_is_single_threaded(void);
bool compiler_main(int argc, const char* argv[], char** envp);

StringReference allocate_string(CompileUnit* restrict unit, str s);
StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s);

TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed);
