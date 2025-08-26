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
    TypeReference type;
    ValueReference next;
    ValueId id;
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

UNION(AbiRegisterCount)
{
    struct
    {
        u32 gpr;
        u32 sse;
    } system_v;
};

typedef enum AbiKind : u8
{
    ABI_KIND_IGNORE,
    ABI_KIND_DIRECT,
    ABI_KIND_EXTEND,
    ABI_KIND_INDIRECT,
    ABI_KIND_INDIRECT_ALIASED,
    ABI_KIND_EXPAND,
    ABI_KIND_COERCE_AND_EXPAND,
    ABI_KIND_IN_ALLOCA,
} AbiKind;

STRUCT(AbiFlags)
{
    AbiKind kind;
};

STRUCT(AbiInformation)
{
    TypeReference semantic_type;
    TypeReference coerce_to_type;
    union
    {
        TypeReference type;
        TypeReference unpadded_coerce_and_expand_type;
    } padding;
    union
    {
        struct
        {
            u32 offset;
            u32 alignment;
        } direct;
        struct
        {
            u32 alignment;
            u32 address_space;
        } indirect;
        u32 alloca_field_index;
    } attributes;
    struct
    {
        u16 padding_in_reg: 1;
        u16 in_alloca_sret: 1;
        u16 in_alloca_indirect: 1;
        u16 indirect_by_value: 1;
        u16 indirect_realign: 1;
        u16 sret_after_this: 1;
        u16 in_reg: 1;
        u16 can_be_flattened: 1;
        u16 sign_extension: 1;
        AbiKind kind:3;
    } flags;
    u16 padding_argument_index;
    u16 abi_start;
    u16 abi_count;
};

static_assert(alignof(AbiInformation) == alignof(TypeReference));

STRUCT(TypeFunction)
{
    TypeReference* semantic_types; // This hides inside the same allocation AbiInformation* abi_informations;
    TypeReference* abi_types;
    AbiRegisterCount register_count;
    u16 semantic_argument_count;
    u16 abi_argument_count;
    CallingConvention calling_convention;
    bool is_variable_argument;
};

static inline TypeReference get_semantic_return_type(TypeFunction* restrict function)
{
    return function->semantic_types[0];
}

static inline TypeReference get_semantic_argument_type(TypeFunction* restrict function, u16 semantic_argument_index)
{
    assert(semantic_argument_index < function->semantic_argument_count);
    return function->semantic_types[semantic_argument_index + 1];
}

static inline TypeReference get_abi_return_type(TypeFunction* restrict function)
{
    return function->abi_types[0];
}

static inline TypeReference get_abi_argument_type(TypeFunction* restrict function, u16 abi_argument_index)
{
    assert(abi_argument_index < function->abi_argument_count);
    return function->abi_types[abi_argument_index + 1];
}

static inline AbiInformation* restrict get_abi_informations(TypeFunction* restrict function)
{
    return (AbiInformation*)(function->semantic_types + function->semantic_argument_count);
}

static inline AbiInformation* restrict get_return_abi_information(TypeFunction* restrict function)
{
    return &get_abi_informations(function)[0];
}

static inline AbiInformation* restrict get_argument_abi_information(TypeFunction* restrict function, u16 semantic_argument_index)
{
    assert(semantic_argument_index < function->semantic_argument_count);
    return &get_abi_informations(function)[semantic_argument_index + 1];
}

STRUCT(Type)
{
    union
    {
        TypeInteger integer;
        TypeFloat fp;
        TypeFunction function;
    };
    StringReference name;
    ScopeReference scope;
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
reference_offset_functions(Argument, argument, UNIT_ARENA_COMPILE_UNIT)

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

static inline TypeReference type_reference_from_pointer(CompileUnit* restrict unit, Type* type)
{
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let arena_byte_pointer = (u8*)type_arena;
    let arena_position = type_arena->position;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena_position;
    let type_byte_pointer = (u8*)type;
    assert(type_byte_pointer > arena_bottom && type_byte_pointer < arena_top);
    let diff = type_byte_pointer - (arena_bottom + sizeof(Arena));
    assert(diff % sizeof(Type) == 0);
    assert(diff < UINT32_MAX);
    diff /= sizeof(Type);
    return (TypeReference) {
        .v = diff + 1,
    };
}

static inline TypeReference type_reference_from_index(CompileUnit* restrict unit, u32 type_index)
{
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let byte_offset = type_index * sizeof(Type);
    let arena_byte_pointer = (u8*)type_arena;
    let arena_position = type_arena->position;
    assert(sizeof(Arena) + byte_offset + sizeof(Type) < arena_position);
    return (TypeReference) {
        .v = type_index + 1,
    };
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

TypeReference get_void_type(CompileUnit* restrict unit);
TypeReference get_noreturn_type(CompileUnit* restrict unit);
TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed);
