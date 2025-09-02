#pragma once

#include <lib.h>
#include <llvm-c/Types.h>
#include <llvm-c/Error.h>
#include <llvm-c/TargetMachine.h>

typedef u32 RawReference;
#define is_ref_valid(x) !!((x).v)
#define ref_eq(a, b) (((typeof(a))(a)).v == ((typeof(a))(b)).v)
#define todo() trap()

STRUCT(SourceLocation)
{
    u32 line_number_offset;
    u32 line_byte_offset;
    u32 column_offset;
};

static u32 location_get_line(SourceLocation location)
{
    return location.line_number_offset + 1;
}

static u32 location_get_column(SourceLocation location)
{
    return location.column_offset + 1;
}

typedef enum CallingConvention : u8
{
    CALLING_CONVENTION_C,
    // CALLING_CONVENTION_COUNT,
} CallingConvention;

typedef enum ResolvedCallingConvention : u8
{
    CALLING_CONVENTION_SYSTEM_V,
} ResolvedCallingConvention;

static ResolvedCallingConvention resolve_calling_convention(CallingConvention cc)
{
    switch (cc)
    {
        break; case CALLING_CONVENTION_C:
        {
            // TODO:
            return CALLING_CONVENTION_SYSTEM_V;
        }
        break; default: UNREACHABLE();
    }
}

typedef enum ValueKind : u8
{
    VALUE_KIND_RIGHT,
    VALUE_KIND_LEFT,
} ValueKind;


typedef enum ValueId : u8
{
    VALUE_ID_DISCARD,
    VALUE_ID_CONSTANT_INTEGER,
    VALUE_ID_FUNCTION,
    VALUE_ID_GLOBAL,
    VALUE_ID_LOCAL,
    VALUE_ID_UNRESOLVED_IDENTIFIER,

    VALUE_ID_UNARY_MINUS,
    VALUE_ID_UNARY_MINUS_INTEGER,
    VALUE_ID_UNARY_ADDRESS_OF,
    VALUE_ID_UNARY_BOOLEAN_NOT,
    VALUE_ID_UNARY_BITWISE_NOT,

    VALUE_ID_INTRINSIC_VALUE,
    VALUE_ID_INTRINSIC_TYPE,
    VALUE_ID_INTRINSIC_UNRESOLVED,

    VALUE_ID_CALL,

    VALUE_ID_BINARY_ADD,
    VALUE_ID_BINARY_SUB,
    VALUE_ID_BINARY_MULTIPLY,
    VALUE_ID_BINARY_DIVIDE,
    VALUE_ID_BINARY_REMAINDER,

    VALUE_ID_BINARY_ADD_INTEGER,

    VALUE_ID_BINARY_BITWISE_AND,
    VALUE_ID_BINARY_BITWISE_OR,
    VALUE_ID_BINARY_BITWISE_XOR,

    VALUE_ID_BINARY_BITWISE_SHIFT_LEFT,
    VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT,

    VALUE_ID_BINARY_COMPARE_EQUAL,
    VALUE_ID_BINARY_COMPARE_NOT_EQUAL,
    VALUE_ID_BINARY_COMPARE_LESS,
    VALUE_ID_BINARY_COMPARE_LESS_EQUAL,
    VALUE_ID_BINARY_COMPARE_GREATER,
    VALUE_ID_BINARY_COMPARE_GREATER_EQUAL,

    VALUE_ID_INTRINSIC_TRAP,
    VALUE_ID_INTRINSIC_EXTEND,
    VALUE_ID_INTRINSIC_INTEGER_MAX,
    VALUE_ID_INTRINSIC_TRUNCATE,

    VALUE_ID_REFERENCED_VARIABLE,
} ValueId;

static inline bool value_id_is_intrinsic(ValueId id)
{
    switch (id)
    {
        case VALUE_ID_INTRINSIC_VALUE:
        case VALUE_ID_INTRINSIC_TYPE:
        case VALUE_ID_INTRINSIC_UNRESOLVED:
            return 1;
        default:
            return 0;
    }
}

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
    SCOPE_ID_NONE,
    SCOPE_ID_GLOBAL,
    SCOPE_ID_FILE,
    SCOPE_ID_FUNCTION,
    SCOPE_ID_BLOCK,
} ScopeId;

#define Ref(T) T ## Reference
#define declare_ref(T) STRUCT(Ref(T)) { RawReference v; }

declare_ref(String);
declare_ref(Scope);
declare_ref(File);
declare_ref(Type);
declare_ref(Value);
declare_ref(ValueNode);
declare_ref(TypeNode);
declare_ref(TopLevelDeclaration);
declare_ref(Global);
declare_ref(Variable);
declare_ref(Argument);
declare_ref(Local);
declare_ref(Block);
declare_ref(Statement);

STRUCT(TypeList)
{
    TypeNodeReference first;
};

STRUCT(Scope)
{
    union
    {
        BlockReference block;
        GlobalReference function;
        FileReference file;
    };
    ScopeReference parent;
    TypeList types;
    SourceLocation location;
    ScopeId id;
    LLVMMetadataRef llvm;
};

typedef enum InlineBehavior : u8
{
    INLINE_DEFAULT,
    INLINE_ALWAYS,
    INLINE_NO,
    INLINE_HINT,
} InlineBehavior;

STRUCT(FunctionAttributes)
{
    InlineBehavior inline_behavior;
    bool is_naked;
};

STRUCT(ValueFunction)
{
    ScopeReference scope;
    ArgumentReference arguments;
    BlockReference block;
    FunctionAttributes attributes;
};

STRUCT(UnresolvedIdentifier)
{
    StringReference string;
    ScopeReference scope;
};

STRUCT(ValueNode)
{
    ValueReference item;
    ValueNodeReference next;
};

STRUCT(TypeNode)
{
    TypeReference item;
    TypeNodeReference next;
};

STRUCT(ValueList)
{
    ValueNodeReference first;
    u32 count;
};

STRUCT(ValueCall)
{
    ValueReference callable;
    ValueList arguments;
    TypeReference function_type;
};

STRUCT(Value)
{
    union
    {
        u64 integer;
        UnresolvedIdentifier unresolved_identifier;
        ValueFunction function;
        ValueReference unary;
        TypeReference unary_type;
        ValueReference binary[2];
        ValueCall call;
        VariableReference variable;
    };
    TypeReference type;
    ValueReference next;
    ValueId id;
    ValueKind kind;
    bool analyzed;
    LLVMValueRef llvm;
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

STRUCT(TypePointer)
{
    TypeReference element_type;
    TypeReference next;
};

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

static bool abi_can_have_coerce_to_type(AbiInformation* restrict abi)
{
    AbiKind kind = abi->flags.kind;
    return (kind == ABI_KIND_DIRECT) | (kind == ABI_KIND_EXTEND) | (kind == ABI_KIND_COERCE_AND_EXPAND);
}

static void abi_set_coerce_to_type(AbiInformation* restrict abi, TypeReference type_reference)
{
    assert(abi_can_have_coerce_to_type(abi));
    abi->coerce_to_type = type_reference;
}

static bool abi_can_have_padding_type(AbiInformation* restrict abi)
{
    AbiKind kind = abi->flags.kind;
    return ((kind == ABI_KIND_DIRECT) | (kind == ABI_KIND_EXTEND)) | ((kind == ABI_KIND_INDIRECT) | (kind == ABI_KIND_INDIRECT_ALIASED)) | (kind == ABI_KIND_EXPAND);
}

static void abi_set_padding_type(AbiInformation* restrict abi, TypeReference type_reference)
{
    assert(abi_can_have_padding_type(abi));
    abi->padding.type = type_reference;
}

static void abi_set_direct_offset(AbiInformation* restrict abi, u32 offset)
{
    assert((abi->flags.kind == ABI_KIND_DIRECT) || (abi->flags.kind == ABI_KIND_EXTEND));
    abi->attributes.direct.offset = offset;
}

static void abi_set_direct_alignment(AbiInformation* restrict abi, u32 alignment)
{
    assert((abi->flags.kind == ABI_KIND_DIRECT) || (abi->flags.kind == ABI_KIND_EXTEND));
    abi->attributes.direct.alignment = alignment;
}

static void abi_set_can_be_flattened(AbiInformation* restrict abi, bool value)
{
    assert(abi->flags.kind == ABI_KIND_DIRECT);
    abi->flags.can_be_flattened = value;
}


static inline TypeReference abi_get_coerce_to_type(AbiInformation* restrict abi)
{
    assert(abi_can_have_coerce_to_type(abi));
    return abi->coerce_to_type;
}

STRUCT(AbiSystemVClassifyArgumentTypeOptions)
{
    u32 available_gpr;
    bool is_named_argument;
    bool is_register_call;
};

STRUCT(AbiSystemVClassifyArgumentTypeResult)
{
    AbiInformation abi;
    AbiRegisterCount needed_registers;
};

STRUCT(AbiSystemVClassifyArgumentOptions)
{
    TypeReference type;
    u16 abi_start;
    bool is_named_argument;
    bool is_register_call;
};

static_assert(alignof(AbiInformation) == alignof(TypeReference));

STRUCT(TypeFunction)
{
    TypeReference* semantic_types; // This hides inside the same allocation AbiInformation* abi_informations;
    TypeReference* abi_types;
    AbiRegisterCount available_registers;
    FileReference file;
    u16 semantic_argument_count;
    u16 abi_argument_count;
    CallingConvention calling_convention;
    bool is_variable_argument;
    TypeReference next;
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

static inline AbiInformation* restrict get_abis(TypeFunction* restrict function)
{
    return (AbiInformation*)(function->semantic_types + function->semantic_argument_count);
}

static inline AbiInformation* restrict get_return_abi(TypeFunction* restrict function)
{
    return &get_abis(function)[0];
}

static inline AbiInformation* restrict get_argument_abi(TypeFunction* restrict function, u16 semantic_argument_index)
{
    assert(semantic_argument_index < function->semantic_argument_count);
    return &get_abis(function)[semantic_argument_index + 1];
}

STRUCT(Block)
{
    ScopeReference scope;
    LocalReference first_local;
    LocalReference last_local;
    StatementReference first_statement;
    bool analyzed;
};

typedef enum StatementId : u8
{
    STATEMENT_ID_RETURN,
    STATEMENT_ID_LOCAL,
    STATEMENT_ID_BLOCK,
    STATEMENT_ID_IF,
    STATEMENT_ID_WHEN,
    STATEMENT_ID_SWITCH,
    STATEMENT_ID_WHILE,
    STATEMENT_ID_FOR,
    STATEMENT_ID_EXPRESSION,
} StatementId;

static inline bool statement_is_block_like(StatementId id)
{
    switch (id)
    {
        break;
        case STATEMENT_ID_BLOCK:
        case STATEMENT_ID_IF:
        case STATEMENT_ID_WHEN:
        case STATEMENT_ID_SWITCH:
        case STATEMENT_ID_WHILE:
        case STATEMENT_ID_FOR:
        {
            return 1;
        }
        break; default:
        {
            return 0;
        }
    }
}

STRUCT(Branch)
{
    ValueReference condition;
    StatementReference taken_branch;
    StatementReference else_branch;
};

STRUCT(Statement)
{
    union
    {
        ValueReference value;
        Branch branch;
        BlockReference block;
        LocalReference local;
    };
    StatementReference next;
    SourceLocation location;
    StatementId id;
    bool analyzed;
};

STRUCT(TypeVector)
{
    TypeReference element_type;
    u32 element_count;
    TypeReference next;
    bool is_scalable;
};

typedef enum TypeKind : u8
{
    TYPE_KIND_ABI,
    TYPE_KIND_MEMORY,
} TypeKind;

STRUCT(Type)
{
    union
    {
        TypeInteger integer;
        TypeFloat fp;
        TypeFunction function;
        TypePointer pointer;
        TypeVector vector;
    };
    StringReference name;
    ScopeReference scope;
    TypeReference next;
    TypeId id;
    bool analyzed;
    struct
    {
        LLVMTypeRef abi;
        LLVMTypeRef memory;
        LLVMMetadataRef debug;
    } llvm;
};

static bool type_is_signed(Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let is_signed = type->integer.is_signed;
            return is_signed;
        }
        break; default: todo();
    }
}

STRUCT(Variable)
{
    StringReference name;
    ValueReference storage;
    TypeReference type;
    ScopeReference scope;
    SourceLocation location;
};

STRUCT(Argument)
{
    Variable variable;
    ArgumentReference next;
    u32 index;
};

STRUCT(Local)
{
    Variable variable;
    ValueReference initial_value;
    LocalReference next;
};

typedef enum Linkage : u8
{
    LINKAGE_INTERNAL,
    LINKAGE_EXTERNAL,
} Linkage;

STRUCT(Global)
{
    Variable variable;
    ValueReference initial_value;
    GlobalReference next;
    Linkage linkage;
    bool analyzed;
    bool generated;
};

STRUCT(File)
{
    str content;
    str path;
    str directory;
    str file_name;
    str name;
    ScopeReference scope;
    GlobalReference first_global;
    GlobalReference last_global;
    TopLevelDeclarationReference first_tld;
    FileReference next;
    LLVMMetadataRef handle;
    LLVMMetadataRef compile_unit;
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

typedef enum CompilePhase : u8
{
    COMPILE_PHASE_LEXER,
    COMPILE_PHASE_PARSER,
    COMPILE_PHASE_ANALYSIS,
    COMPILE_PHASE_LLVM_IR_GENERATION,
    COMPILE_PHASE_LLVM_IR_OPTIMIZATION,
    COMPILE_PHASE_LLVM_CODE_GENERATION,
    COMPILE_PHASE_LLVM_LINKER,
} CompilePhase;

typedef enum BuildMode : u8
{
    BUILD_MODE_DEBUG,
    BUILD_MODE_SIZE,
    BUILD_MODE_SPEED,
} BuildMode;

STRUCT(CompileUnit)
{
    FileReference first_file;
    FileReference last_file;
    ScopeReference scope;

    TypeReference first_pointer_type;
    TypeReference first_function_type;

    TypeReference free_types;
    ValueReference free_values;

    GlobalReference current_function;

    CompilePhase phase;

    str artifact_directory_path;
    str object_path;
    str artifact_path;
    ShowCallback* show_callback;
    const char* target_triple;
    BuildMode build_mode;
    bool has_debug_info;
    bool verbose;
};

static void unit_show(CompileUnit* restrict unit, str message)
{
    let show = unit->show_callback;
    if (likely(show))
    {
        show(unit, message);
    }
}

static inline Arena* unit_arena(CompileUnit* unit, UnitArenaKind kind)
{
    Arena* arena = (Arena*)unit - 1;
    let result = (Arena*)((u8*)arena + ((s64)kind * arena->reserved_size));
    return result;
}

static Arena* get_default_arena(CompileUnit* restrict unit)
{
    return unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
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
reference_offset_functions(Local, local, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(Global, global, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(Statement, statement, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(Block, block, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(TopLevelDeclaration, top_level_declaration, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(ValueNode, value_node, UNIT_ARENA_COMPILE_UNIT)
reference_offset_functions(Variable, variable, UNIT_ARENA_COMPILE_UNIT)

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
    assert(is_ref_valid(reference));

    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_position = arena->position;

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

static inline TypeReference type_reference_from_index(CompileUnit* restrict unit, u32 index)
{
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let byte_offset = index * sizeof(Type);
    let arena_position = type_arena->position;
    assert(sizeof(Arena) + byte_offset + sizeof(Type) <= arena_position);
    return (TypeReference) {
        .v = index + 1,
    };
}

static inline Type* type_pointer_from_reference(CompileUnit* restrict unit, TypeReference reference)
{
    assert(is_ref_valid(reference));
    let arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let index = reference.v - 1;
    let byte_offset = index * sizeof(Type);
    let arena_position = arena->position;
    assert(sizeof(Arena) + byte_offset + sizeof(Type) <= arena_position);
    let type = (Type*)((u8*)arena + sizeof(Arena) + byte_offset);
    return type;
}

static inline ValueReference value_reference_from_pointer(CompileUnit* restrict unit, Value* value)
{
    let value_arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let arena_byte_pointer = (u8*)value_arena;
    let arena_position = value_arena->position;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena_position;
    let value_byte_pointer = (u8*)value;
    assert(value_byte_pointer > arena_bottom && value_byte_pointer < arena_top);
    let diff = value_byte_pointer - (arena_bottom + sizeof(Arena));
    assert(diff % sizeof(Value) == 0);
    assert(diff < UINT32_MAX);
    diff /= sizeof(Value);
    return (ValueReference) {
        .v = diff + 1,
    };
}

static inline ValueReference value_reference_from_index(CompileUnit* restrict unit, u32 index)
{
    let value_arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let byte_offset = index * sizeof(Value);
    let arena_position = value_arena->position;
    assert(sizeof(Arena) + byte_offset + sizeof(Value) < arena_position);
    return (ValueReference) {
        .v = index + 1,
    };
}

static inline Value* value_pointer_from_reference(CompileUnit* restrict unit, ValueReference reference)
{
    assert(is_ref_valid(reference));
    let arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let index = reference.v - 1;
    let byte_offset = index * sizeof(Value);
    let arena_position = arena->position;
    assert(sizeof(Arena) + byte_offset + sizeof(Value) <= arena_position);
    let result = (Value*)((u8*)arena + sizeof(Arena) + byte_offset);
    return result;
}

static inline Type* new_types(CompileUnit* restrict unit, u32 type_count)
{
    let arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let types = arena_allocate(arena, Type, type_count);
    return types;
}

static Type* allocate_free_type(CompileUnit* restrict unit)
{
    let type_ref = unit->free_types;
    assert(is_ref_valid(type_ref));
    let type = type_pointer_from_reference(unit, type_ref);
    type->next = (TypeReference){};
    return type;
}

static inline Type* new_type(CompileUnit* restrict unit)
{
    return is_ref_valid(unit->free_types) ? allocate_free_type(unit) : new_types(unit, 1);
}

static inline Value* new_values(CompileUnit* restrict unit, u32 value_count)
{
    let arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let values = arena_allocate(arena, Value, value_count);
    return values;
}

static inline Value* new_value(CompileUnit* restrict unit)
{
    return new_values(unit, 1);
}

static inline Scope* restrict new_scope(CompileUnit* restrict unit)
{
    let arena = get_default_arena(unit);
    let scope = arena_allocate(arena, Scope, 1);
    return scope;
}

static u64 align_bit_count(u64 bit_count)
{
    let aligned_bit_count = MAX(next_power_of_two(bit_count), 8);
    assert((aligned_bit_count & (aligned_bit_count - 1)) == 0);
    return aligned_bit_count;
}

static u64 aligned_byte_count_from_bit_count(u64 bit_count)
{
    let aligned_bit_count = align_bit_count(bit_count);
    assert(aligned_bit_count % 8 == 0);
    return aligned_bit_count / 8;
}

static u64 get_byte_size(CompileUnit* restrict unit, Type* type_pointer)
{
    assert(unit->phase >= COMPILE_PHASE_ANALYSIS);

    switch (type_pointer->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type_pointer->integer.bit_count;
            let byte_count = aligned_byte_count_from_bit_count(bit_count);
            return byte_count;
        }
        break; default:
        {
            todo();
        }
    }
}

static u32 get_alignment(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type->integer.bit_count;
            let result = aligned_byte_count_from_bit_count(bit_count);
            assert(result == 1 || result == 2 || result == 4 || result == 8 || result == 16);
            return result;
        }
        break; default: todo();
    }
}

STRUCT(Address)
{
    LLVMValueRef pointer;
    Type* element_type;
    u32 alignment;
    LLVMValueRef offset;
};

bool compiler_is_single_threaded(void);
bool compiler_main(int argc, const char* argv[], char** envp);

u64 get_base_type_count();

StringReference allocate_string(CompileUnit* restrict unit, str s);
StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s);
StringReference allocate_and_join_string(CompileUnit* restrict unit, StringSlice slice);

TypeReference get_void_type(CompileUnit* restrict unit);
TypeReference get_noreturn_type(CompileUnit* restrict unit);
TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed);

AbiInformation abi_system_v_classify_return_type(CompileUnit* restrict unit, TypeReference type);
AbiSystemVClassifyArgumentTypeResult abi_system_v_classify_argument_type(CompileUnit* restrict unit, TypeReference type, AbiSystemVClassifyArgumentTypeOptions options);
AbiInformation abi_system_v_classify_argument(CompileUnit* restrict unit, AbiRegisterCount* restrict available_registers, TypeReference* abi_argument_type_buffer, AbiSystemVClassifyArgumentOptions options);

static TypeReference get_u1(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 1, 0);
}

static TypeReference get_u8(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 8, 0);
}

static TypeReference get_u16(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 16, 0);
}

static TypeReference get_u32(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 32, 0);
}

static TypeReference get_u64(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 64, 0);
}

static Global* get_current_function(CompileUnit* restrict unit)
{
    let current_function_ref = unit->current_function;
    if (!is_ref_valid(current_function_ref))
    {
        trap();
    }

    let current_function = global_pointer_from_reference(unit, current_function_ref);
    return current_function;
}

static Type* get_function_type_from_storage(CompileUnit* restrict unit, Global* function)
{
    let function_storage_ref = function->variable.storage;
    let function_storage = value_pointer_from_reference(unit, function_storage_ref);
    let function_pointer_type_ref = function_storage->type;
    assert(is_ref_valid(function_pointer_type_ref));
    let function_pointer_type = type_pointer_from_reference(unit, function_pointer_type_ref);
    assert(function_pointer_type->id == TYPE_ID_POINTER);
    let function_type_ref = function_pointer_type->pointer.element_type;
    assert(is_ref_valid(function_type_ref));
    let function_type = type_pointer_from_reference(unit, function_type_ref);
    assert(function_type->id == TYPE_ID_FUNCTION);

    return function_type;
}
