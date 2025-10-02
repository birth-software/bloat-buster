#pragma once

#include <lib.h>
#include <llvm-c/Types.h>
#include <llvm-c/Error.h>
#include <llvm-c/TargetMachine.h>

typedef u32 RawReference;
#define is_ref_valid(x) !!((x).v)
#define ref_eq(a, b) (((typeof(a))(a)).v == ((typeof(a))(b)).v)

#define todo() todo_internal(unit, __LINE__, S(__FUNCTION__), S(__FILE__))

STRUCT(SourceLocation)
{
    u32 line_number_offset;
    u32 line_byte_offset;
    u32 column_offset;
};

typedef enum CallingConvention : u8
{
    CALLING_CONVENTION_C,
    // CALLING_CONVENTION_COUNT,
} CallingConvention;

typedef enum ResolvedCallingConvention : u8
{
    RESOLVED_CALLING_CONVENTION_SYSTEM_V,
    RESOLVED_CALLING_CONVENTION_WIN64,
    RESOLVED_CALLING_CONVENTION_AARCH64,
} ResolvedCallingConvention;

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
    VALUE_ID_ARGUMENT,
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
    VALUE_ID_BINARY_SUB_INTEGER,
    VALUE_ID_BINARY_MULTIPLY_INTEGER,
    VALUE_ID_BINARY_DIVIDE_INTEGER_SIGNED,
    VALUE_ID_BINARY_DIVIDE_INTEGER_UNSIGNED,
    VALUE_ID_BINARY_REMAINDER_INTEGER_SIGNED,
    VALUE_ID_BINARY_REMAINDER_INTEGER_UNSIGNED,

    VALUE_ID_BINARY_BITWISE_AND,
    VALUE_ID_BINARY_BITWISE_OR,
    VALUE_ID_BINARY_BITWISE_XOR,

    VALUE_ID_BINARY_BITWISE_SHIFT_LEFT,
    VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT,
    VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_LOGICAL,
    VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_ARITHMETIC,

    VALUE_ID_BINARY_COMPARE_EQUAL,
    VALUE_ID_BINARY_COMPARE_NOT_EQUAL,
    VALUE_ID_BINARY_COMPARE_LESS,
    VALUE_ID_BINARY_COMPARE_LESS_EQUAL,
    VALUE_ID_BINARY_COMPARE_GREATER,
    VALUE_ID_BINARY_COMPARE_GREATER_EQUAL,

    VALUE_ID_BINARY_COMPARE_EQUAL_INTEGER,
    VALUE_ID_BINARY_COMPARE_NOT_EQUAL_INTEGER,
    VALUE_ID_BINARY_COMPARE_LESS_INTEGER,
    VALUE_ID_BINARY_COMPARE_LESS_EQUAL_INTEGER,
    VALUE_ID_BINARY_COMPARE_GREATER_INTEGER,
    VALUE_ID_BINARY_COMPARE_GREATER_EQUAL_INTEGER,

    VALUE_ID_INTRINSIC_TRAP,
    VALUE_ID_INTRINSIC_EXTEND,
    VALUE_ID_INTRINSIC_INTEGER_MAX,
    VALUE_ID_INTRINSIC_TRUNCATE,

    VALUE_ID_REFERENCED_VARIABLE,

    VALUE_ID_POINTER_DEREFERENCE,
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

STRUCT(AbiExtendOptions)
{
    TypeReference semantic_type;
    TypeReference type;
    bool is_signed;
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
    } x86_64;
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
    STATEMENT_ID_ASSIGNMENT,
} StatementId;

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
        ValueReference assignment[2];
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
    u32 use_count;
    struct
    {
        LLVMTypeRef abi;
        LLVMTypeRef memory;
        LLVMMetadataRef debug;
    } llvm;
};

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

typedef enum CpuArch : u8
{
    CPU_ARCH_UNKNOWN,
    CPU_ARCH_X86_64,
    CPU_ARCH_AARCH64,
} CpuArch;

typedef enum OperatingSystem : u8
{
    OPERATING_SYSTEM_UNKNOWN,
    OPERATING_SYSTEM_LINUX,
    OPERATING_SYSTEM_MACOS,
    OPERATING_SYSTEM_WINDOWS,
} OperatingSystem;

STRUCT(Target)
{
    CpuArch cpu;
    OperatingSystem os;
};

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
    str target_triple;
    u32 pointer_size;
    u32 pointer_alignment;
    Target target;
    BuildMode build_mode;
    bool has_debug_info;
    bool verbose;
};

STRUCT(Address)
{
    LLVMValueRef pointer;
    Type* element_type;
    u32 alignment;
    LLVMValueRef offset;
};

STRUCT(Win64ClassifyOptions)
{
    u32* free_sse;
    bool is_return_type;
    bool is_vector_call;
    bool is_register_call;
};

STRUCT(AbiDirectOptions)
{
    TypeReference semantic_type;
    TypeReference type;
    TypeReference padding;
    u32 offset;
    u32 alignment;
    bool cannot_be_flattened;
};

typedef enum Aarch64AbiKind : u8
{
    AARCH64_ABI_KIND_AAPCS,
    AARCH64_ABI_KIND_DARWIN_PCS,
    AARCH64_ABI_KIND_WIN64,
    AARCH64_ABI_KIND_AAPCS_SOFT,
} Aarch64AbiKind;

typedef enum TypeEvaluationKind : u8
{
    TYPE_EVALUATION_KIND_SCALAR,
    TYPE_EVALUATION_KIND_AGGREGATE,
    TYPE_EVALUATION_KIND_COMPLEX,
} TypeEvaluationKind;

#define reference_offset_function_ref(O, o) O ## Reference o ## _reference_from_pointer(CompileUnit* restrict unit, O* restrict o)
#define reference_offset_function_ptr(O, o) O* restrict o ## _pointer_from_reference(CompileUnit* restrict unit, O ## Reference o_reference)

#define reference_offset_function_decl(O, o) \
    PUB_DECL reference_offset_function_ref(O, o);\
    PUB_DECL reference_offset_function_ptr(O, o)

reference_offset_function_decl(Scope, scope);
reference_offset_function_decl(File, file);
reference_offset_function_decl(Argument, argument);
reference_offset_function_decl(Local, local);
reference_offset_function_decl(Global, global);
reference_offset_function_decl(Statement, statement);
reference_offset_function_decl(Block, block);
reference_offset_function_decl(TopLevelDeclaration, top_level_declaration);
reference_offset_function_decl(ValueNode, value_node);
reference_offset_function_decl(Variable, variable);

PUB_DECL StringReference string_reference_from_string(CompileUnit* restrict unit, str s);
PUB_DECL str string_from_reference(CompileUnit* restrict unit, StringReference reference);
PUB_DECL TypeReference type_reference_from_pointer(CompileUnit* restrict unit, Type* type);
PUB_DECL TypeReference type_reference_from_index(CompileUnit* restrict unit, u32 index);
PUB_DECL Type* type_pointer_from_reference(CompileUnit* restrict unit, TypeReference reference);
PUB_DECL ValueReference value_reference_from_pointer(CompileUnit* restrict unit, Value* value);
PUB_DECL ValueReference value_reference_from_index(CompileUnit* restrict unit, u32 index);
PUB_DECL Value* value_pointer_from_reference(CompileUnit* restrict unit, ValueReference reference);
PUB_DECL Type* new_types(CompileUnit* restrict unit, u32 type_count);
PUB_DECL Type* allocate_free_type(CompileUnit* restrict unit);
PUB_DECL Type* new_type(CompileUnit* restrict unit);
PUB_DECL Value* new_values(CompileUnit* restrict unit, u32 value_count);
PUB_DECL Value* new_value(CompileUnit* restrict unit);
PUB_DECL Scope* restrict new_scope(CompileUnit* restrict unit);
PUB_DECL u64 align_bit_count(u64 bit_count);
PUB_DECL u64 aligned_byte_count_from_bit_count(u64 bit_count);
PUB_DECL TypeReference get_u1(CompileUnit* restrict unit);
PUB_DECL TypeReference get_u8(CompileUnit* restrict unit);
PUB_DECL TypeReference get_u16(CompileUnit* restrict unit);
PUB_DECL TypeReference get_u32(CompileUnit* restrict unit);
PUB_DECL TypeReference get_u64(CompileUnit* restrict unit);
PUB_DECL Type* get_function_type_from_storage(CompileUnit* restrict unit, Global* function);
[[noreturn]] PUB_DECL void todo_internal(CompileUnit* unit, u32 line, str function_name, str file_path);

PUB_DECL Global* get_current_function(CompileUnit* restrict unit);
PUB_DECL u64 get_byte_size(CompileUnit* restrict unit, Type* type_pointer);
PUB_DECL u64 get_bit_size(CompileUnit* restrict unit, Type* restrict type);
PUB_DECL bool type_is_signed(CompileUnit* restrict unit, Type* type);
PUB_DECL bool type_is_record(Type* restrict type);
PUB_DECL u32 get_alignment(CompileUnit* restrict unit, Type* type);
PUB_DECL ResolvedCallingConvention resolve_calling_convention(Target target, CallingConvention cc);

PUB_DECL void abi_set_padding_type(AbiInformation* restrict abi, TypeReference type_reference);
PUB_DECL void abi_set_direct_offset(AbiInformation* restrict abi, u32 offset);
PUB_DECL void abi_set_direct_alignment(AbiInformation* restrict abi, u32 alignment);
PUB_DECL void abi_set_can_be_flattened(AbiInformation* restrict abi, bool value);
PUB_DECL TypeReference abi_get_coerce_to_type(AbiInformation* restrict abi);
PUB_DECL TypeReference abi_get_padding_type(AbiInformation* restrict abi);

PUB_DECL bool value_id_is_intrinsic(ValueId id);

PUB_DECL u32 location_get_line(SourceLocation location);
PUB_DECL u32 location_get_column(SourceLocation location);

PUB_DECL bool compiler_is_single_threaded(void);

PUB_DECL u64 get_base_type_count();

PUB_DECL StringReference allocate_string(CompileUnit* restrict unit, str s);
PUB_DECL StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s);
PUB_DECL StringReference allocate_and_join_string(CompileUnit* restrict unit, StringSlice slice);

PUB_DECL TypeReference get_void_type(CompileUnit* restrict unit);
PUB_DECL TypeReference get_noreturn_type(CompileUnit* restrict unit);
PUB_DECL TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed);

PUB_DECL AbiInformation abi_system_v_classify_return_type(CompileUnit* restrict unit, TypeReference type);
PUB_DECL AbiSystemVClassifyArgumentTypeResult abi_system_v_classify_argument_type(CompileUnit* restrict unit, TypeReference type, AbiSystemVClassifyArgumentTypeOptions options);
PUB_DECL AbiInformation abi_system_v_classify_argument(CompileUnit* restrict unit, AbiRegisterCount* restrict available_registers, TypeReference* abi_argument_type_buffer, AbiSystemVClassifyArgumentOptions options);

PUB_DECL AbiInformation win64_classify_type(CompileUnit* restrict unit, TypeReference type_reference, Win64ClassifyOptions options);
PUB_DECL AbiInformation aarch64_classify_return_type(CompileUnit* restrict unit, TypeReference type_reference, bool is_variadic_function, Aarch64AbiKind kind);

PUB_DECL AbiInformation abi_get_ignore(TypeReference semantic_type);
PUB_DECL AbiInformation abi_get_direct(CompileUnit* restrict unit, AbiDirectOptions options);
PUB_DECL AbiInformation abi_get_extend(CompileUnit* restrict unit, AbiExtendOptions options);

PUB_DECL void unit_show(CompileUnit* restrict unit, str message);
PUB_DECL Arena* unit_arena(CompileUnit* unit, UnitArenaKind kind);
PUB_DECL Arena* get_default_arena(CompileUnit* restrict unit);
PUB_DECL TypeReference get_semantic_return_type(TypeFunction* restrict function);
PUB_DECL AbiInformation* restrict get_return_abi(TypeFunction* restrict function);
PUB_DECL Aarch64AbiKind get_aarch64_abi_kind(OperatingSystem os);
PUB_DECL TypeReference get_semantic_argument_type(TypeFunction* restrict function, u16 semantic_argument_index);
PUB_DECL void abi_set_coerce_to_type(AbiInformation* restrict abi, TypeReference type_reference);
PUB_DECL bool type_is_aggregate_for_abi (CompileUnit* restrict unit, Type* type);
PUB_DECL bool type_is_promotable_integer_for_abi(CompileUnit* restrict unit, Type* type);
PUB_DECL bool type_is_integral_or_enumeration(CompileUnit* restrict unit, TypeReference type_reference);
PUB_DECL TypeReference get_abi_return_type(TypeFunction* restrict function);
PUB_DECL TypeReference get_abi_argument_type(TypeFunction* restrict function, u16 abi_argument_index);
PUB_DECL AbiInformation* restrict get_abis(TypeFunction* restrict function);
PUB_DECL TypeEvaluationKind get_type_evaluation_kind(CompileUnit* restrict unit, Type* type);
PUB_DECL AbiInformation* restrict get_argument_abi(TypeFunction* restrict function, u16 semantic_argument_index);

PUB_DECL bool statement_is_block_like(StatementId id);
