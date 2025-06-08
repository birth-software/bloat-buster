#pragma once

#include <lib.hpp>
#include <llvm-c/TargetMachine.h>
#define report_error() trap()

enum class Command
{
    compile,
    test,
    count,
};

enum class BuildMode
{
    debug_none,
    debug,
    soft_optimize,
    optimize_for_speed,
    optimize_for_size,
    aggressively_optimize_for_speed,
    aggressively_optimize_for_size,
    count,
};

global_variable constexpr u64 build_mode_count = (u64)BuildMode::count;

fn String build_mode_to_string(BuildMode build_mode)
{
    switch (build_mode)
    {
        case_to_name(BuildMode, debug_none);
        case_to_name(BuildMode, debug);
        case_to_name(BuildMode, soft_optimize);
        case_to_name(BuildMode, optimize_for_speed);
        case_to_name(BuildMode, optimize_for_size);
        case_to_name(BuildMode, aggressively_optimize_for_speed);
        case_to_name(BuildMode, aggressively_optimize_for_size);
        case BuildMode::count: unreachable();
    }
}

fn bool build_mode_is_optimized(BuildMode build_mode)
{
    switch (build_mode)
    {
        case BuildMode::debug_none:
        case BuildMode::debug:
            return false;
        case BuildMode::soft_optimize:
        case BuildMode::optimize_for_speed:
        case BuildMode::optimize_for_size:
        case BuildMode::aggressively_optimize_for_speed:
        case BuildMode::aggressively_optimize_for_size:
            return true;
        case BuildMode::count: unreachable();
    }
}

enum class ValueKind
{
    right,
    left,
};

enum class CPUArchitecture
{
    x86_64,
};

enum class OperatingSystem
{
    linux_,
};

struct Type;
struct Value;
struct Local;
struct Global;
struct Block;
struct Statement;
struct Variable;
struct Argument;
struct Scope;
struct MacroDeclaration;

struct DirectAttributes
{
    u32 offset;
    u32 alignment;
};

struct IndirectAttributes
{
    u32 alignment;
    u32 address_space;
};

enum class AbiKind : u8
{
    ignore,
    direct,
    extend,
    indirect,
    indirect_aliased,
    expand,
    coerce_and_expand,
    in_alloca,
};

struct AbiFlags
{
    AbiKind kind;
    bool padding_in_reg;
    bool in_alloca_sret;
    bool in_alloca_indirect;
    bool indirect_by_value;
    bool indirect_realign;
    bool sret_after_this;
    bool in_reg;
    bool can_be_flattened;
    bool sign_extension;
};

struct AbiInformation
{
    Type* semantic_type;
    Type* coerce_to_type;
    union
    {
        Type* type;
        Type* unpadded_coerce_and_expand_type;
    } padding;
    u16 padding_argument_index;
    union
    {
        DirectAttributes direct;
        IndirectAttributes indirect;
        u32 alloca_field_index;
    } attributes;
    AbiFlags flags;
    u16 abi_start;
    u16 abi_count;

    inline void set_sret_after_this(bool sret_after_this)
    {
        assert(flags.kind == AbiKind::indirect);
        flags.sret_after_this = sret_after_this;
    }

    inline void set_indirect_realign(bool realign)
    {
        assert(flags.kind == AbiKind::indirect);
        flags.indirect_realign = realign;
    }

    inline void set_indirect_by_value(bool by_value)
    {
        assert(flags.kind == AbiKind::indirect);
        flags.indirect_by_value = by_value;
    }

    inline void set_indirect_align(u32 alignment)
    {
        assert(flags.kind == AbiKind::indirect || flags.kind == AbiKind::indirect_aliased);
        attributes.indirect.alignment = alignment;
    }

    inline bool can_have_coerce_to_type()
    {
        switch (flags.kind)
        {
            case AbiKind::direct:
            case AbiKind::extend:
            case AbiKind::coerce_and_expand:
                return true;
            default:
                return false;
        }
    }

    inline void set_coerce_to_type(Type* coerce_to_type)
    {
        assert(can_have_coerce_to_type());
        this->coerce_to_type = coerce_to_type;
    }

    inline Type* get_coerce_to_type()
    {
        assert(can_have_coerce_to_type());
        return coerce_to_type;
    }

    inline void set_padding_type(Type* padding_type)
    {
        assert(can_have_padding_type());
        padding = {
            .type = padding_type,
        };
    }

    inline bool can_have_padding_type()
    {
        switch (flags.kind)
        {
            case AbiKind::direct:
            case AbiKind::extend:
            case AbiKind::indirect:
            case AbiKind::indirect_aliased:
            case AbiKind::expand:
                return true;
            default:
                return false;
        }
    }

    inline Type* get_padding_type()
    {
        return can_have_padding_type() ? padding.type : 0;
    }

    inline void set_direct_offset(u32 offset)
    {
        assert(flags.kind == AbiKind::direct || flags.kind == AbiKind::extend);
        attributes.direct.offset = offset;
    }

    inline void set_direct_alignment(u32 alignment)
    {
        assert(flags.kind == AbiKind::direct || flags.kind == AbiKind::extend);
        attributes.direct.alignment = alignment;
    }

    inline void set_can_be_flattened(bool can_be_flattened)
    {
        assert(flags.kind == AbiKind::direct);
        flags.can_be_flattened = can_be_flattened;
    }

    inline bool get_can_be_flattened()
    {
        return flags.can_be_flattened;
    }
};

struct Target
{
    CPUArchitecture cpu;
    OperatingSystem os;
};

fn Target target_get_native()
{
    return {
        .cpu = CPUArchitecture::x86_64,
        .os = OperatingSystem::linux_,
    };
}

fn bool target_compare(Target a, Target b)
{
    auto is_same_cpu = a.cpu == b.cpu;
    auto is_same_os = a.os == b.os;

    return is_same_cpu && is_same_os;
}

struct Compile
{
    String relative_file_path;
    BuildMode build_mode;
    bool has_debug_info;
    bool silent;
};

#define base_cache_dir "bb-cache"

enum class CallingConvention
{
    c,
    count,
};

enum class ResolvedCallingConvention
{
    system_v,
    win64,
    count,
};

fn ResolvedCallingConvention resolve_calling_convention(CallingConvention cc)
{
    switch (cc)
    {
        case CallingConvention::c:
            // TODO:
            return ResolvedCallingConvention::system_v;
        case CallingConvention::count: unreachable();
    }
}

enum class InlineBehavior
{
    normal,
    always_inline,
    no_inline,
    inline_hint,
};

struct FunctionAttributes
{
    InlineBehavior inline_behavior;
    bool naked;
};

enum class TypeId
{
    void_type,
    noreturn,
    forward_declaration,
    integer,
    function,
    pointer,
    array,
    enumerator,
    structure,
    bits,
    alias,
    union_type,
    unresolved,
    vector,
    floating_point,
    enum_array,
    opaque,
};

struct TypeInteger
{
    u64 bit_count;
    bool is_signed;
};

struct AbiRegisterCountSystemV
{
    u32 gpr;
    u32 sse;
};

union AbiRegisterCount
{
    AbiRegisterCountSystemV system_v;
};

struct TypeFunctionBase
{
    Type* semantic_return_type;
    Slice<Type*> semantic_argument_types;
    CallingConvention calling_convention;
    bool is_variable_arguments;
};

struct TypeFunctionAbi
{
    Slice<Type*> abi_argument_types;
    Type* abi_return_type;
    AbiRegisterCount available_registers;
    Slice<AbiInformation> argument_abis;
    AbiInformation return_abi;
};

struct TypeFunction
{
    TypeFunctionBase base;
    TypeFunctionAbi abi;
    Type* next;
};

struct TypePointer
{
    Type* element_type;
    Type* next;
};

struct TypeArray 
{
    Type* element_type;
    u64 element_count;
    Type* next;
};

struct UnresolvedEnumField
{
    String name;
    Value* value;
};

struct EnumField
{
    String name;
    u64 value;
};

struct UnresolvedTypeEnum
{
    Slice<UnresolvedEnumField> fields;
    Type* backing_type;
    u32 line;
    bool implicit_backing_type;
    Type* resolved_type;
};

struct TypeEnum
{
    Slice<EnumField> fields;
    Type* backing_type;
    LLVMValueRef enum_to_string_function;
    LLVMValueRef string_to_enum_function;
    Type* string_to_enum_struct_type;
    Global* name_array;
    u32 line;
};

struct Field
{
    String name;
    Type* type;
    u64 offset;
    u32 line;
};

struct TypeStruct
{
    Slice<Field> fields;
    u64 byte_size;
    u32 byte_alignment;
    u32 line;
    bool is_slice;
    Type* next;
};

struct TypeBits
{
    Slice<Field> fields;
    Type* backing_type;
    u32 line;
    bool is_implicit_backing_type;
};

struct TypeAlias
{
    Type* type;
    Scope* scope;
    u32 line;
};

struct UnionField
{
    Type* type;
    String name;
    u32 line;
};

struct TypeUnion
{
    Slice<UnionField> fields;
    u64 byte_size;
    u32 byte_alignment;
    u32 line;
    u32 biggest_field;
};

struct LLVMType
{
    LLVMTypeRef abi;
    LLVMTypeRef memory;
    LLVMMetadataRef debug;
};

struct TypeEnumArray
{
    Type* enum_type;
    Type* element_type;
    Type* next;
};

struct Type
{
    union
    {
        TypeInteger integer;
        TypeFunction function;
        TypePointer pointer;
        TypeArray array;
        TypeEnum enumerator;
        TypeStruct structure;
        TypeBits bits;
        TypeAlias alias;
        TypeUnion union_type;
        TypeEnumArray enum_array;
    };
    TypeId id;
    String name;
    Type* next;
    Scope* scope;
    LLVMType llvm;
};

fn u32 align_bit_count(u32 bit_count)
{
    auto aligned_bit_count = MAX(8, next_power_of_two(bit_count));
    assert(aligned_bit_count % 8 == 0);
    return aligned_bit_count;
}

fn u32 aligned_byte_count_from_bit_count(u32 bit_count)
{
    auto aligned_bit_count = align_bit_count(bit_count);
    return aligned_bit_count / 8;
}

fn u64 get_byte_size(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer: 
            {
                auto byte_count = aligned_byte_count_from_bit_count(type->integer.bit_count);
                assert(byte_count == 1 || byte_count == 2 || byte_count == 4 || byte_count == 8 || byte_count == 16);
                return byte_count;
            } break;
        case TypeId::pointer:
            {
                return 8;
            } break;
        case TypeId::array:
            {
                auto element_type = type->array.element_type;
                auto element_size = get_byte_size(element_type);
                auto element_count = type->array.element_count;
                auto result = element_size * element_count;
                return result;
            } break;
        case TypeId::structure:
            {
                auto result = type->structure.byte_size;
                return result;
            } break;
        case TypeId::enumerator:
            {
                auto result = get_byte_size(type->enumerator.backing_type);
                return result;
            } break;
        case TypeId::bits:
            {
                auto result = get_byte_size(type->bits.backing_type);
                return result;
            } break;
        case TypeId::alias:
            {
                auto result = get_byte_size(type->alias.type);
                return result;
            } break;
        case TypeId::union_type:
            {
                auto result = type->union_type.byte_size;
                return result;
            } break;
        case TypeId::enum_array:
            {
                auto enum_type = type->enum_array.enum_type;
                assert(enum_type->id == TypeId::enumerator);
                auto element_count = enum_type->enumerator.fields.length;
                auto element_type = type->enum_array.element_type;
                auto element_size = get_byte_size(element_type);

                auto result = element_size * element_count;
                return result;
            } break;
        default: trap();
    }
}

fn u32 get_byte_alignment(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer:
            {
                auto aligned_byte_count = aligned_byte_count_from_bit_count(type->integer.bit_count);
                assert(aligned_byte_count == 1 || aligned_byte_count == 2 || aligned_byte_count == 4 || aligned_byte_count == 8 || aligned_byte_count == 16);
                return aligned_byte_count;
            } break;
        case TypeId::array:
            {
                auto element_type = type->array.element_type;
                auto result = get_byte_alignment(element_type);
                return result;
            } break;
        case TypeId::structure:
            {
                auto result = type->structure.byte_alignment;
                return result;
            } break;
        case TypeId::enumerator:
            {
                auto result = get_byte_alignment(type->enumerator.backing_type);
                return result;
            } break;
        case TypeId::pointer:
        case TypeId::opaque:
            {
                return 8;
            } break;
        case TypeId::bits:
            {
                auto result = get_byte_alignment(type->bits.backing_type);
                return result;
            } break;
        case TypeId::union_type:
            {
                return type->union_type.byte_alignment;
            } break;
        case TypeId::alias:
            {
                return get_byte_alignment(type->alias.type);
            } break;
        case TypeId::enum_array:
            {
                return get_byte_alignment(type->enum_array.element_type);
            } break;
        case TypeId::function:
            {
                return 1;
            } break;
        default: trap();
    }
}

fn u64 get_bit_size(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer: return type->integer.bit_count;
        case TypeId::enumerator: return get_bit_size(type->enumerator.backing_type);
        case TypeId::alias: return get_bit_size(type->alias.type);
        case TypeId::array: return get_byte_size(type->array.element_type) * type->array.element_count * 8;
        case TypeId::pointer: return 64;
        case TypeId::structure: return type->structure.byte_size * 8;
        case TypeId::union_type: return type->union_type.byte_size * 8;
        case TypeId::enum_array: return get_byte_size(type->enum_array.element_type) * type->enum_array.enum_type->enumerator.fields.length * 8;
        default: trap();
    }
}

struct TypeList
{
    Type* first;
    Type* last;
};

enum class ScopeKind
{
    global,
    function,
    local,
    for_each,
    macro_declaration,
    macro_instantiation,
};

struct Scope
{
    TypeList types;
    Scope* parent;
    u32 line;
    u32 column;
    ScopeKind kind;
    LLVMMetadataRef llvm;
};

struct SourceLocation
{
    Scope* scope;
    u32 line;
    u32 column;
};

enum class StatementId
{
    local,
    expression,
    return_st,
    assignment,
    if_st,
    block,
    while_st,
    switch_st,
    for_each,
    break_st,
    continue_st,
};

enum class StatementAssignmentId
{
    assign,
    assign_add,
    assign_sub,
    assign_mul,
    assign_div,
    assign_rem,
    assign_shift_left,
    assign_shift_right,
    assign_and,
    assign_or,
    assign_xor,
};

struct StatementAssignment
{
    Value* left;
    Value* right;
    StatementAssignmentId id;
};

struct StatementIf
{
    Value* condition;
    Statement* if_statement;
    Statement* else_statement;
};

struct StatementWhile
{
    Value* condition;
    Block* block;
};

enum class ClauseDiscriminantId
{
    single,
    range,
};

struct ClauseDiscriminant
{
    union
    {
        Value* single;
        Value* range[2];
    };
    ClauseDiscriminantId id;
};

struct StatementSwitchClause
{
    Slice<ClauseDiscriminant> values;
    Block* block;
    LLVMBasicBlockRef basic_block;
};

struct StatementSwitch
{
    Value* discriminant;
    Slice<StatementSwitchClause> clauses;
};

enum class ForEachKind
{
    slice,
    range,
};

struct StatementForEach
{
    Local* first_local;
    Local* last_local;
    Slice<ValueKind> left_values;
    Slice<Value*> right_values;
    Statement* predicate;
    Scope scope;
    ForEachKind kind;
};

struct Statement
{
    union
    {
        Local* local;
        Value* expression;
        Value* return_st;
        StatementAssignment assignment;
        StatementIf if_st;
        Block* block;
        StatementWhile while_st;
        StatementSwitch switch_st;
        StatementForEach for_each;
    };
    Statement* next;
    StatementId id;
    u32 line;
    u32 column;
};

struct Block
{
    Local* first_local;
    Local* last_local;
    Statement* first_statement;
    Scope scope;
};

enum class ValueId
{
    infer_or_ignore,
    forward_declared_function,
    function,
    constant_integer,
    unary,
    binary,
    unary_type,
    variable_reference,
    macro_reference,
    macro_instantiation,
    call,
    global,
    array_initialization,
    array_expression,
    slice_expression,
    enum_literal,
    trap,
    field_access,
    string_literal,
    va_start,
    va_arg,
    aggregate_initialization,
    undefined,
    unreachable,
    zero,
    select,
    string_to_enum,
    local,
    argument,
    build_mode,
    has_debug_info,
    field_parent_pointer,
};

struct ValueConstantInteger
{
    u64 value;
    bool is_signed;
};

struct FunctionLLVM
{
    LLVMBasicBlockRef return_block;
    LLVMValueRef return_alloca;
};

struct ValueFunction
{
    Slice<Argument> arguments;
    Scope scope;
    Block* block;
    FunctionAttributes attributes;
    FunctionLLVM llvm;
};

enum class UnaryId
{
    minus,
    plus,
    ampersand,
    exclamation,
    enum_name,
    extend,
    truncate,
    pointer_cast,
    int_from_enum,
    int_from_pointer,
    va_end,
    bitwise_not,
    dereference,
    pointer_from_int,
    enum_from_int,
    leading_zeroes,
    trailing_zeroes,
};

struct ValueUnary
{
    Value* value;
    UnaryId id;
};

enum class UnaryTypeId
{
    align_of,
    byte_size,
    enum_values,
    integer_max,
};

struct ValueUnaryType
{
    Type* type;
    UnaryTypeId id;
};

enum class BinaryId
{
    add,
    sub,
    mul,
    div,
    rem,
    bitwise_and,
    bitwise_or,
    bitwise_xor,
    shift_left,
    shift_right,
    compare_equal,
    compare_not_equal,
    compare_greater,
    compare_less,
    compare_greater_equal,
    compare_less_equal,
    logical_and,
    logical_or,
    logical_and_shortcircuit,
    logical_or_shortcircuit,
    max,
    min,
};

struct ValueBinary
{
    Value* left;
    Value* right;
    BinaryId id;
};

struct ValueCall
{
    Value* callable;
    Slice<Value*> arguments;
    Type* function_type;
};

struct ValueArrayInitialization
{
    Slice<Value*> values;
    bool is_constant;
};

struct ValueArrayExpression
{
    Value* array_like;
    Value* index;
};

struct ValueFieldAccess
{
    Value* aggregate;
    String field_name;
};

struct ValueSliceExpression
{
    Value* array_like;
    Value* start;
    Value* end;
};

struct ValueVaArg
{
    Value* va_list;
    Type* type;
};

struct AggregateInitializationElement
{
    String name;
    Value* value;
    u32 line;
    u32 column;
};

struct ValueAggregateInitialization
{
    Slice<AggregateInitializationElement> elements;
    Scope* scope;
    bool is_constant;
    bool zero;
};

struct ValueSelect
{
    Value* condition;
    Value* true_value;
    Value* false_value;
};

struct ValueStringToEnum
{
    Type* type;
    Value* string;
};

enum class ConstantArgumentId
{
    value,
    type,
};

struct ConstantArgument
{
    String name;
    union
    {
        Type* type;
        Value* value;
    };
    ConstantArgumentId id;
};

struct MacroDeclaration
{
    Slice<Argument> arguments;
    Slice<ConstantArgument> constant_arguments;
    TypeList types;
    Type* return_type;
    Block* block;
    String name;
    Scope scope;
    MacroDeclaration* next;

    bool is_generic()
    {
        return constant_arguments.length != 0;
    }
};

struct MacroInstantiation
{
    MacroDeclaration* declaration;
    Global* instantiation_function;
    Slice<Argument> declaration_arguments;
    Slice<Value*> instantiation_arguments;
    Slice<ConstantArgument> constant_arguments;
    Type* return_type;
    Block* block;
    Scope scope;
    u32 line;
    u32 column;
    LLVMValueRef return_alloca;
    LLVMBasicBlockRef return_block;
};

struct FieldParentPointer
{
    Value* pointer;
    String name;
};

fn bool variable_is_constant(Value* value);

struct Value
{
    union
    {
        ValueConstantInteger constant_integer;
        ValueFunction function;
        ValueUnary unary;
        ValueBinary binary;
        Variable* variable_reference;
        ValueUnaryType unary_type;
        ValueCall call;
        ValueArrayInitialization array_initialization;
        ValueArrayExpression array_expression;
        String enum_literal;
        ValueFieldAccess field_access;
        ValueSliceExpression slice_expression;
        String string_literal;
        ValueVaArg va_arg;
        ValueAggregateInitialization aggregate_initialization;
        ValueSelect select;
        ValueStringToEnum string_to_enum;
        MacroDeclaration* macro_reference;
        MacroInstantiation macro_instantiation;
        FieldParentPointer field_parent_pointer;
    };
    Type* type;
    ValueId id;
    ValueKind kind;
    LLVMValueRef llvm;

    bool is_constant()
    {
        switch (id)
        {
            case ValueId::constant_integer: 
            case ValueId::enum_literal:
            case ValueId::unary_type:
            case ValueId::string_literal:
            case ValueId::zero:
                return true;
            case ValueId::unary:
                return unary.value->is_constant();
            case ValueId::binary:
                return binary.left->is_constant() && binary.right->is_constant();
            case ValueId::field_access:
            case ValueId::array_expression:
            case ValueId::call:
            case ValueId::select:
            case ValueId::slice_expression:
                return false;
            case ValueId::variable_reference:
                {
                    return variable_is_constant(this);
                } break;
            case ValueId::array_initialization:
                {
                    assert(type); // This asserts that the value type has been analyzed and `is_constant` was properly set 
                    return array_initialization.is_constant;
                } break;
            case ValueId::aggregate_initialization:
                {
                    assert(type); // This asserts that the value type has been analyzed and `is_constant` was properly set 
                    return aggregate_initialization.is_constant;
                } break;
            default: trap();
        }
    }
};

struct Variable
{
    Value* storage;
    Value* initial_value;
    Type* type;
    Scope* scope;
    String name;
    u32 line;
    u32 column;
};

fn bool variable_is_constant(Value* value)
{
    assert(value->id == ValueId::variable_reference);
    auto* variable = value->variable_reference;

    switch (value->kind)
    {
        case ValueKind::left:
            {
                switch (variable->scope->kind)
                {
                    case ScopeKind::global:
                        return true;
                    default:
                        return false;
                }
            } break;
        case ValueKind::right:
            return false;
    }
}

enum class Linkage
{
    internal,
    external,
};

struct Global
{
    Variable variable;
    Linkage linkage;
    bool emitted;
    Global* next;
};

struct Local
{
    Variable variable;
    Local* next;
};

struct Argument
{
    Variable variable;
    u32 index;
};

struct LLVMIntrinsicId
{
    u32 n;
};

enum class IntrinsicIndex
{
    clz,
    ctz,
    smax,
    smin,
    trap,
    umax,
    umin,
    va_start,
    va_end,
    va_copy,
    count,
};

global_variable String intrinsic_names[] = {
    string_literal("llvm.ctlz"),
    string_literal("llvm.cttz"),
    string_literal("llvm.smax"),
    string_literal("llvm.smin"),
    string_literal("llvm.trap"),
    string_literal("llvm.umax"),
    string_literal("llvm.umin"),
    string_literal("llvm.va_start"),
    string_literal("llvm.va_end"),
    string_literal("llvm.va_copy"),
};

static_assert(array_length(intrinsic_names) == (u64)IntrinsicIndex::count);

struct LLVMAttributeId
{
    u32 n;
};

enum class AttributeIndex
{
    align,
    alwaysinline,
    byval,
    dead_on_unwind,
    inlinehint,
    inreg,
    naked,
    noalias,
    noinline,
    noreturn,
    nounwind,
    signext,
    sret,
    writable,
    zeroext,

    count,
};

global_variable String attribute_names[] = {
    string_literal("align"),
    string_literal("alwaysinline"),
    string_literal("byval"),
    string_literal("dead_on_unwind"),
    string_literal("inlinehint"),
    string_literal("inreg"),
    string_literal("naked"),
    string_literal("noalias"),
    string_literal("noinline"),
    string_literal("noreturn"),
    string_literal("nounwind"),
    string_literal("signext"),
    string_literal("sret"),
    string_literal("writable"),
    string_literal("zeroext"),
};

static_assert(array_length(attribute_names) == (u64)AttributeIndex::count);

struct ModuleLLVM
{
    LLVMContextRef context;
    LLVMModuleRef module;
    LLVMBuilderRef builder;
    LLVMDIBuilderRef di_builder;
    LLVMMetadataRef file;
    LLVMTargetMachineRef target_machine;
    LLVMTargetDataRef target_data;
    LLVMMetadataRef compile_unit;
    LLVMTypeRef pointer_type;
    LLVMTypeRef void_type;
    LLVMIntrinsicId intrinsic_table[(u64)IntrinsicIndex::count];
    LLVMAttributeId attribute_table[(u64)AttributeIndex::count];
    LLVMValueRef memcmp;
    LLVMMetadataRef inlined_at;
    LLVMBasicBlockRef continue_block;
    LLVMBasicBlockRef exit_block;
    u32 debug_tag;
};

struct Module
{
    Arena* arena;
    String content;
    u64 offset;
    u64 line_offset;
    u64 line_character_offset;

    Type* first_pointer_type;
    Type* first_slice_type;
    Type* first_pair_struct_type;
    Type* first_array_type;
    Type* first_enum_array_type;
    Type* first_function_type;

    Type* va_list_type;
    Type* build_mode_enum;

    Value* void_value;
    Global* first_global;
    Global* last_global;
    Global* current_function;
    MacroDeclaration* first_macro_declaration;
    MacroDeclaration* last_macro_declaration;
    MacroDeclaration* current_macro_declaration;
    MacroInstantiation* current_macro_instantiation;

    ModuleLLVM llvm;
    Scope scope;

    String name;
    String path;
    String executable;

    Slice<String> objects;
    Slice<String> library_directories;
    Slice<String> library_names;
    Slice<String> library_paths;
    bool link_libc = true;
    bool link_libcpp = false;

    Target target;
    BuildMode build_mode;
    bool has_debug_info;
    bool silent;
};

constexpr u64 i128_offset = 64 * 2;
constexpr u64 void_offset = i128_offset + 2;

fn Type* integer_type(Module* module, TypeInteger integer)
{
    assert(integer.bit_count);
    assert(integer.bit_count <= 64 || integer.bit_count == 128);
    if (integer.is_signed)
    {
        assert(integer.bit_count > 1);
    }
    auto index = integer.bit_count == 128 ? (i128_offset + integer.is_signed) : (integer.bit_count - 1 + (64 * integer.is_signed));
    auto* result_type = module->scope.types.first + index;
    assert(result_type->id == TypeId::integer);
    assert(result_type->integer.bit_count == integer.bit_count);
    assert(result_type->integer.is_signed == integer.is_signed);
    return result_type;
}

fn Type* void_type(Module* module)
{
    return module->scope.types.first + void_offset;
}

fn Type* noreturn_type(Module* module)
{
    return void_type(module) + 1;
}

fn Type* uint1(Module* module)
{
    return integer_type(module, { .bit_count = 1, .is_signed = false });
}

fn Type* uint8(Module* module)
{
    return integer_type(module, { .bit_count = 8, .is_signed = false });
}

fn Type* uint32(Module* module)
{
    return integer_type(module, { .bit_count = 32, .is_signed = false });
}

fn Type* uint64(Module* module)
{
    return integer_type(module, { .bit_count = 64, .is_signed = false });
}

fn Type* sint32(Module* module)
{
    return integer_type(module, { .bit_count = 32, .is_signed = true });
}

fn Type* sint64(Module* module)
{
    return integer_type(module, { .bit_count = 64, .is_signed = true });
}

struct Options
{
    String content;
    String path;
    String executable;
    String name;
    Slice<String> objects;
    Slice<String> library_paths;
    Slice<String> library_names;
    Slice<String> library_directories;
    bool link_libcpp;
    Target target;
    BuildMode build_mode;
    bool has_debug_info;
    bool silent;
};

fn Type* type_allocate_init(Module* module, Type type)
{
    auto* result = &arena_allocate<Type>(module->arena, 1)[0];
    *result = type;

    auto scope = type.scope;
    assert(scope);

    if (scope->types.last)
    {
        assert(scope->types.first);
        scope->types.last->next = result;
        scope->types.last = result;
    }
    else
    {
        assert(!scope->types.first);
        scope->types.first = result;
        scope->types.last = result;
    }

    return result;
}

fn Value* new_value(Module* module)
{
    auto* result = &arena_allocate<Value>(module->arena, 1)[0];
    return result;
}

fn Slice<Value*> new_value_array(Module* module, u64 count)
{
    auto result = arena_allocate<Value*>(module->arena, count);
    return result;
}

fn Slice<Type*> new_type_array(Module* module, u64 count)
{
    auto result = arena_allocate<Type*>(module->arena, count);
    return result;
}

fn Global* new_global(Module* module)
{
    auto* result = &arena_allocate<Global>(module->arena, 1)[0];

    if (module->last_global)
    {
        module->last_global->next = result;
        module->last_global = result;
    }
    else
    {
        assert(!module->first_global);
        module->first_global = result;
        module->last_global = result;
    }

    return result;
}

fn Type* get_pointer_type(Module* module, Type* element_type)
{
    auto last_pointer_type = module->first_pointer_type;
    while (last_pointer_type)
    {
        assert(last_pointer_type->id == TypeId::pointer);
        if (last_pointer_type->pointer.element_type == element_type)
        {
            return last_pointer_type;
        }

        if (!last_pointer_type->pointer.next)
        {
            break;
        }

        last_pointer_type = last_pointer_type->pointer.next;
    }

    String name_parts[] = {
        string_literal("&"),
        element_type->name,
    };

    auto result = type_allocate_init(module, {
        .pointer = {
            .element_type = element_type,
        },
        .id = TypeId::pointer,
        .name = arena_join_string(module->arena, array_to_slice(name_parts)),
        .scope = element_type->scope,
    });

    if (last_pointer_type)
    {
        assert(module->first_pointer_type);
        last_pointer_type->pointer.next = result;
    }
    else
    {
        assert(!module->first_pointer_type);
        module->first_pointer_type = result;
    }

    return result;
}

fn bool is_slice(Type* type)
{
    switch (type->id)
    {
        case TypeId::structure:
            {
                return type->structure.is_slice;
            }
        default: return false;
    }
}

fn Type* get_slice_type(Module* module, Type* element_type)
{
    Type* slice_type = module->first_slice_type;

    if (slice_type)
    {
        while (1)
        {
            assert(is_slice(slice_type));
            assert(slice_type->structure.fields.length == 2);
            auto* pointer_type = slice_type->structure.fields[0].type;
            assert(pointer_type->id == TypeId::pointer);
            auto* candidate_element_type = pointer_type->pointer.element_type;
            if (candidate_element_type == element_type)
            {
                return slice_type;
            }

            if (!slice_type->structure.next)
            {
                break;
            }

            slice_type = slice_type->structure.next;
        }
    }

    Type* last_slice_type = slice_type;
    auto fields = arena_allocate<Field>(module->arena, 2);
    fields[0] = {
        .name = string_literal("pointer"),
        .type = get_pointer_type(module, element_type),
        .offset = 0,
        .line = 0,
    };
    fields[1] = {
        .name = string_literal("length"),
        .type = uint64(module),
        .offset = 8,
        .line = 0,
    };
    String name_parts[] = {
        string_literal("[]"),
        element_type->name,
    };

    auto result = type_allocate_init(module, {
        .structure = {
            .fields = fields,
            .byte_size = 16,
            .byte_alignment = 8,
            .line = 0,
            .is_slice = true,
        },
        .id = TypeId::structure,
        .name = arena_join_string(module->arena, array_to_slice(name_parts)),
        .scope = element_type->scope,
    });

    if (last_slice_type)
    {
        last_slice_type->structure.next = result;
    }
    else
    {
        module->first_slice_type = result;
    }

    return result;
}

fn String array_name(Module* module, Type* element_type, u64 element_count)
{
    u8 buffer[512];
    auto buffer_slice = String{ .pointer = buffer, .length = array_length(buffer) };

    u64 i = 0;

    buffer[i] = '[';
    i += 1;

    i += format_integer_decimal(buffer_slice(i), element_count);

    buffer[i] = ']';
    i += 1;

    auto element_name = element_type->name;
    memcpy(buffer + i, element_name.pointer, element_name.length);
    i += element_name.length;

    auto name = arena_duplicate_string(module->arena, buffer_slice(0, i));
    return name;
}

fn Type* get_array_type(Module* module, Type* element_type, u64 element_count)
{
    assert(element_type);
    assert(element_count);

    Type* array_type = module->first_array_type;

    if (array_type)
    {
        while (1)
        {
            assert(array_type->id == TypeId::array);
            auto* candidate_element_type = array_type->array.element_type;
            auto candidate_element_count = array_type->array.element_count;

            if (candidate_element_type == element_type && candidate_element_count == element_count)
            {
                return array_type;
            }

            if (!array_type->array.next)
            {
                break;
            }

            array_type = array_type->array.next;
        }
    }

    Type* last_array_type = array_type;

    auto result = type_allocate_init(module, {
        .array = {
            .element_type = element_type,
            .element_count = element_count,
        },
        .id = TypeId::array,
        .name = array_name(module, element_type, element_count),
        .scope = element_type->scope,
    });

    if (last_array_type)
    {
        last_array_type->array.next = result;
    }
    else
    {
        module->first_array_type = result;
    }

    return result;
}

fn Block* scope_to_block(Scope* scope)
{
    assert(scope->kind == ScopeKind::local);
    auto byte_offset = offsetof(Block, scope);
    auto result = (Block*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::local);
    return result;
}

fn StatementForEach* scope_to_for_each(Scope* scope)
{
    assert(scope->kind == ScopeKind::for_each);
    auto byte_offset = offsetof(StatementForEach, scope);
    auto result = (StatementForEach*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::for_each);
    return result;
}

fn MacroDeclaration* scope_to_macro_declaration(Scope* scope)
{
    assert(scope->kind == ScopeKind::macro_declaration);
    auto byte_offset = offsetof(MacroDeclaration, scope);
    auto result = (MacroDeclaration*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::macro_declaration);
    return result;
}

fn MacroInstantiation* scope_to_macro_instantiation(Scope* scope)
{
    assert(scope->kind == ScopeKind::macro_instantiation);
    auto byte_offset = offsetof(MacroInstantiation, scope);
    auto result = (MacroInstantiation*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::macro_instantiation);
    return result;
}

fn ValueFunction* scope_to_function(Scope* scope)
{
    assert(scope->kind == ScopeKind::function);
    auto byte_offset = offsetof(ValueFunction, scope);
    auto result = (ValueFunction*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::function);
    return result;
}

fn Module* scope_to_module(Scope* scope)
{
    assert(scope->kind == ScopeKind::global);
    auto byte_offset = offsetof(Module, scope);
    auto result = (Module*)((u8*)scope - byte_offset);
    assert(result->scope.kind == ScopeKind::global);
    return result;
}

fn Value* reference_identifier(Module* module, Scope* current_scope, String identifier, ValueKind kind)
{
    assert(!identifier.equal(string_literal("")));
    assert(!identifier.equal(string_literal("_")));

    Variable* variable = 0;

    for (Scope* scope = current_scope; scope && !variable; scope = scope->parent)
    {
        switch (scope->kind)
        {
            case ScopeKind::global:
                {
                    assert(module == scope_to_module(scope));

                    for (Global* global = module->first_global; global; global = global->next)
                    {
                        if (identifier.equal(global->variable.name))
                        {
                            variable = &global->variable;
                            break;
                        }
                    }

                    for (MacroDeclaration* macro_declaration = module->first_macro_declaration; macro_declaration; macro_declaration = macro_declaration->next)
                    {
                        if (identifier.equal(macro_declaration->name))
                        {
                            auto result = new_value(module);
                            *result = {
                                .macro_reference = macro_declaration,
                                .id = ValueId::macro_reference,
                            };
                            return result;
                        }
                    }
                } break;
            case ScopeKind::function:
                {
                    assert(scope->parent);
                    auto function = scope_to_function(scope);
                    for (auto& argument: function->arguments)
                    {
                        if (identifier.equal(argument.variable.name))
                        {
                            variable = &argument.variable;
                            break;
                        }
                    }
                } break;
            case ScopeKind::local:
                {
                    assert(scope->parent);
                    assert(scope->parent->kind != ScopeKind::global);

                    auto block = scope_to_block(scope);
                    for (Local* local = block->first_local; local; local = local->next)
                    {
                        assert(!local->next || block->last_local != local);
                        if (identifier.equal(local->variable.name))
                        {
                            variable = &local->variable;
                            break;
                        }
                    }
                } break;
            case ScopeKind::for_each:
                {
                    assert(scope->parent);
                    auto for_each = scope_to_for_each(scope);

                    for (Local* local = for_each->first_local; local; local = local->next)
                    {
                        if (identifier.equal(local->variable.name))
                        {
                            variable = &local->variable;
                            break;
                        }
                    }
                } break;
            case ScopeKind::macro_declaration:
                {
                    assert(scope->parent);
                    auto macro_declaration = scope_to_macro_declaration(scope);

                    for (auto& constant_argument: macro_declaration->constant_arguments)
                    {
                        if (identifier.equal(constant_argument.name))
                        {
                            trap();
                        }
                    }

                    for (auto& argument: macro_declaration->arguments)
                    {
                        if (identifier.equal(argument.variable.name))
                        {
                            variable = &argument.variable;
                            break;
                        }
                    }
                } break;
            case ScopeKind::macro_instantiation:
                {
                    assert(scope->parent);
                    auto macro_instantiation = scope_to_macro_instantiation(scope);

                    for (auto& argument : macro_instantiation->declaration_arguments)
                    {
                        if (identifier.equal(argument.variable.name))
                        {
                            variable = &argument.variable;
                            break;
                        }
                    }
                } break;
        }
    }

    if (variable)
    {
        auto result = new_value(module);
        *result = {
            .variable_reference = variable,
            .id = ValueId::variable_reference,
            .kind = kind,
        };
        return result;
    }
    else
    {
        report_error();
    }
}

fn Local* new_local(Module* module, Scope* scope)
{
    auto* result = &arena_allocate<Local>(module->arena, 1)[0];
    *result = {};

    switch (scope->kind)
    {
        case ScopeKind::local:
            {
                auto block = scope_to_block(scope);
                if (block->last_local)
                {
                    block->last_local->next = result;
                    block->last_local = result;
                }
                else
                {
                    block->first_local = result;
                    block->last_local = result;
                }
            } break;
        case ScopeKind::for_each:
            {
                auto for_each = scope_to_for_each(scope);
                if (for_each->last_local)
                {
                    for_each->last_local->next = result;
                    for_each->last_local = result;
                }
                else
                {
                    for_each->first_local = result;
                    for_each->last_local = result;
                }
            } break;
        default: report_error();
    }

    return result;
}

fn Type* get_enum_array_type(Module* module, Type* enum_type, Type* element_type)
{
    assert(enum_type);
    assert(element_type);

    Type* last_enum_type = module->first_enum_array_type;

    if (last_enum_type)
    {
        while (1)
        {
            assert(last_enum_type->id == TypeId::enum_array);

            if (last_enum_type->enum_array.enum_type == enum_type && last_enum_type->enum_array.element_type == element_type)
            {
                return last_enum_type;
            }

            if (!last_enum_type->enum_array.next)
            {
                break;
            }

            last_enum_type = last_enum_type->enum_array.next;
        }
    }

    String name_parts[] = {
        string_literal("enum_array["),
        enum_type->name,
        string_literal("]("),
        element_type->name,
        string_literal(")"),
    };

    assert(enum_type->scope);
    assert(element_type->scope);

    auto scope = element_type->scope->kind == ScopeKind::global ? enum_type->scope : element_type->scope;

    auto enum_array_type = type_allocate_init(module, {
        .enum_array = {
            .enum_type = enum_type,
            .element_type = element_type,
        },
        .id = TypeId::enum_array,
        .name = arena_join_string(module->arena, array_to_slice(name_parts)),
        .scope = scope,
    });
    return enum_array_type;
}

fn Type* resolve_alias(Module* module, Type* type)
{
    Type* result_type = 0;
    switch (type->id)
    {
        case TypeId::void_type:
        case TypeId::noreturn:
        case TypeId::integer:
        case TypeId::enumerator:
        case TypeId::function:
        case TypeId::bits:
        case TypeId::union_type:
        case TypeId::opaque:
        case TypeId::forward_declaration:
            {
                result_type = type;
            } break;
        case TypeId::pointer:
            {
                auto* element_type = type->pointer.element_type;
                auto* resolved_element_type = resolve_alias(module, element_type);
                if (element_type == resolved_element_type)
                {
                    result_type = type;
                }
                else
                {
                    result_type = get_pointer_type(module, resolved_element_type);
                }
            } break;
        case TypeId::array:
            {
                auto* element_type = type->array.element_type;
                auto element_count = type->array.element_count;
                assert(element_count);
                auto* resolved_element_type = resolve_alias(module, element_type);
                if (element_type == resolved_element_type)
                {
                    result_type = type;
                }
                else
                {
                    result_type = get_array_type(module, resolved_element_type, element_count);
                }
            } break;
        case TypeId::structure:
            {
                if (type->structure.is_slice)
                {
                    auto old_element_type = type->structure.fields[0].type->pointer.element_type;
                    auto element_type = resolve_alias(module, old_element_type);
                    if (old_element_type == element_type)
                    {
                        result_type = type;
                    }
                    else
                    {
                        result_type = get_slice_type(module, element_type);
                    }
                }
                else
                {
                    result_type = type;
                }
            } break;
        case TypeId::alias:
            {
                result_type = resolve_alias(module, type->alias.type);
            } break;
        case TypeId::enum_array:
            {
                auto old_enum_type = type->enum_array.enum_type;
                auto old_element_type = type->enum_array.element_type;
                auto enum_type = resolve_alias(module, old_enum_type);
                auto element_type = resolve_alias(module, old_element_type);

                if (old_enum_type == enum_type && old_element_type == element_type)
                {
                    result_type = type;
                }
                else
                {
                    result_type = get_enum_array_type(module, enum_type, element_type);
                }
            } break;
        default: unreachable();
    }

    assert(result_type);
    return result_type;
}


fn u64 enum_bit_count(u64 highest_value)
{
    auto needed_bit_count = 64 - (u64)clz(highest_value);
    needed_bit_count = needed_bit_count ? needed_bit_count : 1;
    return needed_bit_count;
}

struct ArgBuilder
{
    char* args[128];
    u32 argument_count = 0;

    void add(const char* arg)
    {
        assert(argument_count < array_length(args));
        args[argument_count] = (char*)arg;
        argument_count += 1;
    }

    void add(Arena* arena, String arg)
    {
        if (arg.pointer[arg.length] != 0)
        {
            arg = arena_duplicate_string(arena, arg);
        }

        add((const char*)arg.pointer);
    }

    Slice<char* const> flush()
    {
        assert(argument_count < array_length(args));
        args[argument_count] = 0;
        return { args, argument_count };
    }
};

void parse(Module* module);
void emit(Module* module);
