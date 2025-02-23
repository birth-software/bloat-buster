const llvm = @import("LLVM.zig");
const lld = llvm.lld;

const Bool = c_int;

pub extern fn llvm_context_create_module(context: *llvm.Context, name: llvm.String) *llvm.Module;
pub extern fn LLVMContextCreate() *llvm.Context;
pub extern fn LLVMCreateBuilderInContext(context: *llvm.Context) *llvm.Builder;

// Module
pub extern fn llvm_module_create_global_variable(module: *llvm.Module, global_type: *llvm.Type, is_constant: bool, linkage: llvm.LinkageType, initial_value: *llvm.Constant, name: llvm.String, before: ?*llvm.GlobalVariable, thread_local_mode: llvm.ThreadLocalMode, address_space: c_uint, externally_initialized: bool) *llvm.GlobalVariable;
pub extern fn llvm_module_create_function(module: *llvm.Module, function_type: *llvm.Type.Function, linkage_type: llvm.LinkageType, address_space: c_uint, name: llvm.String) *llvm.Function;
pub extern fn llvm_context_create_basic_block(context: *llvm.Context, name: llvm.String, parent: *llvm.Function) *llvm.BasicBlock;

pub extern fn LLVMGetBasicBlockTerminator(basic_block: *llvm.BasicBlock) ?*llvm.Value;

pub extern fn llvm_function_to_string(function: *llvm.Function) *llvm.String;
pub extern fn llvm_function_verify(function: *llvm.Function, error_message: *llvm.String) bool;
pub extern fn llvm_module_verify(module: *llvm.Module, error_message: *llvm.String) bool;

pub extern fn llvm_module_to_string(module: *llvm.Module) llvm.String;

// Builder API
pub extern fn LLVMPositionBuilderAtEnd(builder: *llvm.Builder, basic_block: *llvm.BasicBlock) void;
pub extern fn LLVMBuildRet(builder: *llvm.Builder, value: ?*llvm.Value) void;
pub extern fn LLVMBuildAdd(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildSub(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildMul(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildSDiv(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildUDiv(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildSRem(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildURem(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildShl(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildAShr(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildLShr(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildAnd(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildOr(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildXor(builder: *llvm.Builder, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildICmp(builder: *llvm.Builder, predicate: llvm.IntPredicate, left: *llvm.Value, right: *llvm.Value, name: [*:0]const u8) *llvm.Value;
pub extern fn LLVMBuildCondBr(builder: *llvm.Builder, condition: *llvm.Value, taken: *llvm.BasicBlock, not_taken: *llvm.BasicBlock) *llvm.Value;

pub extern fn llvm_builder_create_alloca(builder: *llvm.Builder, ty: *llvm.Type, address_space: c_uint, name: llvm.String) *llvm.Value;
pub extern fn LLVMBuildStore(builder: *llvm.Builder, value: *llvm.Value, pointer: *llvm.Value) *llvm.Value;
pub extern fn LLVMBuildLoad2(builder: *llvm.Builder, ty: *llvm.Type, pointer: *llvm.Value, name: [*:0]const u8) *llvm.Value;

pub extern fn LLVMSetCurrentDebugLocation2(builder: *llvm.Builder, location: ?*llvm.DI.Location) void;

pub extern fn LLVMTypeOf(value: *llvm.Value) *llvm.Type;
pub extern fn LLVMGlobalGetValueType(value: *llvm.GlobalValue) *llvm.Type;

// TYPES
// Types: integers
pub extern fn LLVMInt1TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMInt8TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMInt16TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMInt32TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMInt64TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMInt128TypeInContext(context: *llvm.Context) *llvm.Type.Integer;
pub extern fn LLVMIntTypeInContext(context: *llvm.Context, bit_count: c_uint) *llvm.Type.Integer;

// Types: floating point
pub extern fn LLVMHalfTypeInContext(context: *llvm.Context) *llvm.Type;
pub extern fn LLVMBFloatTypeInContext(context: *llvm.Context) *llvm.Type;
pub extern fn LLVMFloatTypeInContext(context: *llvm.Context) *llvm.Type;
pub extern fn LLVMDoubleTypeInContext(context: *llvm.Context) *llvm.Type;
pub extern fn LLVMFP128TypeInContext(context: *llvm.Context) *llvm.Type;

// Types: functions
pub extern fn LLVMFunctionType(return_type: *llvm.Type, parameter_type_pointer: [*]const *llvm.Type, parameter_type_count: c_uint, is_var_arg: Bool) *llvm.Type.Function;
pub extern fn LLVMIsFunctionVarArg(function_type: *llvm.Type.Function) Bool;
pub extern fn LLVMGetReturnType(function_type: *llvm.Type.Function) *llvm.Type;
pub extern fn LLVMSetSubprogram(function: *llvm.Function, subprogram: *llvm.DI.Subprogram) void;
pub extern fn LLVMGetSubprogram(function: *llvm.Function) *llvm.DI.Subprogram;
pub extern fn LLVMCountParamTypes(function_type: *llvm.Type.Function) c_uint;
pub extern fn LLVMGetParamTypes(function_type: *llvm.Type.Function, types: [*]*llvm.Type) void;

// Types: struct
pub extern fn llvm_context_create_struct_type(context: *llvm.Context, element_types_pointer: [*]const *llvm.Type, element_type_count: usize, name: llvm.String, is_packed: bool) *llvm.Type.Struct;
pub extern fn llvm_context_get_struct_type(context: *llvm.Context, element_types_pointer: [*]const *llvm.Type, element_type_count: usize, is_packed: bool) *llvm.Type.Struct;

// Types: arrays
pub extern fn LLVMArrayType2(element_type: *llvm.Type, element_count: u64) *llvm.Type.Array;

// Types: pointers
pub extern fn LLVMPointerTypeInContext(context: *llvm.Context, address_space: c_uint) *llvm.Type.Pointer;

// Types: vectors
pub extern fn LLVMVectorType(element_type: *llvm.Type, element_count: c_uint) *llvm.Type.FixedVector;
pub extern fn LLVMScalableVectorType(element_type: *llvm.Type, element_count: c_uint) *llvm.Type.ScalableVector;

pub extern fn llvm_type_is_function(ty: *llvm.Type) bool;
pub extern fn llvm_type_is_integer(ty: *llvm.Type) bool;

pub extern fn llvm_integer_type_get_bit_count(integer_type: *llvm.Type.Integer) c_uint;

// VALUES
pub extern fn LLVMConstInt(type: *llvm.Type.Integer, value: c_ulonglong, sign_extend: Bool) *llvm.Constant.Integer;

pub extern fn LLVMIsConstant(value: *llvm.Value) Bool;

// Debug info API
pub extern fn LLVMCreateDIBuilder(module: *llvm.Module) *llvm.DI.Builder;
pub extern fn LLVMDIBuilderFinalize(builder: *llvm.DI.Builder) void;
pub extern fn LLVMDIBuilderCreateFile(builder: *llvm.DI.Builder, file_name: llvm.String, directory_name: llvm.String) *llvm.DI.File;
pub extern fn LLVMDIBuilderCreateCompileUnit(builder: *llvm.DI.Builder, language: llvm.Dwarf.SourceLanguage, file: *llvm.DI.File, producer_name: llvm.String, optimized: Bool, flags: llvm.String, runtime_version: c_uint, split_name: llvm.String, dwarf_emission_kind: llvm.Dwarf.EmissionKind, debug_with_offset_id: c_uint, split_debug_inlining: Bool, debug_info_for_profiling: Bool, sysroot: llvm.String, sdk: llvm.String) *llvm.DI.CompileUnit;
pub extern fn LLVMDIBuilderCreateSubroutineType(builder: *llvm.DI.Builder, file: *llvm.DI.File, parameter_type_pointer: [*]const *llvm.DI.Type, parameter_type_count: c_uint, flags: llvm.DI.Flags) *llvm.DI.Type.Subroutine;
pub extern fn LLVMDIBuilderCreateFunction(builder: *llvm.DI.Builder, scope: *llvm.DI.Scope, name: llvm.String, linkage_name: llvm.String, file: *llvm.DI.File, line_number: c_uint, type: *llvm.DI.Type.Subroutine, local_to_unit: Bool, is_definition: Bool, scope_line: c_uint, flags: llvm.DI.Flags, is_optimized: Bool) *llvm.DI.Subprogram;
pub extern fn LLVMDIBuilderFinalizeSubprogram(builder: *llvm.DI.Builder, subprogram: *llvm.DI.Subprogram) void;
pub extern fn LLVMDIBuilderCreateExpression(builder: *llvm.DI.Builder, address: ?[*]const u64, length: u64) *llvm.DI.Expression;
pub extern fn LLVMDIBuilderCreateDebugLocation(context: *llvm.Context, line: c_uint, column: c_uint, scope: *llvm.DI.Scope, inlined_at: ?*llvm.DI.Metadata) *llvm.DI.Location;
pub extern fn LLVMDIBuilderCreateBasicType(builder: *llvm.DI.Builder, name_pointer: [*]const u8, name_length: usize, bit_count: u64, dwarf_type: llvm.Dwarf.Type, flags: llvm.DI.Flags) *llvm.DI.Type;
pub extern fn LLVMDIBuilderCreateAutoVariable(builder: *llvm.DI.Builder, scope: *llvm.DI.Scope, name_pointer: [*]const u8, name_length: usize, file: *llvm.DI.File, line: c_uint, type: *llvm.DI.Type, always_preserve: Bool, flags: llvm.DI.Flags, align_in_bits: u32) *llvm.DI.LocalVariable;
pub extern fn LLVMDIBuilderInsertDeclareRecordAtEnd(builder: *llvm.DI.Builder, storage: *llvm.Value, local_variable: *llvm.DI.LocalVariable, expression: *llvm.DI.Expression, debug_location: *llvm.DI.Location, basic_block: *llvm.BasicBlock) *llvm.DI.Record;
pub extern fn LLVMDIBuilderCreateGlobalVariableExpression(builder: *llvm.DI.Builder, scope: *llvm.DI.Scope, name_pointer: [*]const u8, name_length: usize, linkage_name_pointer: [*]const u8, linkage_name_length: usize, file: *llvm.DI.File, line: c_uint, global_type: *llvm.DI.Type, local_to_unit: Bool, expression: *llvm.DI.Expression, declaration: ?*llvm.DI.Metadata, align_in_bits: u32) *llvm.DI.GlobalVariableExpression;
pub extern fn llvm_global_variable_add_debug_info(global_variable: *llvm.GlobalVariable, debug_global_variable: *llvm.DI.GlobalVariableExpression) void;
pub extern fn LLVMDIBuilderCreateLexicalBlock(builder: *llvm.DI.Builder, scope: *llvm.DI.Scope, file: *llvm.DI.File, line: c_uint, column: c_uint) *llvm.DI.LexicalBlock;

// Target
pub extern fn llvm_default_target_triple() llvm.String;
pub extern fn llvm_host_cpu_name() llvm.String;
pub extern fn llvm_host_cpu_features() llvm.String;

pub extern fn llvm_create_target_machine(create: *const llvm.Target.Machine.Create, error_message: *llvm.String) ?*llvm.Target.Machine;
pub extern fn llvm_module_set_target(module: *llvm.Module, target_machine: *llvm.Target.Machine) void;

pub extern fn llvm_module_run_optimization_pipeline(module: *llvm.Module, target_machine: *llvm.Target.Machine, options: llvm.OptimizationPipelineOptions) void;
pub extern fn llvm_module_run_code_generation_pipeline(module: *llvm.Module, target_machine: *llvm.Target.Machine, options: llvm.CodeGenerationPipelineOptions) llvm.CodeGenerationPipelineResult;

pub fn get_initializer(comptime llvm_arch: llvm.Architecture) type {
    const arch_name = @tagName(llvm_arch);
    return struct {
        pub const initialize_target_info = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "TargetInfo",
        });
        pub const initialize_target = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "Target",
        });
        pub const initialize_target_mc = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "TargetMC",
        });
        pub const initialize_asm_printer = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "AsmPrinter",
        });
        pub const initialize_asm_parser = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "AsmParser",
        });
        pub const initialize_disassembler = @extern(*const fn () callconv(.C) void, .{
            .name = "LLVMInitialize" ++ arch_name ++ "Disassembler",
        });

        pub fn initialize(options: llvm.TargetInitializerOptions) void {
            initialize_target_info();
            initialize_target();
            initialize_target_mc();

            if (options.asm_printer) {
                initialize_asm_printer();
            }

            if (options.asm_parser) {
                initialize_asm_parser();
            }

            if (options.disassembler) {
                initialize_disassembler();
            }
        }
    };
}

// LLD

pub extern fn lld_elf_link(argument_pointer: [*:null]const ?[*:0]const u8, argument_length: u64, exit_early: bool, disable_output: bool) lld.Result;
