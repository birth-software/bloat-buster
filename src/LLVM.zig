const lib = @import("lib.zig");
const Arena = lib.Arena;
const assert = lib.assert;
const os = lib.os;
const builtin = @import("builtin");
const api = @import("llvm_api.zig");

/// This is a String which ABI-compatible with C++
pub const String = extern struct {
    pointer: ?[*]const u8 = null,
    length: usize = 0,

    pub fn from_slice(slice: []const u8) String {
        return String{
            .pointer = slice.ptr,
            .length = slice.len,
        };
    }

    pub fn to_slice(string: String) ?[]const u8 {
        if (string.length != 0) {
            return string.pointer.?[0..string.length];
        } else {
            return null;
        }
    }
};

pub const Intrinsic = enum {
    pub const Id = enum(c_uint) {
        _,
    };
};

pub const Attribute = opaque {
    pub const Index = enum(c_uint) {
        @"return" = 0,
        function = 0xffff_ffff,
        _,
    };

    pub const Kind = enum(c_uint) {
        _,
    };
};

pub const CodeModel = enum(u8) {
    none = 0,
    tiny = 1,
    small = 2,
    kernel = 3,
    medium = 4,
    large = 5,
};

pub const RelocationModel = enum(u8) {
    default = 0,
    static = 1,
    pic = 2,
    dynamic_no_pic = 3,
    ropi = 4,
    rwpi = 5,
    ropi_rwpi = 6,
};

pub const CodeGenerationOptimizationLevel = enum(u8) {
    none = 0, // -O0
    less = 1, // -O1
    default = 2, // -O2, -Os
    aggressive = 3, // -O3
};

pub const Target = opaque {
    /// This is ABI-compatible with C++
    pub const Options = extern struct {
        flags0: packed struct(u64) {
            unsafe_fp_math: u1,
            no_infs_fp_math: u1,
            no_nans_fp_math: u1,
            no_trapping_fp_math: u1,
            no_signed_zeroes_fp_math: u1,
            approx_func_fp_match: u1,
            enable_aix_extended_altivec_abi: u1,
            honor_sign_dependent_rounding_fp_math: u1,
            no_zeroes_in_bss: u1,
            guaranteed_tail_call_optimization: u1,
            stack_symbol_ordering: u1,
            enable_fast_isel: u1,
            enable_global_isel: u1,
            global_isel_abort_mode: enum(u2) {
                disable = 0,
                enable = 1,
                disable_with_diag = 2,
            },
            swift_async_frame_pointer: enum(u2) {
                deployment_based = 0,
                always = 1,
                never = 2,
            },
            use_init_array: u1,
            disable_integrated_assembler: u1,
            function_sections: u1,
            data_sections: u1,
            ignore_xcoff_visibility: u1,
            xcoff_traceback_table: u1,
            unique_section_names: u1,
            unique_basic_block_section_names: u1,
            separate_named_sections: u1,
            trap_unreachable: u1,
            no_trap_after_noreturn: u1,
            tls_size: u8,
            emulated_tls: u1,
            enable_tls_descriptors: u1,
            enable_ipra: u1,
            emit_stack_size_section: u1,
            enable_machine_outliner: u1,
            enable_machine_function_splitter: u1,
            supports_default_outlining: u1,
            emit_address_significance_table: u1,
            bb_address_map: u1,
            bb_sections: enum(u3) {
                all = 0,
                list = 1,
                labels = 2,
                preset = 3,
                none = 4,
            },
            emit_call_site_information: u1,
            supports_debug_entry_values: u1,
            enable_debug_entry_values: u1,
            value_tracking_variable_locations: u1,
            force_dwarf_frame_section: u1,
            xray_function_index: u1,
            debug_strict_dwarf: u1,
            hotpatch: u1,
            ppc_gen_scalar_mass_entries: u1,
            jmc_instrument: u1,
            enable_cfi_fixup: u1,
            mis_expect: u1,
            xcoff_read_only_pointers: u1,
            float_abi: enum(u2) {
                default = 0,
                soft = 1,
                hard = 2,
            },
            thread_model: enum(u1) {
                posix = 0,
                single = 1,
            },
        },
        flags1: packed struct(u32) {
            fp_op_fusion_mode: enum(u2) {
                fast = 0,
                standard = 1,
                strict = 2,
            },
            eabi_version: enum(u3) {
                unknown = 0,
                default = 1,
                eabi4 = 2,
                eabi5 = 3,
                gnu = 4,
            },
            debugger_kind: enum(u3) {
                default = 0,
                gdb = 1,
                lldb = 2,
                sce = 3,
                dbx = 4,
            },
            exception_handling: enum(u3) {
                none = 0,
                dwarf_cfi = 1,
                setjmp_longjmp = 2,
                arm = 3,
                win_eh = 4,
                wasm = 5,
                aix = 6,
                zos = 7,
            },
            reserved: PaddingType = 0,
        },
        loop_alignment: c_uint,
        binutils_version: [2]c_int,
        mc: MCTargetOptions,

        const padding_bit_count = 21;
        const PaddingType = @Type(.{
            .int = .{
                .signedness = .unsigned,
                .bits = padding_bit_count,
            },
        });
        comptime {
            assert(@sizeOf(Target.Options) == 136);
            assert(padding_bit_count == 21);
        }

        pub fn default() Target.Options {
            return .{
                .binutils_version = .{ 0, 0 },
                .flags0 = .{
                    .unsafe_fp_math = 0,
                    .no_infs_fp_math = 0,
                    .no_nans_fp_math = 0,
                    .no_trapping_fp_math = 1,
                    .no_signed_zeroes_fp_math = 0,
                    .approx_func_fp_match = 0,
                    .enable_aix_extended_altivec_abi = 0,
                    .honor_sign_dependent_rounding_fp_math = 0,
                    .no_zeroes_in_bss = 0,
                    .guaranteed_tail_call_optimization = 0,
                    .stack_symbol_ordering = 1,
                    .enable_fast_isel = 0,
                    .enable_global_isel = 0,
                    .global_isel_abort_mode = .enable,
                    .swift_async_frame_pointer = .always,
                    .use_init_array = 0,
                    .disable_integrated_assembler = 0,
                    .function_sections = 0,
                    .data_sections = 0,
                    .ignore_xcoff_visibility = 0,
                    .xcoff_traceback_table = 1,
                    .unique_section_names = 1,
                    .unique_basic_block_section_names = 0,
                    .separate_named_sections = 0,
                    .trap_unreachable = 0,
                    .no_trap_after_noreturn = 0,
                    .tls_size = 0,
                    .emulated_tls = 0,
                    .enable_tls_descriptors = 0,
                    .enable_ipra = 0,
                    .emit_stack_size_section = 0,
                    .enable_machine_outliner = 0,
                    .enable_machine_function_splitter = 0,
                    .supports_default_outlining = 0,
                    .emit_address_significance_table = 0,
                    .bb_address_map = 0,
                    .bb_sections = .none,
                    .emit_call_site_information = 0,
                    .supports_debug_entry_values = 0,
                    .enable_debug_entry_values = 0,
                    .value_tracking_variable_locations = 0,
                    .force_dwarf_frame_section = 0,
                    .xray_function_index = 1,
                    .debug_strict_dwarf = 0,
                    .hotpatch = 0,
                    .ppc_gen_scalar_mass_entries = 0,
                    .jmc_instrument = 0,
                    .enable_cfi_fixup = 0,
                    .mis_expect = 0,
                    .xcoff_read_only_pointers = 0,
                    .float_abi = .default,
                    .thread_model = .posix,
                },
                .flags1 = .{
                    .fp_op_fusion_mode = .standard,
                    .eabi_version = .default,
                    .debugger_kind = .default,
                    .exception_handling = .none,
                },
                .loop_alignment = 0,
                .mc = .{
                    .abi_name = .{},
                    .assembly_language = .{},
                    .split_dwarf_file = .{},
                    .as_secure_log_file = .{},
                    .argv0 = null,
                    .argv_pointer = null,
                    .argv_count = 0,
                    .integrated_assembler_search_path_pointer = null,
                    .integrated_assembler_search_path_count = 0,
                    .flags = .{
                        .relax_all = 0,
                        .no_exec_stack = 0,
                        .fatal_warnings = 0,
                        .no_warn = 0,
                        .no_deprecated_warn = 0,
                        .no_type_check = 0,
                        .save_temp_labels = 0,
                        .incremental_linker_compatible = 0,
                        .fdpic = 0,
                        .show_mc_encoding = 0,
                        .show_mc_inst = 0,
                        .asm_verbose = 0,
                        .preserve_asm_comments = 1,
                        .dwarf64 = 0,
                        .crel = 0,
                        .x86_relax_relocations = 1,
                        .x86_sse2_avx = 0,
                        .emit_dwarf_unwind = .default,
                        .use_dwarf_directory = .default,
                        .debug_compression_type = .none,
                        .emit_compact_unwind_non_canonical = 0,
                        .ppc_use_full_register_names = 0,
                    },
                },
            };
        }
    };

    pub const Machine = opaque {
        /// This is ABI-compatible with C++
        pub const Create = extern struct {
            target_options: Target.Options,
            cpu_triple: String,
            cpu_model: String,
            cpu_features: String,
            code_model: CodeModel,
            relocation_model: RelocationModel,
            optimization_level: CodeGenerationOptimizationLevel,
            jit: bool,
            reserved: [padding_byte_count]u8 = [1]u8{0} ** padding_byte_count,

            const padding_byte_count = 4;
            comptime {
                assert(@sizeOf(Create) == 192);
                assert(padding_byte_count == 4);
            }
        };

        pub fn create(options: Create, error_message: *String) ?*Target.Machine {
            const target_machine = api.llvm_create_target_machine(&options, error_message);
            return target_machine;
        }
    };
};

pub const MCTargetOptions = extern struct {
    abi_name: String,
    assembly_language: String,
    split_dwarf_file: String,
    as_secure_log_file: String,
    argv0: ?[*:0]const u8,
    argv_pointer: ?[*]const String,
    argv_count: u64,
    integrated_assembler_search_path_pointer: ?[*]const String,
    integrated_assembler_search_path_count: u64,
    flags: packed struct(u32) {
        relax_all: u1,
        no_exec_stack: u1,
        fatal_warnings: u1,
        no_warn: u1,
        no_deprecated_warn: u1,
        no_type_check: u1,
        save_temp_labels: u1,
        incremental_linker_compatible: u1,
        fdpic: u1,
        show_mc_encoding: u1,
        show_mc_inst: u1,
        asm_verbose: u1,
        preserve_asm_comments: u1,
        dwarf64: u1,
        crel: u1,
        x86_relax_relocations: u1,
        x86_sse2_avx: u1,
        emit_dwarf_unwind: enum(u2) {
            always = 0,
            no_compact_unwind = 1,
            default = 2,
        },
        use_dwarf_directory: enum(u2) {
            disable = 0,
            enable = 1,
            default = 2,
        },
        debug_compression_type: enum(u2) {
            none = 0,
            zlib = 1,
            zstd = 2,
        },
        emit_compact_unwind_non_canonical: u1,
        ppc_use_full_register_names: u1,
        reserved: PaddingType = 0,
    },

    const padding_bit_count = 7;
    const PaddingType = @Type(.{
        .int = .{
            .signedness = .unsigned,
            .bits = 7,
        },
    });
    comptime {
        assert(@sizeOf(MCTargetOptions) == 112);
        assert(padding_bit_count == 7);
    }
};

pub const OptimizationLevel = enum(u3) {
    O0 = 0,
    O1 = 1,
    O2 = 2,
    O3 = 3,
    Os = 4,
    Oz = 5,

    fn prefers_size(optimization_level: OptimizationLevel) bool {
        return switch (optimization_level) {
            .O0, .O1, .Os, .Oz => true,
            .O2, .O3 => false,
        };
    }

    fn prefers_speed(optimization_level: OptimizationLevel) bool {
        return !prefers_size(optimization_level);
    }
};

/// This is ABI-compatible with C++
pub const OptimizationPipelineOptions = packed struct(u64) {
    optimization_level: OptimizationLevel,
    debug_info: u1,
    loop_unrolling: u1,
    loop_interleaving: u1,
    loop_vectorization: u1,
    slp_vectorization: u1,
    merge_functions: u1,
    call_graph_profile: u1,
    unified_lto: u1,
    assignment_tracking: u1,
    verify_module: u1,
    reserved: PaddingType = 0,

    const padding_bit_count = 51;
    const PaddingType = @Type(.{
        .int = .{
            .signedness = .unsigned,
            .bits = padding_bit_count,
        },
    });

    comptime {
        assert(@sizeOf(OptimizationPipelineOptions) == @sizeOf(u64));
        assert(padding_bit_count == 51);
    }

    const Create = packed struct {
        optimization_level: OptimizationLevel,
        debug_info: u1,
    };
    pub fn default(create: Create) OptimizationPipelineOptions {
        const pref_speed = @intFromBool(create.optimization_level.prefers_speed());
        return .{
            .optimization_level = create.optimization_level,
            .debug_info = create.debug_info,
            .loop_unrolling = pref_speed,
            .loop_interleaving = pref_speed,
            .loop_vectorization = pref_speed,
            .slp_vectorization = pref_speed,
            .merge_functions = pref_speed,
            .call_graph_profile = 0,
            .unified_lto = 0,
            .assignment_tracking = create.debug_info,
            .verify_module = @intFromBool(lib.optimization_mode == .ReleaseSafe or lib.optimization_mode == .Debug),
        };
    }
};

/// This is ABI-compatible with C++
pub const CodeGenerationPipelineOptions = extern struct {
    output_dwarf_file_path: String,
    output_file_path: String,
    flags: packed struct(u64) {
        code_generation_file_type: enum(u2) {
            assembly_file = 0,
            object_file = 1,
            null = 2,
        },
        optimize_when_possible: u1,
        verify_module: u1,
        reserved: PaddingType = 0,
    },

    const padding_bit_count = 60;
    const PaddingType = @Type(.{
        .int = .{
            .signedness = .unsigned,
            .bits = padding_bit_count,
        },
    });

    comptime {
        assert(@sizeOf(CodeGenerationPipelineOptions) == 5 * @sizeOf(u64));
        assert(padding_bit_count == 60);
    }
};

pub const CodeGenerationPipelineResult = enum(u8) {
    success = 0,
    failed_to_create_file = 1,
    failed_to_add_emit_passes = 2,
};

pub const Architecture = enum {
    X86,
};

pub const TargetInitializerOptions = struct {
    asm_parser: bool = true,
    asm_printer: bool = true,
    disassembler: bool = false,
};

const targets = [@typeInfo(Architecture).@"enum".fields.len]type{
    api.get_initializer(.X86),
};

pub const Context = opaque {
    pub const create = api.LLVMContextCreate;

    pub fn create_module(context: *Context, name: []const u8) *Module {
        return api.llvm_context_create_module(context, String.from_slice(name));
    }

    pub const create_builder = api.LLVMCreateBuilderInContext;

    pub fn create_basic_block(context: *Context, name: []const u8, parent: *Function) *BasicBlock {
        return api.llvm_context_create_basic_block(context, String.from_slice(name), parent);
    }

    pub fn create_forward_declared_struct_type(context: *Context, name: []const u8) *Type.Struct {
        return api.llvm_context_create_forward_declared_struct_type(context, String.from_slice(name));
    }

    pub fn create_struct_type(context: *Context, element_types: []const *Type, name: []const u8) *Type.Struct {
        const is_packed = false;
        return api.llvm_context_create_struct_type(context, element_types.ptr, @intCast(element_types.len), String.from_slice(name), is_packed);
    }

    pub fn get_struct_type(context: *Context, element_types: []const *Type) *Type.Struct {
        const is_packed = false;
        return api.llvm_context_get_struct_type(context, element_types.ptr, element_types.len, is_packed);
    }

    pub const get_void_type = api.LLVMVoidTypeInContext;
    pub const get_integer_type = api.LLVMIntTypeInContext;
    pub const get_pointer_type = api.LLVMPointerTypeInContext;

    pub fn get_intrinsic_type(context: *Context, intrinsic_id: Intrinsic.Id, parameter_types: []const *Type) *Type.Function {
        return api.LLVMIntrinsicGetType(context, intrinsic_id, parameter_types.ptr, parameter_types.len);
    }

    pub fn create_string_attribute(context: *Context, attribute_name: []const u8, attribute_value: []const u8) *Attribute {
        return api.LLVMCreateStringAttribute(context, attribute_name.ptr, @intCast(attribute_name.len), attribute_value.ptr, @intCast(attribute_value.len));
    }

    pub const create_enum_attribute = api.LLVMCreateEnumAttribute;
    pub const create_type_attribute = api.LLVMCreateTypeAttribute;
};

pub const BasicBlock = opaque {
    pub const get_terminator = api.LLVMGetBasicBlockTerminator;
};

pub const Module = opaque {
    pub const create_di_builder = api.LLVMCreateDIBuilder;
    pub const set_target = api.llvm_module_set_target;
    pub const run_optimization_pipeline = api.llvm_module_run_optimization_pipeline;
    pub const run_code_generation_pipeline = api.llvm_module_run_code_generation_pipeline;

    pub fn to_string(module: *Module) []const u8 {
        return api.llvm_module_to_string(module).to_slice().?;
    }

    pub const FunctionCreate = struct {
        type: *Type.Function,
        linkage: LinkageType,
        address_space: c_uint = 0,
        name: []const u8,
    };

    pub fn create_function(module: *Module, create: FunctionCreate) *Function {
        return api.llvm_module_create_function(module, create.type, create.linkage, create.address_space, String.from_slice(create.name));
    }

    pub const GlobalCreate = struct {
        type: *Type,
        initial_value: *Constant,
        name: []const u8,
        before: ?*GlobalVariable = null,
        address_space: c_uint = 0,
        linkage: LinkageType,
        thread_local_mode: ThreadLocalMode = .none,
        is_constant: bool = false,
        externally_initialized: bool = false,
    };

    pub fn create_global_variable(module: *Module, create: GlobalCreate) *GlobalVariable {
        return api.llvm_module_create_global_variable(module, create.type, create.is_constant, create.linkage, create.initial_value, String.from_slice(create.name), create.before, create.thread_local_mode, create.address_space, create.externally_initialized);
    }

    pub fn verify(module: *Module) VerifyResult {
        var result: VerifyResult = undefined;
        var string: String = undefined;
        result.success = api.llvm_module_verify(module, &string);
        result.error_message = string.to_slice();
        return result;
    }

    pub fn get_intrinsic_declaration(module: *Module, intrinsic_id: Intrinsic.Id, parameter_types: []const *Type) *Value {
        return api.LLVMGetIntrinsicDeclaration(module, intrinsic_id, parameter_types.ptr, parameter_types.len);
    }
};

pub const VerifyResult = struct {
    error_message: ?[]const u8,
    success: bool,
};

pub const Builder = opaque {
    pub const position_at_end = api.LLVMPositionBuilderAtEnd;
    pub const get_insert_block = api.LLVMGetInsertBlock;

    pub const create_ret = api.LLVMBuildRet;

    pub fn create_ret_void(builder: *Builder) void {
        builder.create_ret(null);
    }

    pub fn create_add(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildAdd(builder, left, right, "");
    }

    pub fn create_sub(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildSub(builder, left, right, "");
    }

    pub fn create_mul(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildMul(builder, left, right, "");
    }

    pub fn create_sdiv(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildSDiv(builder, left, right, "");
    }

    pub fn create_udiv(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildUDiv(builder, left, right, "");
    }

    pub fn create_srem(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildSRem(builder, left, right, "");
    }

    pub fn create_urem(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildURem(builder, left, right, "");
    }

    pub fn create_shl(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildShl(builder, left, right, "");
    }

    pub fn create_ashr(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildAShr(builder, left, right, "");
    }

    pub fn create_lshr(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildLShr(builder, left, right, "");
    }

    pub fn create_and(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildAnd(builder, left, right, "");
    }

    pub fn create_or(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildOr(builder, left, right, "");
    }

    pub fn create_xor(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildXor(builder, left, right, "");
    }

    pub fn create_alloca(builder: *Builder, ty: *Type, name: []const u8) *Value {
        return api.llvm_builder_create_alloca(builder, ty, 0, String.from_slice(name));
    }

    pub const create_store = api.LLVMBuildStore;

    pub fn create_load(builder: *Builder, ty: *Type, pointer: *Value) *Value {
        return api.LLVMBuildLoad2(builder, ty, pointer, "");
    }

    pub fn clear_current_debug_location(builder: *Builder) void {
        return builder.set_current_debug_location(null);
    }

    pub const set_current_debug_location = api.LLVMSetCurrentDebugLocation2;

    pub fn create_compare(builder: *Builder, predicate: IntPredicate, left: *Value, right: *Value) *Value {
        return api.LLVMBuildICmp(builder, predicate, left, right, "");
    }

    pub const create_conditional_branch = api.LLVMBuildCondBr;

    pub fn create_call(builder: *Builder, function_type: *Type.Function, function_value: *Value, arguments: []const *Value) *Value {
        return api.LLVMBuildCall2(builder, function_type, function_value, arguments.ptr, @intCast(arguments.len), "");
    }

    pub fn create_struct_gep(builder: *Builder, struct_type: *Type.Struct, pointer: *Value, index: c_uint) *Value {
        return api.LLVMBuildStructGEP2(builder, struct_type, pointer, index, "");
    }

    pub fn create_gep(builder: *Builder, ty: *Type, aggregate: *Value, indices: []const *Value) *Value {
        return api.LLVMBuildInBoundsGEP2(builder, ty, aggregate, indices.ptr, @intCast(indices.len), "");
    }

    pub fn create_insert_value(builder: *Builder, aggregate: *Value, element: *Value, index: c_uint) *Value {
        return api.LLVMBuildInsertValue(builder, aggregate, element, index, "");
    }

    pub fn create_zero_extend(builder: *Builder, value: *Value, destination_type: *Type) *Value {
        return api.LLVMBuildZExt(builder, value, destination_type, "");
    }

    pub fn create_sign_extend(builder: *Builder, value: *Value, destination_type: *Type) *Value {
        return api.LLVMBuildSExt(builder, value, destination_type, "");
    }

    pub fn create_int_to_ptr(builder: *Builder, value: *Value, destination_type: *Type) *Value {
        return api.LLVMBuildIntToPtr(builder, value, destination_type, "");
    }

    pub fn create_ptr_to_int(builder: *Builder, value: *Value, destination_type: *Type) *Value {
        return api.LLVMBuildPtrToInt(builder, value, destination_type, "");
    }

    pub fn create_truncate(builder: *Builder, value: *Value, destination_type: *Type) *Value {
        return api.LLVMBuildTrunc(builder, value, destination_type, "");
    }

    pub const create_unreachable = api.LLVMBuildUnreachable;

    pub const create_memcpy = api.LLVMBuildMemCpy;
};

pub const GlobalValue = opaque {
    pub const get_type = api.LLVMGlobalGetValueType;
};

pub const GlobalVariable = opaque {
    pub const add_debug_info = api.llvm_global_variable_add_debug_info;
    pub fn to_value(global_variable: *GlobalVariable) *Value {
        return @ptrCast(global_variable);
    }
};

pub const Function = opaque {
    pub fn get_type(function: *Function) *Type.Function {
        return function.to_global_value().get_type().to_function();
    }

    pub fn to_value(function: *Function) *Value {
        return @ptrCast(function);
    }

    pub fn to_global_value(function: *Function) *GlobalValue {
        return @ptrCast(function);
    }

    pub fn verify(function: *Function) VerifyResult {
        var result: VerifyResult = undefined;
        var string: String = undefined;
        result.success = api.llvm_function_verify(function, &string);
        result.error_message = string.to_slice();
        return result;
    }
    pub const set_subprogram = api.LLVMSetSubprogram;
    pub const get_subprogram = api.LLVMGetSubprogram;

    pub fn to_string(function: *Function) []const u8 {
        return api.llvm_function_to_string(function).to_slice().?;
    }

    pub const set_calling_convention = api.LLVMSetFunctionCallConv;
    pub const get_calling_convention = api.LLVMGetFunctionCallConv;

    pub const get_arguments = api.LLVMGetParams;

    pub const add_attribute = api.LLVMAddAttributeAtIndex;
};

pub const Constant = opaque {
    pub fn to_value(constant: *Constant) *Value {
        return @ptrCast(constant);
    }

    pub const Integer = opaque {
        pub fn to_value(constant: *Constant.Integer) *Value {
            return @ptrCast(constant);
        }
    };

    pub const Array = opaque {
        pub fn to_value(constant: *Constant.Array) *Value {
            return @ptrCast(constant);
        }
    };
};

pub const Argument = opaque {
    pub fn to_value(argument: *Argument) *Value {
        return @ptrCast(argument);
    }
};

pub const Value = opaque {
    pub const get_type = api.LLVMTypeOf;
    pub const get_kind = api.LLVMGetValueKind;

    pub const is_call_instruction = api.LLVMIsACallInst;

    pub fn is_constant(value: *Value) bool {
        return api.LLVMIsConstant(value) != 0;
    }

    pub fn to_constant(value: *Value) *Constant {
        assert(value.is_constant());
        return @ptrCast(value);
    }

    pub fn to_instruction(value: *Value) *Instruction {
        assert(value.get_kind() == .Instruction);
        return @ptrCast(value);
    }

    pub fn to_function(value: *Value) *Function {
        assert(value.get_kind() == .Function);
        return @ptrCast(value);
    }

    pub fn get_calling_convention(value: *Value) CallingConvention {
        const kind = value.get_kind();
        switch (kind) {
            .Instruction => {
                const call = value.to_instruction().to_call();
                return call.get_calling_convention();
            },
            .Function => {
                const function = value.to_function();
                return function.get_calling_convention();
            },
            else => unreachable,
        }
    }

    pub const Kind = enum(c_uint) {
        Argument,
        BasicBlock,
        MemoryUse,
        MemoryDef,
        MemoryPhi,

        Function,
        GlobalAlias,
        GlobalIFunc,
        GlobalVariable,
        BlockAddress,
        ConstantExpr,
        ConstantArray,
        ConstantStruct,
        ConstantVector,

        UndefValue,
        ConstantAggregateZero,
        ConstantDataArray,
        ConstantDataVector,
        ConstantInt,
        ConstantFP,
        ConstantPointerNull,
        ConstantTokenNone,

        MetadataAsValue,
        InlineAsm,

        Instruction,
        PoisonValue,
        ConstantTargetNone,
        ConstantPtrAuth,
    };
};

pub const Instruction = opaque {
    pub fn to_value(instruction: *Instruction) *Value {
        return @ptrCast(instruction);
    }
    pub fn to_call(instruction: *Instruction) *Instruction.Call {
        assert(instruction.to_value().is_call_instruction() != null);
        return @ptrCast(instruction);
    }
    pub const Call = opaque {
        pub const set_calling_convention = api.LLVMSetInstructionCallConv;
        pub const get_calling_convention = api.LLVMGetInstructionCallConv;
        pub const add_attribute = api.LLVMAddCallSiteAttribute;
    };
};

pub const DI = struct {
    pub const Builder = opaque {
        pub fn create_file(builder: *DI.Builder, file_name: []const u8, directory: []const u8) *File {
            return api.LLVMDIBuilderCreateFile(builder, String.from_slice(file_name), String.from_slice(directory));
        }

        pub fn create_compile_unit(builder: *DI.Builder, file: *DI.File, optimized: bool) *DI.CompileUnit {
            return api.LLVMDIBuilderCreateCompileUnit(builder, .C17, file, String.from_slice("bloat buster"), @intFromBool(optimized), String{}, 0, String{}, .full, 0, 0, @intFromBool(optimized), String{}, String{});
        }

        pub const finalize = api.LLVMDIBuilderFinalize;

        pub fn create_subroutine_type(builder: *DI.Builder, file: *DI.File, parameter_types: []const *DI.Type, flags: DI.Flags) *DI.Type.Subroutine {
            return api.LLVMDIBuilderCreateSubroutineType(builder, file, parameter_types.ptr, @intCast(parameter_types.len), flags);
        }

        pub fn create_function(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, linkage_name: []const u8, file: *DI.File, line_number: c_uint, subroutine_type: *DI.Type.Subroutine, local_to_unit: bool, is_definition: bool, scope_line: c_uint, flags: DI.Flags, is_optimized: bool) *DI.Subprogram {
            return api.LLVMDIBuilderCreateFunction(builder, scope, String.from_slice(name), String.from_slice(linkage_name), file, line_number, subroutine_type, @intFromBool(local_to_unit), @intFromBool(is_definition), scope_line, flags, @intFromBool(is_optimized));
        }

        pub fn create_basic_type(builder: *DI.Builder, name: []const u8, bit_count: u64, dwarf_type: Dwarf.Type, flags: DI.Flags) *DI.Type {
            return api.LLVMDIBuilderCreateBasicType(builder, name.ptr, name.len, bit_count, dwarf_type, flags);
        }

        pub const finalize_subprogram = api.LLVMDIBuilderFinalizeSubprogram;

        pub fn create_expression(builder: *DI.Builder, slice: []const u64) *DI.Expression {
            return api.LLVMDIBuilderCreateExpression(builder, slice.ptr, slice.len);
        }

        pub fn null_expression(builder: *DI.Builder) *DI.Expression {
            return api.LLVMDIBuilderCreateExpression(builder, null, 0);
        }

        pub fn create_auto_variable(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, file: *DI.File, line: c_uint, auto_type: *DI.Type, always_preserve: bool, flags: DI.Flags, alignment_in_bits: u32) *DI.LocalVariable {
            return api.LLVMDIBuilderCreateAutoVariable(builder, scope, name.ptr, name.len, file, line, auto_type, @intFromBool(always_preserve), flags, alignment_in_bits);
        }

        pub fn create_parameter_variable(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, argument_number: c_uint, file: *DI.File, line: c_uint, parameter_type: *DI.Type, always_preserve: bool, flags: DI.Flags) *DI.LocalVariable {
            return api.LLVMDIBuilderCreateParameterVariable(builder, scope, name.ptr, name.len, argument_number, file, line, parameter_type, @intFromBool(always_preserve), flags);
        }

        pub const insert_declare_record_at_end = api.LLVMDIBuilderInsertDeclareRecordAtEnd;

        pub fn create_global_variable(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, linkage_name: []const u8, file: *DI.File, line: c_uint, global_type: *DI.Type, local_to_unit: bool, expression: *DI.Expression, align_in_bits: u32) *DI.GlobalVariableExpression {
            const declaration: ?*DI.Metadata = null;
            return api.LLVMDIBuilderCreateGlobalVariableExpression(builder, scope, name.ptr, name.len, linkage_name.ptr, linkage_name.len, file, line, global_type, @intFromBool(local_to_unit), expression, declaration, align_in_bits);
        }

        pub const create_lexical_block = api.LLVMDIBuilderCreateLexicalBlock;

        pub fn create_replaceable_composite_type(builder: *DI.Builder, tag: c_uint, name: []const u8, scope: *DI.Scope, file: *DI.File, line: c_uint) *DI.Type.Composite {
            return api.LLVMDIBuilderCreateReplaceableCompositeType(builder, tag, name.ptr, name.len, scope, file, line, 0, 0, 0, .{}, null, 0);
        }

        pub fn create_array_type(builder: *DI.Builder, element_count: u64, align_in_bits: u32, element_type: *DI.Type, subscripts: []const *DI.Metadata) *DI.Type.Composite {
            return api.LLVMDIBuilderCreateArrayType(builder, element_count, align_in_bits, element_type, subscripts.ptr, @intCast(subscripts.len));
        }

        pub fn create_struct_type(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, file: *DI.File, line: c_uint, bit_size: u64, align_in_bits: u32, flags: DI.Flags, members: []const *DI.Type.Derived) *DI.Type.Composite {
            const derived_from: ?*DI.Type = null;
            const runtime_language: c_uint = 0;
            const vtable_holder: ?*DI.Metadata = null;
            const unique_id_pointer: ?[*]const u8 = null;
            const unique_id_length: usize = 0;
            return api.LLVMDIBuilderCreateStructType(builder, scope, name.ptr, name.len, file, line, bit_size, align_in_bits, flags, derived_from, members.ptr, @intCast(members.len), runtime_language, vtable_holder, unique_id_pointer, unique_id_length);
        }

        pub fn create_member_type(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, file: *DI.File, line: c_uint, bit_size: u64, align_in_bits: u32, bit_offset: u64, flags: DI.Flags, member_type: *DI.Type) *DI.Type.Derived {
            return api.LLVMDIBuilderCreateMemberType(builder, scope, name.ptr, name.len, file, line, bit_size, align_in_bits, bit_offset, flags, member_type);
        }

        pub fn create_bit_field_member_type(builder: *DI.Builder, scope: *DI.Scope, name: []const u8, file: *DI.File, line: c_uint, bit_size: u64, bit_offset: u64, bit_storage_offset: u64, flags: DI.Flags, member_type: *DI.Type) *DI.Type.Derived {
            return api.LLVMDIBuilderCreateBitFieldMemberType(builder, scope, name.ptr, name.len, file, line, bit_size, bit_offset, bit_storage_offset, flags, member_type);
        }

        pub fn create_pointer_type(builder: *DI.Builder, element_type: *DI.Type, bit_size: u64, align_in_bits: u32, address_space: c_uint, name: []const u8) *DI.Type.Derived {
            return api.LLVMDIBuilderCreatePointerType(builder, element_type, bit_size, align_in_bits, address_space, name.ptr, name.len);
        }
    };

    pub const create_debug_location = api.LLVMDIBuilderCreateDebugLocation;

    pub const CompileUnit = opaque {
        pub fn to_scope(compile_unit: *DI.CompileUnit) *DI.Scope {
            return @ptrCast(compile_unit);
        }
    };
    pub const File = opaque {};
    pub const Scope = opaque {};
    pub const Subprogram = opaque {};
    pub const Expression = opaque {};
    pub const GlobalVariableExpression = opaque {};
    pub const LexicalBlock = opaque {
        pub fn to_scope(lexical_block: *LexicalBlock) *Scope {
            return @ptrCast(lexical_block);
        }
    };
    pub const LocalVariable = opaque {};
    pub const Location = opaque {};
    pub const Metadata = opaque {};
    pub const Record = opaque {};

    pub const Type = opaque {
        pub const Subroutine = opaque {
            pub fn to_type(subroutine: *Subroutine) *DI.Type {
                return @ptrCast(subroutine);
            }
        };
        pub const Composite = opaque {
            pub fn to_type(composite: *Composite) *DI.Type {
                return @ptrCast(composite);
            }

            pub const replace_all_uses_with = api.LLVMMetadataReplaceAllUsesWith;
        };
        pub const Derived = opaque {
            pub fn to_type(derived: *Derived) *DI.Type {
                return @ptrCast(derived);
            }
        };
    };

    pub const Flags = packed struct(u32) {
        visibility: Visibility = .none,
        forward_declaration: bool = false,
        apple_block: bool = false,
        block_by_ref_struct: bool = false,
        virtual: bool = false,
        artificial: bool = false,
        explicit: bool = false,
        prototyped: bool = false,
        objective_c_class_complete: bool = false,
        object_pointer: bool = false,
        vector: bool = false,
        static_member: bool = false,
        lvalue_reference: bool = false,
        rvalue_reference: bool = false,
        reserved: bool = false,
        inheritance: Inheritance = .none,
        introduced_virtual: bool = false,
        bit_field: bool = false,
        no_return: bool = false,
        type_pass_by_value: bool = false,
        type_pass_by_reference: bool = false,
        enum_class: bool = false,
        thunk: bool = false,
        non_trivial: bool = false,
        big_endian: bool = false,
        little_endian: bool = false,
        all_calls_described: bool = false,
        _: u3 = 0,

        const Visibility = enum(u2) {
            none = 0,
            private = 1,
            protected = 2,
            public = 3,
        };
        const Inheritance = enum(u2) {
            none = 0,
            single = 1,
            multiple = 2,
            virtual = 3,
        };
    };
};

pub const Type = opaque {
    pub const Kind = enum(c_uint) {
        Void,
        Half,
        Float,
        Double,
        X86_FP80,
        FP128,
        PPC_FP128,
        Label,
        Integer,
        Function,
        Struct,
        Array,
        Pointer,
        Vector,
        Metadata,
        X86_MMX,
        Token,
        ScalableVector,
        BFloat,
        X86_AMX,
        TargetExt,
    };

    pub const get_kind = api.LLVMGetTypeKind;
    pub const get_poison = api.LLVMGetPoison;

    pub fn to_integer(ty: *Type) *Type.Integer {
        assert(ty.get_kind() == .Integer);
        return @ptrCast(ty);
    }

    pub fn to_function(ty: *Type) *Type.Function {
        assert(ty.get_kind() == .Function);
        return @ptrCast(ty);
    }

    pub fn to_struct(ty: *Type) *Type.Struct {
        assert(ty.get_kind() == .Struct);
        return @ptrCast(ty);
    }

    pub const Function = opaque {
        pub const get_return_type = api.LLVMGetReturnType;
        pub fn get(return_type: *Type, parameter_types: []const *Type, is_var_args: bool) *Type.Function {
            return api.LLVMFunctionType(return_type, parameter_types.ptr, @intCast(parameter_types.len), @intFromBool(is_var_args));
        }

        pub fn to_type(function_type: *Type.Function) *Type {
            return @ptrCast(function_type);
        }
    };

    pub const Integer = opaque {
        pub const get_constant = api.LLVMConstInt;
        pub fn to_type(integer: *Type.Integer) *Type {
            return @ptrCast(integer);
        }
        pub const get_bit_count = api.llvm_integer_type_get_bit_count;
    };

    pub const Struct = opaque {
        pub fn to_type(struct_type: *Type.Struct) *Type {
            return @ptrCast(struct_type);
        }

        pub fn set_body(struct_type: *Type.Struct, element_types: []const *Type) void {
            const is_packed = false;
            api.LLVMStructSetBody(struct_type, element_types.ptr, @intCast(element_types.len), @intFromBool(is_packed));
        }
    };

    pub const Array = opaque {
        pub fn to_type(array_type: *Type.Array) *Type {
            return @ptrCast(array_type);
        }
    };

    pub const Pointer = opaque {
        pub fn to_type(pointer_type: *Type.Pointer) *Type {
            return @ptrCast(pointer_type);
        }
    };

    pub fn get_array_type(element_type: *Type, element_count: u64) *Type.Array {
        return api.LLVMArrayType2(element_type, element_count);
    }

    pub fn get_constant_array(element_type: *Type, values: []const *Constant) *Constant.Array {
        return api.LLVMConstArray2(element_type, values.ptr, values.len);
    }
};

pub const Dwarf = struct {
    pub const Type = enum(c_uint) {
        void = 0x0,
        address = 0x1,
        boolean = 0x2,
        complex_float = 0x3,
        float = 0x4,
        signed = 0x5,
        signed_char = 0x6,
        unsigned = 0x7,
        unsigned_char = 0x8,

        // DWARF 3.
        imaginary_float = 0x9,
        packed_decimal = 0xa,
        numeric_string = 0xb,
        edited = 0xc,
        signed_fixed = 0xd,
        unsigned_fixed = 0xe,
        decimal_float = 0xf,

        // DWARF 4.
        UTF = 0x10,

        // DWARF 5.
        UCS = 0x11,
        ASCII = 0x12,

        // HP extensions.
        HP_float80 = 0x80, // Floating-point (80 bit).
        HP_complex_float80 = 0x81, // Complex floating-point (80 bit).
        HP_float128 = 0x82, // Floating-point (128 bit).
        HP_complex_float128 = 0x83, // Complex fp (128 bit).
        HP_floathpintel = 0x84, // Floating-point (82 bit IA64).
        HP_imaginary_float80 = 0x85,
        HP_imaginary_float128 = 0x86,
        HP_VAX_float = 0x88, // F or G floating.
        HP_VAX_float_d = 0x89, // D floating.
        HP_packed_decimal = 0x8a, // Cobol.
        HP_zoned_decimal = 0x8b, // Cobol.
        HP_edited = 0x8c, // Cobol.
        HP_signed_fixed = 0x8d, // Cobol.
        HP_unsigned_fixed = 0x8e, // Cobol.
        HP_VAX_complex_float = 0x8f, // F or G floating complex.
        HP_VAX_complex_float_d = 0x90, // D floating complex.
    };

    pub const EmissionKind = enum(c_int) {
        none,
        full,
        line_tables_only,
    };

    pub const SourceLanguage = enum(c_int) {
        C89,
        C,
        Ada83,
        C_plus_plus,
        Cobol74,
        Cobol85,
        Fortran77,
        Fortran90,
        Pascal83,
        Modula2,
        // New in DWARF v3:
        Java,
        C99,
        Ada95,
        Fortran95,
        PLI,
        ObjC,
        ObjC_plus_plus,
        UPC,
        D,
        // New in DWARF v4:
        Python,
        // New in DWARF v5:
        OpenCL,
        Go,
        Modula3,
        Haskell,
        C_plus_plus_03,
        C_plus_plus_11,
        OCaml,
        Rust,
        C11,
        Swift,
        Julia,
        Dylan,
        C_plus_plus_14,
        Fortran03,
        Fortran08,
        RenderScript,
        BLISS,
        Kotlin,
        Zig,
        Crystal,
        C_plus_plus_17,
        C_plus_plus_20,
        C17,
        Fortran18,
        Ada2005,
        Ada2012,
        HIP,
        Assembly,
        C_sharp,
        Mojo,
        GLSL,
        GLSL_ES,
        HLSL,
        OpenCL_CPP,
        CPP_for_OpenCL,
        SYCL,
        Ruby,
        Move,
        Hylo,

        // Vendor extensions:
        Mips_Assembler,
        GOOGLE_RenderScript,
        BORLAND_Delphi,
    };
};

pub fn lookup_intrinsic_id(name: []const u8) Intrinsic.Id {
    return api.LLVMLookupIntrinsicID(name.ptr, name.len);
}

pub fn lookup_attribute_kind(name: []const u8) Attribute.Kind {
    return api.LLVMGetEnumAttributeKindForName(name.ptr, name.len);
}

pub const IntPredicate = enum(c_int) {
    eq = 32,
    ne,
    ugt,
    uge,
    ult,
    ule,
    sgt,
    sge,
    slt,
    sle,
};

pub const LinkageType = enum(c_int) {
    ExternalLinkage,
    AvailableExternallyLinkage,
    LinkOnceAnyLinkage,
    LinkOnceODRLinkage,
    WeakAnyLinkage,
    WeakODRLinkage,
    AppendingLinkage,
    InternalLinkage,
    PrivateLinkage,
    ExternalWeakLinkage,
    CommonLinkage,
};

pub const ThreadLocalMode = enum(c_uint) {
    none = 0,
};

pub const CallingConvention = enum(c_uint) {
    c = 0,
    fast = 8,
    cold = 9,
    ghc = 10,
    hipe = 11,
    anyreg = 13,
    preserve_most = 14,
    preserve_all = 15,
    swift = 16,
    cxx_fast_tls = 17,
    x86_stdcall = 64,
    x86_fastcall = 65,
    arm_apcs = 66,
    arm_aapcs = 67,
    arm_aapcsvfp = 68,
    msp430_interrupt = 69,
    x86_thiscall = 70,
    ptx_kernel = 71,
    ptx_device = 72,
    spir_func = 75,
    spir_kernel = 76,
    intel_oclbi = 77,
    x86_64_system_v = 78,
    win64 = 79,
    x86_vector = 80,
    hhvm = 81,
    hhvmc = 82,
    x86_interrupt = 83,
    avr_interrupt = 84,
    avr_signal = 85,
    avr_builtin = 86,
    amdgpu_vs = 87,
    amdgpu_gs = 88,
    amdgpu_ps = 89,
    amdgpu_cs = 90,
    amdgpu_kernel = 91,
    x86_regcall = 92,
    amdgpu_hs = 93,
    msp430_builtin = 94,
    amgpu_ls = 95,
    amdgpu_es = 96,
};

pub const lld = struct {
    pub const Result = extern struct {
        stdout: String,
        stderr: String,
        success: bool,
    };
};

pub const Global = struct {
    host_triple: []const u8,
    host_cpu_model: []const u8,
    host_cpu_features: []const u8,
};
pub var global: Global = undefined;

pub var initialized = false;

// This is meant to call globally, only once per execution
pub fn initialize_all() void {
    assert(!initialized);
    defer initialized = true;
    inline for (targets) |target| {
        target.initialize(.{});
    }

    global = .{
        .host_triple = api.llvm_default_target_triple().to_slice() orelse unreachable,
        .host_cpu_model = api.llvm_host_cpu_name().to_slice() orelse unreachable,
        .host_cpu_features = api.llvm_host_cpu_features().to_slice() orelse unreachable,
    };
}

const LldArgvBuilder = struct {
    buffer: [1024]?[*:0]const u8 = undefined,
    count: usize = 0,

    pub fn add(builder: *LldArgvBuilder, arg: [*:0]const u8) void {
        builder.buffer[builder.count] = arg;
        builder.count += 1;
    }

    pub fn flush(builder: *LldArgvBuilder) [:null]const ?[*:0]const u8 {
        builder.buffer[builder.count] = null;
        return builder.buffer[0..builder.count :null];
    }
};

pub fn default_initialize() void {
    if (!initialized) {
        initialize_all();
    }
}

pub const GenerateObject = struct {
    path: []const u8,
    target_triple: []const u8,
    cpu_model: []const u8,
    cpu_features: []const u8,
    target_options: Target.Options,
};

pub const ObjectGenerate = struct {
    path: []const u8,
    optimization_level: ?OptimizationLevel,
    debug_info: bool,
    optimize_when_possible: u1,
};

pub fn object_generate(module: *Module, target_machine: *Target.Machine, generate: ObjectGenerate) CodeGenerationPipelineResult {
    module.set_target(target_machine);

    if (generate.optimization_level) |optimization_level| {
        module.run_optimization_pipeline(target_machine, OptimizationPipelineOptions.default(.{ .optimization_level = optimization_level, .debug_info = @intFromBool(generate.debug_info) }));
    }

    const result = module.run_code_generation_pipeline(target_machine, CodeGenerationPipelineOptions{
        .output_file_path = String.from_slice(generate.path),
        .output_dwarf_file_path = .{},
        .flags = .{
            .code_generation_file_type = .object_file,
            .optimize_when_possible = generate.optimize_when_possible,
            .verify_module = @intFromBool(lib.optimization_mode == .Debug or lib.optimization_mode == .ReleaseSafe),
        },
    });

    return result;
}

pub const LinkOptions = struct {
    objects: []const [:0]const u8,
    output_path: [:0]const u8,
};

pub fn link(arena: *Arena, options: LinkOptions) lld.Result {
    var arg_builder = LldArgvBuilder{};
    arg_builder.add("ld.lld");
    arg_builder.add("--error-limit=0");
    arg_builder.add("-o");
    arg_builder.add(options.output_path);
    for (options.objects) |object| {
        arg_builder.add(object);
    }

    const library_paths = [_][:0]const u8{ "/usr/lib", "/usr/lib/x86_64-linux-gnu" };

    const scrt1_object_directory_path = inline for (library_paths) |library_path| {
        const scrt1_path = library_path ++ "/" ++ "Scrt1.o";
        const file = lib.os.File.open(scrt1_path, .{ .read = 1 }, .{});
        if (file.is_valid()) {
            file.close();
            break library_path;
        }
    } else {
        lib.print_string_stderr("Failed to find directory for Scrt1.o\n");
        lib.os.abort();
    };

    arg_builder.add(arena.join_string(&.{ "-L", scrt1_object_directory_path }));

    const link_libcpp = false;
    if (link_libcpp) {
        arg_builder.add("-lstdc++");
    }

    const link_libc = true;

    const dynamic_linker = true;
    if (dynamic_linker) {
        arg_builder.add("-dynamic-linker");

        const dynamic_linker_path = "/usr/lib64/ld-linux-x86-64.so.2";
        arg_builder.add(dynamic_linker_path);
    }

    if (link_libc) {
        arg_builder.add(arena.join_string(&.{ scrt1_object_directory_path, "/", "Scrt1.o" }));
        arg_builder.add("-lc");
    }

    const lld_args = arg_builder.flush();
    const lld_result = api.lld_elf_link(lld_args.ptr, lld_args.len, true, false);
    const success = lld_result.success and lld_result.stderr.length == 0;
    if (!success) {
        for (lld_args) |lld_arg| {
            lib.print_string_stderr(lib.cstring.to_slice(lld_arg.?));
            lib.print_string_stderr(" ");
        }
        lib.print_string_stderr("\n");

        if (lld_result.stdout.length != 0) {
            lib.print_string_stderr(lld_result.stdout.to_slice() orelse unreachable);
        }

        if (lld_result.stderr.length != 0) {
            lib.print_string_stderr(lld_result.stderr.to_slice() orelse unreachable);
        }
    }

    return lld_result;
}
