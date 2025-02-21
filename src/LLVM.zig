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
};

pub const BasicBlock = opaque {};

pub const Module = opaque {
    pub const create_di_builder = api.LLVMCreateDIBuilder;
    pub const set_target = api.llvm_module_set_target;
    pub const run_optimization_pipeline = api.llvm_module_run_optimization_pipeline;
    pub const run_code_generation_pipeline = api.llvm_module_run_code_generation_pipeline;

    pub fn to_string(module: *Module) []const u8 {
        return api.llvm_module_to_string(module).to_slice().?;
    }

    const FunctionCreate = struct {
        type: *Type.Function,
        linkage: LinkageType,
        address_space: c_uint = 0,
        name: []const u8,
    };

    pub fn create_function(module: *Module, create: FunctionCreate) *Function {
        return api.llvm_module_create_function(module, create.type, create.linkage, create.address_space, String.from_slice(create.name));
    }

    pub fn verify(module: *Module) VerifyResult {
        var result: VerifyResult = undefined;
        var string: String = undefined;
        result.success = api.llvm_module_verify(module, &string);
        result.error_message = string.to_slice();
        return result;
    }
};

pub const VerifyResult = struct {
    error_message: ?[]const u8,
    success: bool,
};

pub const Builder = opaque {
    pub const position_at_end = api.LLVMPositionBuilderAtEnd;

    pub const create_ret = api.LLVMBuildRet;
    pub fn create_add(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildAdd(builder, left, right, "");
    }

    pub fn create_sub(builder: *Builder, left: *Value, right: *Value) *Value {
        return api.LLVMBuildSub(builder, left, right, "");
    }

    pub fn create_ret_void(builder: *Builder) void {
        builder.create_ret(null);
    }
};

pub const GlobalValue = opaque {
    pub const get_type = api.LLVMGlobalGetValueType;
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
};

pub const Value = opaque {
    pub const get_type = api.LLVMTypeOf;
};

pub const DI = struct {
    pub const Builder = opaque {
        pub fn create_file(builder: *DI.Builder, file_name: []const u8, directory_name: []const u8) *File {
            return api.LLVMCreateDIBuilder(builder, file_name.ptr, file_name.len, directory_name.ptr, directory_name.len);
        }
    };
    pub const File = opaque {};

    const Flags = enum(c_int) {
        _,
        const Zero = 0;
        const Private = 1;
        const Protected = 2;
        const Public = 3;
        const FwdDecl = 1 << 2;
        const AppleBlock = 1 << 3;
        const ReservedBit4 = 1 << 4;
        const Virtual = 1 << 5;
        const Artificial = 1 << 6;
        const Explicit = 1 << 7;
        const Prototyped = 1 << 8;
        const ObjcClassComplete = 1 << 9;
        const ObjectPointer = 1 << 10;
        const Vector = 1 << 11;
        const StaticMember = 1 << 12;
        const LValueReference = 1 << 13;
        const RValueReference = 1 << 14;
        const Reserved = 1 << 15;
        const SingleInheritance = 1 << 16;
        const MultipleInheritance = 2 << 16;
        const VirtualInheritance = 3 << 16;
        const IntroducedVirtual = 1 << 18;
        const BitField = 1 << 19;
        const NoReturn = 1 << 20;
        const TypePassByValue = 1 << 22;
        const TypePassByReference = 1 << 23;
        const EnumClass = 1 << 24;
        const Thunk = 1 << 25;
        const NonTrivial = 1 << 26;
        const BigEndian = 1 << 27;
        const LittleEndian = 1 << 28;
        const IndirectVirtualBase = (1 << 2) | (1 << 5);
        const Accessibility = Private | Protected | Public;
        const PtrToMemberRep = SingleInheritance | MultipleInheritance | VirtualInheritance;
    };
};

pub const Type = opaque {
    pub const is_function = api.llvm_type_is_function;
    pub const is_integer = api.llvm_type_is_integer;
    pub fn to_function(t: *Type) *Type.Function {
        assert(t.is_function());
        return @ptrCast(t);
    }

    pub fn to_integer(t: *Type) *Type.Integer {
        assert(t.is_integer());
        return @ptrCast(t);
    }

    pub const Function = opaque {
        pub const get_return_type = api.LLVMGetReturnType;
        pub fn get(return_type: *Type, parameter_types: []const *Type, is_var_args: bool) *Type.Function {
            return api.LLVMFunctionType(return_type, parameter_types.ptr, @intCast(parameter_types.len), @intFromBool(is_var_args));
        }
    };

    pub const Integer = opaque {
        pub const get_constant = api.LLVMConstInt;
        pub fn to_type(integer: *Type.Integer) *Type {
            return @ptrCast(integer);
        }
    };
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

pub const DwarfSourceLanguage = enum(c_int) {
    c17 = 0x2c,
};
pub const DwarfEmissionKind = enum(c_int) {
    none,
    full,
    line_tables_only,
};

pub const lld = struct {
    pub const Result = extern struct {
        stdout: String,
        stderr: String,
        success: bool,
    };
};

pub const Thread = struct {
    context: *Context,
    builder: *Builder,
    i1: Integer,
    i8: Integer,
    i16: Integer,
    i32: Integer,
    i64: Integer,
    i128: Integer,

    pub const Integer = struct {
        type: *Type.Integer,
        zero: *Constant.Integer,
    };

    pub fn initialize(thread: *Thread) void {
        const context = Context.create();
        const type_i1 = api.LLVMInt1TypeInContext(context);
        const type_i8 = api.LLVMInt8TypeInContext(context);
        const type_i16 = api.LLVMInt16TypeInContext(context);
        const type_i32 = api.LLVMInt32TypeInContext(context);
        const type_i64 = api.LLVMInt64TypeInContext(context);
        const type_i128 = api.LLVMInt128TypeInContext(context);
        const zero_i1 = type_i1.get_constant(0, 0);
        const zero_i8 = type_i8.get_constant(0, 0);
        const zero_i16 = type_i16.get_constant(0, 0);
        const zero_i32 = type_i32.get_constant(0, 0);
        const zero_i64 = type_i64.get_constant(0, 0);
        const zero_i128 = type_i128.get_constant(0, 0);

        thread.* = .{
            .context = context,
            .builder = context.create_builder(),
            .i1 = .{
                .type = type_i1,
                .zero = zero_i1,
            },
            .i8 = .{
                .type = type_i8,
                .zero = zero_i8,
            },
            .i16 = .{
                .type = type_i16,
                .zero = zero_i16,
            },
            .i32 = .{
                .type = type_i32,
                .zero = zero_i32,
            },
            .i64 = .{
                .type = type_i64,
                .zero = zero_i64,
            },
            .i128 = .{
                .type = type_i128,
                .zero = zero_i128,
            },
        };
    }
};

pub const Global = struct {
    threads: []Thread,
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
        .threads = lib.global.arena.allocate(Thread, lib.global.thread_count),
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

pub const FunctionBuilder = struct {
    function: *Function,
    current_basic_block: *BasicBlock,
};

pub fn default_initialize() *Thread {
    assert(lib.GlobalState.initialized);
    if (!initialized) {
        initialize_all();
    }

    const thread = &global.threads[0];
    thread.initialize();

    return thread;
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
    debug_info: u1,
    optimize_when_possible: u1,
};

pub fn object_generate(module: *Module, target_machine: *Target.Machine, generate: ObjectGenerate) CodeGenerationPipelineResult {
    module.set_target(target_machine);

    if (generate.optimization_level) |optimization_level| {
        module.run_optimization_pipeline(target_machine, OptimizationPipelineOptions.default(.{ .optimization_level = optimization_level, .debug_info = generate.debug_info }));
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
        const scrt1_path = arena.join_string(&.{ scrt1_object_directory_path, "/Scrt1.o" });
        arg_builder.add(scrt1_path);
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
