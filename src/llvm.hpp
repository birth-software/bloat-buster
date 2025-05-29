#pragma once

#include <lib.hpp>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/TargetMachine.h>

struct LLDResult
{
    String stdout_string;
    String stderr_string;
    bool success;
};

enum class BBLLVMCodeGenerationPipelineResult : u8
{
    success = 0,
    failed_to_create_file = 1,
    failed_to_add_emit_passes = 2,
};

enum class BBLLVMCodeGenerationFileType : u8
{
    assembly_file = 0,
    object_file = 1,
    null = 2,
};

#define BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT (60)

struct BBLLVMCodeGenerationPipelineOptions
{
    String output_dwarf_file_path;
    String output_file_path;
    u64 code_generation_file_type:2;
    u64 optimize_when_possible:1;
    u64 verify_module:1;
    u64 reserved: BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMCodeGenerationPipelineOptions) == 5 * sizeof(u64));
static_assert(BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT == 60);

enum class BBLLVMOptimizationLevel : u8
{
    O0 = 0,
    O1 = 1,
    O2 = 2,
    O3 = 3,
    Os = 4,
    Oz = 5,
};

#define BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT (51)
struct BBLLVMOptimizationPipelineOptions
{
    u64 optimization_level:3;
    u64 debug_info:1;
    u64 loop_unrolling:1;
    u64 loop_interleaving:1;
    u64 loop_vectorization:1;
    u64 slp_vectorization:1;
    u64 merge_functions:1;
    u64 call_graph_profile:1;
    u64 unified_lto:1;
    u64 assignment_tracking:1;
    u64 verify_module:1;
    u64 reserved:BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMOptimizationPipelineOptions) == sizeof(u64));
static_assert(BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT == 51);

enum class BBLLVMUWTableKind : u64
{
    None = 0,  ///< No unwind table requested
    Sync = 1,  ///< "Synchronous" unwind tables
    Async = 2, ///< "Asynchronous" unwind tables (instr precise)
    Default = 2,
};

enum class BBLLVMFramePointerKind : u64
{
    none = 0,
    reserved = 1,
    non_leaf = 2,
    all = 3,
};

enum class ZeroCallUsedRegsKind : u64
{
    all = 0,
    skip = 1 << 0,
    only_used = 1 << 1,
    only_gpr = 1 << 2,
    only_arg = 1 << 3,
    used_gpr_arg = only_used | only_gpr | only_arg,
    used_gpr = only_used | only_gpr,
    used_arg = only_used | only_arg,
    used = only_used,
    all_gpr_arg = only_gpr | only_arg,
    all_gpr = only_gpr,
    all_arg = only_arg,
};

struct BBLLVMFunctionAttributesFlags0
{
    u64 noreturn:1;
    u64 cmse_ns_call:1;
    u64 nounwind:1;
    u64 returns_twice:1;
    u64 cold:1;
    u64 hot:1;
    u64 no_duplicate:1;
    u64 convergent:1;
    u64 no_merge:1;
    u64 will_return:1;
    u64 no_caller_saved_registers:1;
    u64 no_cf_check:1;
    u64 no_callback:1;
    u64 alloc_size:1;
    u64 uniform_work_group_size:1;
    u64 aarch64_pstate_sm_body:1;
    u64 aarch64_pstate_sm_enabled:1;
    u64 aarch64_pstate_sm_compatible:1;
    u64 aarch64_preserves_za:1;
    u64 aarch64_in_za:1;
    u64 aarch64_out_za:1;
    u64 aarch64_inout_za:1;
    u64 aarch64_preserves_zt0:1;
    u64 aarch64_in_zt0:1;
    u64 aarch64_out_zt0:1;
    u64 aarch64_inout_zt0:1;
    u64 optimize_for_size:1;
    u64 min_size:1;
    u64 no_red_zone:1;
    u64 indirect_tls_seg_refs:1;
    u64 no_implicit_floats:1;
    u64 sample_profile_suffix_elision_policy:1;
    u64 memory_none:1;
    u64 memory_readonly:1;
    u64 memory_inaccessible_or_arg_memory_only:1;
    u64 memory_arg_memory_only:1;
    u64 strict_fp:1;
    u64 no_inline:1;
    u64 always_inline:1;
    u64 guard_no_cf:1;

    // TODO: branch protection function attributes
    // TODO: cpu features

    // Call-site begin
    u64 call_no_builtins:1;

    BBLLVMFramePointerKind definition_frame_pointer_kind:2;
    u64 definition_less_precise_fpmad:1;
    u64 definition_null_pointer_is_valid:1;
    u64 definition_no_trapping_fp_math:1;
    u64 definition_no_infs_fp_math:1;
    u64 definition_no_nans_fp_math:1;
    u64 definition_approx_func_fp_math:1;
    u64 definition_unsafe_fp_math:1;
    u64 definition_use_soft_float:1;
    u64 definition_no_signed_zeroes_fp_math:1;
    u64 definition_stack_realignment:1;
    u64 definition_backchain:1;
    u64 definition_split_stack:1;
    u64 definition_speculative_load_hardening:1;
    ZeroCallUsedRegsKind definition_zero_call_used_registers:4;
    // TODO: denormal builtins
    u64 definition_non_lazy_bind:1;
    u64 definition_cmse_nonsecure_entry:1;
    BBLLVMUWTableKind definition_unwind_table_kind:2;
};

static_assert(sizeof(BBLLVMFunctionAttributesFlags0) == sizeof(u64));

struct BBLLVMFunctionAttributesFlags1
{
    u64 definition_disable_tail_calls:1;
    u64 definition_stack_protect_strong:1;
    u64 definition_stack_protect:1;
    u64 definition_stack_protect_req:1;
    u64 definition_aarch64_new_za:1;
    u64 definition_aarch64_new_zt0:1;
    u64 definition_optimize_none:1;
    u64 definition_naked:1;
    u64 definition_inline_hint:1;
    u64 _:55;
};

static_assert(sizeof(BBLLVMFunctionAttributesFlags1) == sizeof(u64));

struct BBLLVMFunctionAttributes
{
    String prefer_vector_width;
    String stack_protector_buffer_size;
    String definition_probe_stack;
    String definition_stack_probe_size;

    BBLLVMFunctionAttributesFlags0 flags0;
    BBLLVMFunctionAttributesFlags1 flags1;
};

static_assert(sizeof(BBLLVMFunctionAttributes) == 10 * sizeof(u64));

struct BBLLVMArgumentAttributes
{
    LLVMTypeRef semantic_type;
    LLVMTypeRef abi_type;
    u64 dereferenceable_bytes;
    u32 alignment;
    u32 no_alias:1;
    u32 non_null:1;
    u32 no_undef:1;
    u32 sign_extend:1;
    u32 zero_extend:1;
    u32 in_reg:1;
    u32 no_fp_class:10;
    u32 struct_return:1;
    u32 writable:1;
    u32 dead_on_unwind:1;
    u32 in_alloca:1;
    u32 dereferenceable:1;
    u32 dereferenceable_or_null:1;
    u32 nest:1;
    u32 by_value:1;
    u32 by_reference:1;
    u32 no_capture:1;
    u32 _:6;
};

static_assert(sizeof(BBLLVMArgumentAttributes) == 2 * sizeof(LLVMTypeRef) + 2 * sizeof(u64));

struct BBLLVMAttributeListOptions
{
    BBLLVMFunctionAttributes function;
    BBLLVMArgumentAttributes return_;
    BBLLVMArgumentAttributes* argument_pointer;
    u64 argument_count;
};

static_assert(sizeof(BBLLVMAttributeListOptions) == sizeof(BBLLVMFunctionAttributes) + sizeof(BBLLVMArgumentAttributes) + sizeof(void*) + sizeof(u64));

typedef void* BBLLVMAttributeList;

enum class DwarfEmissionKind
{
    none,
    full,
    line_tables_only,
};

enum class DwarfType
{
    void_type = 0x0,
    address = 0x1,
    boolean = 0x2,
    complex_float = 0x3,
    float_type = 0x4,
    signed_type = 0x5,
    signed_char = 0x6,
    unsigned_type = 0x7,
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

enum class DIFlagsVisibility : u32
{
    none = 0,
    private_ = 1,
    protected_ = 2,
    public_ = 3,
};

enum class DIFlagsInheritance : u32
{
    none = 0,
    single_ = 1,
    multiple_ = 2,
    virtual_ = 3,
};

struct DIFlags
{
    DIFlagsVisibility visibility:2;
    u32 forward_declaration:1;
    u32 apple_block:1;
    u32 block_by_ref_struct:1;
    u32 virtual_:1;
    u32 artificial:1;
    u32 explicit_:1;
    u32 prototyped:1;
    u32 objective_c_class_complete:1;
    u32 object_pointer:1;
    u32 vector:1;
    u32 static_member:1;
    u32 lvalue_reference:1;
    u32 rvalue_reference:1;
    u32 reserved:1;
    DIFlagsInheritance inheritance:2;
    u32 introduced_virtual:1;
    u32 bit_field:1;
    u32 no_return:1;
    u32 type_pass_by_value:1;
    u32 type_pass_by_reference:1;
    u32 enum_class:1;
    u32 thunk:1;
    u32 non_trivial:1;
    u32 big_endian:1;
    u32 little_endian:1;
    u32 all_calls_described:1;
    u32 _:3;
};

static_assert(sizeof(DIFlags) == sizeof(u32));

enum class BBLLVMEmitDwarfUnwindType : u8
{
    always = 0,
    no_compact_unwind = 1,
    normal = 2,
};

enum class BBLLVMDwarfDirectory : u8
{
    disable = 0,
    enable = 1,
    normal = 2,
};

enum class BBLLVMDebugCompressionType : u8
{
    none = 0,
    zlib = 1,
    zstd = 2,
};

#define BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT (7)

struct BBLLVMMCTargetOptions
{
    String abi_name;
    String assembly_language;
    String split_dwarf_file;
    String as_secure_log_file;
    const char* argv0;
    String* argv_pointer;
    u64 argv_count;
    String* integrated_assembler_search_path_pointer;
    u64 integrated_assembler_search_path_count;
    u32 relax_all:1;
    u32 no_exec_stack:1;
    u32 fatal_warnings:1;
    u32 no_warn:1;
    u32 no_deprecated_warn:1;
    u32 no_type_check:1;
    u32 save_temp_labels:1;
    u32 incremental_linker_compatible:1;
    u32 fdpic:1;
    u32 show_mc_encoding:1;
    u32 show_mc_inst:1;
    u32 asm_verbose:1;
    u32 preserve_asm_comments:1 = true;
    u32 dwarf64:1;
    u32 crel:1;
    u32 x86_relax_relocations:1;
    u32 x86_sse2_avx:1;
    u32 emit_dwarf_unwind:2 = 2;
    u32 use_dwarf_directory:2 = 2;
    u32 debug_compression_type:2 = 0;
    u32 emit_compact_unwind_non_canonical:1;
    u32 ppc_use_full_register_names:1;
    u32 reserved:BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMMCTargetOptions) == 112);
static_assert(BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT == 7);

enum class BBLLVMCodeModel : u8
{
    none = 0,
    tiny = 1,
    small = 2,
    kernel = 3,
    medium = 4,
    large = 5,
};

enum class BBLLVMRelocationModel : u8
{
    default_relocation = 0,
    static_relocation = 1,
    pic = 2,
    dynamic_no_pic = 3,
    ropi = 4,
    rwpi = 5,
    ropi_rwpi = 6,
};

enum class BBLLVMCodeGenerationOptimizationLevel : u8
{
    none = 0,      // -O0
    less = 1,      // -O1
    normal = 2,   // -O2, -Os
    aggressive = 3 // -O3
};

enum class BBLLVMGlobalISelAbortMode : u8
{
    disable = 0,
    enable = 1,
    disable_with_diag = 2,
};

enum class BBLLVMSwiftAsyncFramePointerMode : u8
{
    deployment_based = 0,
    always = 1,
    never = 2,
};

enum class BBLLVMBasicBlockSection : u8
{
    all = 0,
    list = 1,
    preset = 2,
    none = 3,
};

enum class BBLLVMFloatAbi : u8
{
    normal = 0,
    soft = 1,
    hard = 2,
};

enum class BBLLVMFPOpFusion : u8
{
    fast = 0,
    standard = 1,
    strict = 2,
};

enum class BBLLVMThreadModel : u8
{
    posix = 0,
    single = 1,
};

enum class BBLLVMEAbi : u8
{
    unknown = 0,
    normal = 1,
    eabi4 = 2,
    eabi5 = 3,
    gnu = 4,
};

enum class BBLLVMDebuggerKind : u8
{
    normal = 0,
    gdb = 1,
    lldb = 2,
    sce = 3,
    dbx = 4,
};

enum class BBLLVMExceptionHandling : u8
{
    none = 0,
    dwarf_cfi = 1,
    setjmp_longjmp = 2,
    arm = 3,
    win_eh = 4,
    wasm = 5,
    aix = 6,
    zos = 7,
};

#define BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT (21)

struct BBLLVMTargetOptions
{
    u64 unsafe_fp_math:1;
    u64 no_infs_fp_math:1;
    u64 no_nans_fp_math:1;
    u64 no_trapping_fp_math:1 = true;
    u64 no_signed_zeroes_fp_math:1;
    u64 approx_func_fp_math:1;
    u64 enable_aix_extended_altivec_abi:1;
    u64 honor_sign_dependent_rounding_fp_math:1;
    u64 no_zeroes_in_bss:1;
    u64 guaranteed_tail_call_optimization:1;
    u64 stack_symbol_ordering:1 = true;
    u64 enable_fast_isel:1;
    u64 enable_global_isel:1 = 1;
    u64 global_isel_abort_mode:2;
    u64 swift_async_frame_pointer:2 = 1;
    u64 use_init_array:1;
    u64 disable_integrated_assembler:1;
    u64 function_sections:1;
    u64 data_sections:1;
    u64 ignore_xcoff_visibility:1;
    u64 xcoff_traceback_table:1 = true;
    u64 unique_section_names:1 = true;
    u64 unique_basic_block_section_names:1;
    u64 separate_named_sections:1;
    u64 trap_unreachable:1;
    u64 no_trap_after_noreturn:1;
    u64 tls_size:8;
    u64 emulated_tls:1;
    u64 enable_tls_descriptors:1;
    u64 enable_ipra:1;
    u64 emit_stack_size_section:1;
    u64 enable_machine_outliner:1;
    u64 enable_machine_function_splitter:1;
    u64 supports_default_outlining:1;
    u64 emit_address_significance_table:1;
    u64 bb_address_map:1;
    u64 bb_sections:3 = 3;
    u64 emit_call_site_information:1;
    u64 supports_debug_entry_values:1;
    u64 enable_debug_entry_values:1;
    u64 value_tracking_variable_locations:1;
    u64 force_dwarf_frame_section:1;
    u64 xray_function_index:1 = true;
    u64 debug_strict_dwarf:1;
    u64 hotpatch:1;
    u64 ppc_gen_scalar_mass_entries:1;
    u64 jmc_instrument:1;
    u64 enable_cfi_fixup:1;
    u64 mis_expect:1;
    u64 xcoff_read_only_pointers:1;
    u64 float_abi:2 = 0;
    u64 thread_model:1 = 0;
    u32 fp_op_fusion_mode:2 = 1;
    u32 eabi_version:3 = 1;
    u32 debugger_kind:3 = 0;
    u32 exception_handling:3 = 0;
    u32 reserved:BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT;
    unsigned loop_alignment = 0;
    int binutils_version[2];

    BBLLVMMCTargetOptions mc;
};

static_assert(sizeof(BBLLVMTargetOptions) == 136);
static_assert(BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT == 21);

#define BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT (4)

struct BBLLVMTargetMachineCreate
{
    BBLLVMTargetOptions target_options;
    String target_triple;
    String cpu_model;
    String cpu_features;
    BBLLVMRelocationModel relocation_model;
    BBLLVMCodeModel code_model;
    BBLLVMCodeGenerationOptimizationLevel optimization_level;
    bool jit;
    u8 reserved[BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT];
};

static_assert(sizeof(BBLLVMTargetMachineCreate) == 192);
static_assert(BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT == 4);

fn bool llvm_initialized = false;

extern "C" String llvm_default_target_triple();
extern "C" String llvm_host_cpu_name();
extern "C" String llvm_host_cpu_features();

extern "C" LLVMModuleRef llvm_context_create_module(LLVMContextRef context, String name);

extern "C" LLVMValueRef llvm_module_create_function(LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage_type, unsigned address_space, String name);
extern "C" void llvm_function_set_attributes(LLVMValueRef function, BBLLVMAttributeList attribute_list);

extern "C" LLVMBasicBlockRef llvm_context_create_basic_block(LLVMContextRef context, String name, LLVMValueRef parent_function);

extern "C" LLVMValueRef llvm_module_create_global_variable(LLVMModuleRef module, LLVMTypeRef type, bool is_constant, LLVMLinkage linkage_type, LLVMValueRef initial_value, String name, LLVMValueRef before, LLVMThreadLocalMode thread_local_mode, unsigned address_space, bool externally_initialized);

extern "C" LLVMValueRef llvm_builder_create_alloca(LLVMBuilderRef builder, LLVMTypeRef type, unsigned address_space, u32 alignment, String name);
extern "C" bool llvm_value_has_one_use(LLVMValueRef value);
extern "C" LLVMValueRef llvm_basic_block_user_begin(LLVMBasicBlockRef basic_block);
extern "C" void llvm_basic_block_delete(LLVMBasicBlockRef basic_block);
extern "C" bool llvm_basic_block_is_empty(LLVMBasicBlockRef basic_block);
extern "C" void llvm_function_set_attributes(LLVMValueRef f, BBLLVMAttributeList attribute_list_handle);
extern "C" void llvm_call_base_set_attributes(LLVMValueRef call_value, BBLLVMAttributeList attribute_list_handle);

extern "C" BBLLVMAttributeList llvm_attribute_list_build(LLVMContextRef context, BBLLVMAttributeListOptions* attributes, bool call_site);
extern "C" LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef b, LLVMValueRef ra, LLVMTypeRef et);
extern "C" bool llvm_value_use_empty(LLVMValueRef value);
extern "C" bool llvm_function_verify(LLVMValueRef function_value, String* error_message);
extern "C" bool llvm_module_verify(LLVMModuleRef m, String* error_message);

extern "C" void llvm_subprogram_replace_type(LLVMMetadataRef subprogram, LLVMMetadataRef subroutine_type);

extern "C" String llvm_module_to_string(LLVMModuleRef module);

extern "C" LLVMTargetMachineRef llvm_create_target_machine(const BBLLVMTargetMachineCreate* create, String* error_message);
extern "C" void llvm_module_set_target(LLVMModuleRef m, LLVMTargetMachineRef tm);
extern "C" void llvm_module_run_optimization_pipeline(LLVMModuleRef module, LLVMTargetMachineRef target_machine, BBLLVMOptimizationPipelineOptions options);
extern "C" BBLLVMCodeGenerationPipelineResult llvm_module_run_code_generation_pipeline(LLVMModuleRef m, LLVMTargetMachineRef tm, const BBLLVMCodeGenerationPipelineOptions* options);

#define lld_api_args() char* const* argument_pointer, u64 argument_count, bool exit_early, bool disable_output
#define lld_api_function_decl(link_name) LLDResult lld_ ## link_name ## _link(lld_api_args())
extern "C" lld_api_function_decl(elf);
