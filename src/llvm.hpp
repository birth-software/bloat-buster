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

struct BBLLVMCodeGenerationPipelineOptions
{
    String output_dwarf_file_path;
    String output_file_path;
    BBLLVMCodeGenerationFileType file_type;
    bool optimize_when_possible;
    bool verify_module;
};

static_assert(sizeof(BBLLVMCodeGenerationPipelineOptions) == 5 * sizeof(u64));

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


fn bool llvm_initialized = false;

extern "C" String llvm_default_target_triple();
extern "C" String llvm_host_cpu_name();
extern "C" String llvm_host_cpu_features();

extern "C" LLVMModuleRef llvm_context_create_module(LLVMContextRef context, String name);

extern "C" LLVMValueRef llvm_module_create_function(LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage_type, unsigned address_space, String name);

extern "C" LLVMBasicBlockRef llvm_context_create_basic_block(LLVMContextRef context, String name, LLVMValueRef parent_function);

extern "C" LLVMValueRef llvm_module_create_global_variable(LLVMModuleRef module, LLVMTypeRef type, bool is_constant, LLVMLinkage linkage_type, LLVMValueRef initial_value, String name, LLVMValueRef before, LLVMThreadLocalMode thread_local_mode, unsigned address_space, bool externally_initialized);

extern "C" LLVMValueRef llvm_builder_create_alloca(LLVMBuilderRef builder, LLVMTypeRef type, unsigned address_space, u32 alignment, String name);
extern "C" bool llvm_basic_block_is_empty(LLVMBasicBlockRef basic_block);

extern "C" LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef b, LLVMValueRef ra, LLVMTypeRef et);
extern "C" bool llvm_value_use_empty(LLVMValueRef value);
extern "C" bool llvm_function_verify(LLVMValueRef function_value, String* error_message);
extern "C" bool llvm_module_verify(LLVMModuleRef m, String* error_message);

extern "C" void llvm_subprogram_replace_type(LLVMMetadataRef subprogram, LLVMMetadataRef subroutine_type);

extern "C" String llvm_module_to_string(LLVMModuleRef module);

extern "C" void llvm_module_run_optimization_pipeline(LLVMModuleRef module, LLVMTargetMachineRef target_machine, BBLLVMOptimizationPipelineOptions options);
extern "C" BBLLVMCodeGenerationPipelineResult llvm_module_run_code_generation_pipeline(LLVMModuleRef m, LLVMTargetMachineRef tm, const BBLLVMCodeGenerationPipelineOptions* options);

#define lld_api_args() char* const* argument_pointer, u64 argument_count, bool exit_early, bool disable_output
#define lld_api_function_decl(link_name) LLDResult lld_ ## link_name ## _link(lld_api_args())
extern "C" lld_api_function_decl(elf);
