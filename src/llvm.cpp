#include <stdint.h>

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/SubtargetFeature.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/MC/TargetRegistry.h"

#define EXPORT extern "C"
#define fn static

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

using namespace llvm;

struct BBLLVMString
{
    const char* pointer;
    size_t length;

    inline StringRef string_ref() const
    {
        return { pointer, length };
    }
};

EXPORT Module* llvm_context_create_module(LLVMContext& context, BBLLVMString name)
{
    return new Module(name.string_ref(), context);
}

EXPORT Value* llvm_builder_create_add(IRBuilder<>& builder, Value* left, Value* right, bool nuw, bool nsw)
{
    auto* result = builder.CreateAdd(left, right, "", nuw, nsw);
    return result;
}

EXPORT Function* llvm_module_create_function(Module* module, FunctionType* function_type, GlobalValue::LinkageTypes linkage_type, unsigned address_space, BBLLVMString name)
{
    auto* function = Function::Create(function_type, linkage_type, address_space, name.string_ref(), module);
    return function;
}

EXPORT StructType* llvm_context_create_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, BBLLVMString name, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto* struct_type = StructType::create(context, types, name.string_ref(), is_packed);
    return struct_type;
}

EXPORT StructType* llvm_context_get_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto* struct_type = StructType::get(context, types, is_packed);
    return struct_type;
}

EXPORT BasicBlock* llvm_context_create_basic_block(LLVMContext& context, BBLLVMString name, Function* parent)
{
    auto* basic_block = BasicBlock::Create(context, name.string_ref(), parent);
    return basic_block;
}

fn BBLLVMString stream_to_string(raw_string_ostream& stream)
{
    // No need to call stream.flush(); because it's string-based
    stream.flush();

    auto string = stream.str();
    auto length = string.length();

    char* result = 0;
    if (length)
    {
        result = new char[length];
        memcpy(result, string.c_str(), length);
    }

    return { result, length };
}

EXPORT bool llvm_function_verify(Function& function, BBLLVMString* error_message)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyFunction(function, &message_stream);
    auto size = message_stream.str().size();
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT bool llvm_module_verify(const Module& module, BBLLVMString* error_message)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyModule(module, &message_stream);
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT BBLLVMString llvm_module_to_string(Module* module)
{
    std::string buffer;
    raw_string_ostream stream(buffer);
    module->print(stream, 0);

    return stream_to_string(stream);
}

EXPORT BBLLVMString llvm_default_target_triple()
{
    auto triple = llvm::sys::getDefaultTargetTriple();
    auto length = triple.length();

    char* pointer = 0;
    if (length)
    {
        pointer = new char[length];
        memcpy(pointer, triple.c_str(), length);
    }

    return { pointer, length };
}

EXPORT BBLLVMString llvm_host_cpu_name()
{
    auto cpu = llvm::sys::getHostCPUName();
    return { cpu.data(), cpu.size() };
}

EXPORT BBLLVMString llvm_host_cpu_features()
{
    SubtargetFeatures Features;
    for (const auto &[Feature, IsEnabled] : sys::getHostCPUFeatures())
    {
        Features.AddFeature(Feature, IsEnabled);
    }

    auto feature_string = Features.getString();
    auto length = feature_string.length();

    char* result = 0;
    if (length)
    {
        result = new char[length];
        memcpy(result, feature_string.c_str(), length);
    }

    return { result, length };
}

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

struct BBLLVMMCTargetOptions
{
    BBLLVMString abi_name;
    BBLLVMString assembly_language;
    BBLLVMString split_dwarf_file;
    BBLLVMString as_secure_log_file;
    const char* argv0;
    BBLLVMString* argv_pointer;
    u64 argv_count;
    BBLLVMString* integrated_assembler_search_path_pointer;
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
    u32 preserve_asm_comments:1;
    u32 dwarf64:1;
    u32 crel:1;
    u32 x86_relax_relocations:1;
    u32 x86_sse2_avx:1;
    u32 emit_dwarf_unwind:2;
    u32 use_dwarf_directory:2;
    u32 debug_compression_type:2;
    u32 emit_compact_unwind_non_canonical:1;
    u32 ppc_use_full_register_names:1;
    u32 reserved:7;
};
static_assert(sizeof(BBLLVMMCTargetOptions) == 112);

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
    labels = 2,
    preset = 3,
    none = 4,
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

struct BBLLVMTargetOptions
{
    u64 unsafe_fp_math:1;
    u64 no_infs_fp_math:1;
    u64 no_nans_fp_math:1;
    u64 no_trapping_fp_math:1;
    u64 no_signed_zeroes_fp_math:1;
    u64 approx_func_fp_match:1;
    u64 enable_aix_extended_altivec_abi:1;
    u64 honor_sign_dependent_rounding_fp_math:1;
    u64 no_zeroes_in_bss:1;
    u64 guaranteed_tail_call_optimization:1;
    u64 stack_symbol_ordering:1;
    u64 enable_fast_isel:1;
    u64 enable_global_isel:1;
    u64 global_isel_abort_mode:2;
    u64 swift_async_frame_pointer:2;
    u64 use_init_array:1;
    u64 disabled_integrated_assembler:1;
    u64 function_sections:1;
    u64 data_sections:1;
    u64 ignore_xcoff_visibility:1;
    u64 xcoff_traceback_table:1;
    u64 unique_section_names:1;
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
    u64 bb_sections:3;
    u64 emit_call_site_information:1;
    u64 supports_debug_entry_values:1;
    u64 enable_debug_entry_values:1;
    u64 value_tracking_variable_locations:1;
    u64 force_dwarf_frame_section:1;
    u64 xray_function_index:1;
    u64 debug_strict_dwarf:1;
    u64 hotpatch:1;
    u64 ppc_gen_scalar_mass_entries:1;
    u64 jmc_instrument:1;
    u64 enable_cfi_fixup:1;
    u64 mis_expect:1;
    u64 xcoff_read_only_pointers:1;
    u64 float_abi:2;
    u64 thread_model:1;
    u32 fp_op_fusion_mode:2;
    u32 eabi_version:3;
    u32 debugger_kind:3;
    u32 exception_handling:3;
    u32 reserved:21;
    unsigned loop_alignment;
    struct
    {
        int major;
        int minor;
    } binutils_version;

    BBLLVMMCTargetOptions mc;
};

struct BBLLVMTargetMachineCreate
{
    BBLLVMTargetOptions target_options;
    BBLLVMString target_triple;
    BBLLVMString cpu_model;
    BBLLVMString cpu_features;
    BBLLVMRelocationModel relocation_model;
    BBLLVMCodeModel code_model;
    BBLLVMCodeGenerationOptimizationLevel optimization_level;
    bool jit;
    u32 reserved;
};

static_assert(sizeof(BBLLVMTargetMachineCreate) == 192);

EXPORT TargetMachine* llvm_create_target_machine(const BBLLVMTargetMachineCreate& create, BBLLVMString* error_message)
{
    std::string error_message_string;
    const Target* target = TargetRegistry::lookupTarget(create.target_triple.string_ref(), error_message_string);

    TargetMachine* target_machine;

    if (target)
    {
        std::optional<CodeModel::Model> code_model;
        switch (create.code_model)
        {
            case BBLLVMCodeModel::none: code_model = std::nullopt; break;
            case BBLLVMCodeModel::tiny: code_model = CodeModel::Tiny; break;
            case BBLLVMCodeModel::small: code_model = CodeModel::Small; break;
            case BBLLVMCodeModel::kernel: code_model = CodeModel::Kernel; break;
            case BBLLVMCodeModel::medium: code_model = CodeModel::Medium; break;
            case BBLLVMCodeModel::large: code_model = CodeModel::Large; break;
        }

        std::optional<Reloc::Model> relocation_model;

        switch (create.relocation_model)
        {
            case BBLLVMRelocationModel::default_relocation: relocation_model = std::nullopt; break;
            case BBLLVMRelocationModel::static_relocation: relocation_model = Reloc::Static; break;
            case BBLLVMRelocationModel::pic: relocation_model = Reloc::PIC_; break;
            case BBLLVMRelocationModel::dynamic_no_pic: relocation_model = Reloc::DynamicNoPIC; break;
            case BBLLVMRelocationModel::ropi: relocation_model = Reloc::ROPI; break;
            case BBLLVMRelocationModel::rwpi: relocation_model = Reloc::RWPI; break;
            case BBLLVMRelocationModel::ropi_rwpi: relocation_model = Reloc::ROPI_RWPI; break;
        }

        CodeGenOptLevel optimization_level;
        switch (create.optimization_level)
        {
            case BBLLVMCodeGenerationOptimizationLevel::none: optimization_level = CodeGenOptLevel::None; break;
            case BBLLVMCodeGenerationOptimizationLevel::less: optimization_level = CodeGenOptLevel::Less; break;
            case BBLLVMCodeGenerationOptimizationLevel::normal: optimization_level = CodeGenOptLevel::Default; break;
            case BBLLVMCodeGenerationOptimizationLevel::aggressive: optimization_level = CodeGenOptLevel::Aggressive; break;
        }

        TargetOptions target_options;
        target_machine = target->createTargetMachine(create.target_triple.string_ref(), create.cpu_model.string_ref(), create.cpu_features.string_ref(), target_options, relocation_model, code_model, optimization_level, create.jit);
    }
    else
    {
        auto length = error_message_string.length();
        char* result = new char[length];
        memcpy(result, error_message_string.c_str(), length);

        *error_message = { result, length };
    }

    return target_machine;
}
