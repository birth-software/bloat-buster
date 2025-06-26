#pragma once

#include <lib.hpp>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/TargetMachine.h>
#include <llvm-c/Transforms/PassBuilder.h>

struct LLDResult
{
    String stdout_string;
    String stderr_string;
    bool success;
};

enum class BBLLVMOptimizationLevel : u8
{
    O0 = 0,
    O1 = 1,
    O2 = 2,
    O3 = 3,
    Os = 4,
    Oz = 5,
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

fn bool llvm_initialized = false;

extern "C" LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef b, LLVMValueRef ra, LLVMTypeRef et);

extern "C" void llvm_subprogram_replace_type(LLVMMetadataRef subprogram, LLVMMetadataRef subroutine_type);

#define lld_api_args() char* const* argument_pointer, u64 argument_count, bool exit_early, bool disable_output
#define lld_api_function_decl(link_name) LLDResult lld_ ## link_name ## _link(lld_api_args())
extern "C" lld_api_function_decl(elf);
