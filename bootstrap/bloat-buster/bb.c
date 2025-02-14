#include <std/base.h>
#include <std/os.h>
#include <std/virtual_buffer.h>
#include <std/project.h>
#include <generated.h>

#include <std/base.c>
#include <std/os.c>
#include <std/virtual_buffer.c>
#include <generated.c>

#include <llvm-c/Disassembler.h>

global_variable char** environment_pointer;

typedef enum GPR_x86_64
{
    REGISTER_X86_64_AL  = 0x0,
    REGISTER_X86_64_AH  = REGISTER_X86_64_AL | (1 << 2),
    REGISTER_X86_64_AX  = REGISTER_X86_64_AL,
    REGISTER_X86_64_EAX = REGISTER_X86_64_AL,
    REGISTER_X86_64_RAX = REGISTER_X86_64_AL,

    REGISTER_X86_64_CL  = 0x1,
    REGISTER_X86_64_CH  = REGISTER_X86_64_CL | (1 << 2),
    REGISTER_X86_64_CX  = REGISTER_X86_64_CL,
    REGISTER_X86_64_ECX = REGISTER_X86_64_CL,
    REGISTER_X86_64_RCX = REGISTER_X86_64_CL,

    REGISTER_X86_64_DL  = 0x2,
    REGISTER_X86_64_DH  = REGISTER_X86_64_DL | (1 << 2),
    REGISTER_X86_64_DX  = REGISTER_X86_64_DL,
    REGISTER_X86_64_EDX = REGISTER_X86_64_DL,
    REGISTER_X86_64_RDX = REGISTER_X86_64_DL,

    REGISTER_X86_64_BL  = 0x3,
    REGISTER_X86_64_BH  = REGISTER_X86_64_BL | (1 << 2),
    REGISTER_X86_64_BX  = REGISTER_X86_64_BL,
    REGISTER_X86_64_EBX = REGISTER_X86_64_BL,
    REGISTER_X86_64_RBX = REGISTER_X86_64_BL,

    REGISTER_X86_64_SPL = 0x4,
    REGISTER_X86_64_SP  = REGISTER_X86_64_SPL,
    REGISTER_X86_64_ESP = REGISTER_X86_64_SPL,
    REGISTER_X86_64_RSP = REGISTER_X86_64_SPL,

    REGISTER_X86_64_BPL = 0x5,
    REGISTER_X86_64_BP  = REGISTER_X86_64_BPL,
    REGISTER_X86_64_EBP = REGISTER_X86_64_BPL,
    REGISTER_X86_64_RBP = REGISTER_X86_64_BPL,

    REGISTER_X86_64_SIL = 0x6,
    REGISTER_X86_64_SI  = REGISTER_X86_64_SIL,
    REGISTER_X86_64_ESI = REGISTER_X86_64_SIL,
    REGISTER_X86_64_RSI = REGISTER_X86_64_SIL,

    REGISTER_X86_64_DIL = 0x7,
    REGISTER_X86_64_DI  = REGISTER_X86_64_DIL,
    REGISTER_X86_64_EDI = REGISTER_X86_64_DIL,
    REGISTER_X86_64_RDI = REGISTER_X86_64_DIL,

    REGISTER_X86_64_R8L = 0x8,
    REGISTER_X86_64_R8W = REGISTER_X86_64_R8L,
    REGISTER_X86_64_R8D = REGISTER_X86_64_R8L,
    REGISTER_X86_64_R8  = REGISTER_X86_64_R8L,

    REGISTER_X86_64_R9L = 0x9,
    REGISTER_X86_64_R9W = REGISTER_X86_64_R9L,
    REGISTER_X86_64_R9D = REGISTER_X86_64_R9L,
    REGISTER_X86_64_R9  = REGISTER_X86_64_R9L,

    REGISTER_X86_64_R10L = 0xa,
    REGISTER_X86_64_R10W = REGISTER_X86_64_R10L,
    REGISTER_X86_64_R10D = REGISTER_X86_64_R10L,
    REGISTER_X86_64_R10  = REGISTER_X86_64_R10L,

    REGISTER_X86_64_R11L = 0xb,
    REGISTER_X86_64_R11W = REGISTER_X86_64_R11L,
    REGISTER_X86_64_R11D = REGISTER_X86_64_R11L,
    REGISTER_X86_64_R11  = REGISTER_X86_64_R11L,

    REGISTER_X86_64_R12L = 0xc,
    REGISTER_X86_64_R12W = REGISTER_X86_64_R12L,
    REGISTER_X86_64_R12D = REGISTER_X86_64_R12L,
    REGISTER_X86_64_R12  = REGISTER_X86_64_R12L,

    REGISTER_X86_64_R13L = 0xd,
    REGISTER_X86_64_R13W = REGISTER_X86_64_R13L,
    REGISTER_X86_64_R13D = REGISTER_X86_64_R13L,
    REGISTER_X86_64_R13  = REGISTER_X86_64_R13L,

    REGISTER_X86_64_R14L = 0xe,
    REGISTER_X86_64_R14W = REGISTER_X86_64_R14L,
    REGISTER_X86_64_R14D = REGISTER_X86_64_R14L,
    REGISTER_X86_64_R14  = REGISTER_X86_64_R14L,

    REGISTER_X86_64_R15L = 0xf,
    REGISTER_X86_64_R15W = REGISTER_X86_64_R15L,
    REGISTER_X86_64_R15D = REGISTER_X86_64_R15L,
    REGISTER_X86_64_R15  = REGISTER_X86_64_R15L,
} GPR_x86_64;

fn u8 gpr_is_extended(GPR_x86_64 gpr)
{
    return (gpr & 0b1000) >> 3;
}

#define X86_64_GPR_COUNT (16)

typedef enum OpcodeLength
{
    OPCODE_LENGTH_1 = 0,
    OPCODE_LENGTH_2 = 1, // 0f xx
    OPCODE_LENGTH_3 = 2, // 0f yy xx
} OpcodeLength;

STRUCT(Opcode)
{
    u8 plus_register:1;
    u8 prefix_0f:1;
    u8 extension:3;
    u8 reserved:2;
    u8 bytes[2];
};

typedef enum LegacyPrefix
{
    LEGACY_PREFIX_F0,
    LEGACY_PREFIX_F2,
    LEGACY_PREFIX_F3,
    LEGACY_PREFIX_2E,
    LEGACY_PREFIX_36,
    LEGACY_PREFIX_3E,
    LEGACY_PREFIX_26,
    LEGACY_PREFIX_64,
    LEGACY_PREFIX_65,
    LEGACY_PREFIX_66,
    LEGACY_PREFIX_67,
    LEGACY_PREFIX_COUNT,
} LegacyPrefix;

typedef enum SegmentRegisterOverride
{
    SEGMENT_REGISTER_OVERRIDE_CS,
    SEGMENT_REGISTER_OVERRIDE_SS,
    SEGMENT_REGISTER_OVERRIDE_DS,
    SEGMENT_REGISTER_OVERRIDE_ES,
    SEGMENT_REGISTER_OVERRIDE_FS,
    SEGMENT_REGISTER_OVERRIDE_GS,
    SEGMENT_REGISTER_OVERRIDE_COUNT,
} SegmentRegisterOverride;

fn String segment_register_override_to_register_string(SegmentRegisterOverride segment_register_override)
{
    switch (segment_register_override)
    {
        case SEGMENT_REGISTER_OVERRIDE_CS: return strlit("cs");
        case SEGMENT_REGISTER_OVERRIDE_SS: return strlit("ss");
        case SEGMENT_REGISTER_OVERRIDE_DS: return strlit("ds");
        case SEGMENT_REGISTER_OVERRIDE_ES: return strlit("es");
        case SEGMENT_REGISTER_OVERRIDE_FS: return strlit("fs");
        case SEGMENT_REGISTER_OVERRIDE_GS: return strlit("gs");
        case SEGMENT_REGISTER_OVERRIDE_COUNT: unreachable();
    }
}

global_variable const u8 segment_register_overrides[] = {
    [SEGMENT_REGISTER_OVERRIDE_CS] = LEGACY_PREFIX_2E,
    [SEGMENT_REGISTER_OVERRIDE_SS] = LEGACY_PREFIX_36,
    [SEGMENT_REGISTER_OVERRIDE_DS] = LEGACY_PREFIX_3E,
    [SEGMENT_REGISTER_OVERRIDE_ES] = LEGACY_PREFIX_26,
    [SEGMENT_REGISTER_OVERRIDE_FS] = LEGACY_PREFIX_64,
    [SEGMENT_REGISTER_OVERRIDE_GS] = LEGACY_PREFIX_65,
};
static_assert(array_length(segment_register_overrides) == SEGMENT_REGISTER_OVERRIDE_COUNT);

global_variable u8 legacy_prefixes[] = {
    0xf0,
    0xf2,
    0xf3,
    0x2e,
    0x36,
    0x3e,
    0x26,
    0x64,
    0x65,
    0x66,
    0x67,
};

static_assert(array_length(legacy_prefixes) == LEGACY_PREFIX_COUNT);

STRUCT(EncodingScalar)
{
    EncodingInvariantData invariant;
    u64 legacy_prefixes:LEGACY_PREFIX_COUNT;
    u64 rm_register:4;
    u64 reg_register:4;
    union
    {
        u8 bytes[8];
        u64 value;
    } immediate;
    union
    {
        s32 value;
        s8 bytes[4];
    } displacement;
    Opcode opcode;
};

#define batch_element_count (64)
#define max_instruction_byte_count (16)

u32 encode_scalar(u8* restrict output, const EncodingScalar* const restrict encodings, u64 encoding_count)
{
    assert(encoding_count);
    u8 buffers[batch_element_count][max_instruction_byte_count];
    u8 instruction_lengths[batch_element_count];

    for (u32 encoding_index = 0; encoding_index < encoding_count; encoding_index += 1)
    {
        let(encoding, encodings[encoding_index]);
    
        const u8* const start = (const u8* const) &buffers[encoding_index];
        u8* restrict local_buffer = (u8* restrict)&buffers[encoding_index];
        u8* restrict it = local_buffer;

        for (LegacyPrefix prefix = 0; prefix < LEGACY_PREFIX_COUNT; prefix += 1)
        {
            let(is_prefix, (encoding.legacy_prefixes & (1 << prefix)) >> prefix);
            let(prefix_byte, legacy_prefixes[prefix]);
            *it = prefix_byte;
            it += is_prefix;
        }

        u8 has_base_register = encoding.invariant.is_rm_register | encoding.invariant.is_reg_register | encoding.invariant.implicit_register;

        u8 rex_base = 0x40;
        u8 rex_b = 0x01;
        u8 rex_x = 0x02;
        unused(rex_x);
        u8 rex_r = 0x04;
        u8 rex_w = 0x08;
        u8 is_reg_direct_addressing_mode = !encoding.invariant.is_displacement;
        u8 reg_register = encoding.reg_register;
        u8 rm_register = encoding.rm_register;
        u8 byte_rex_b = rex_b * gpr_is_extended(rm_register);
        u8 byte_rex_x = 0; // TODO: rex_x * encoding.scaled_index_register;
        u8 byte_rex_r = rex_r * gpr_is_extended(reg_register); 
        u8 byte_rex_w = rex_w * encoding.invariant.rex_w;
        u8 byte_rex = (byte_rex_b | byte_rex_x) | (byte_rex_r | byte_rex_w);
        u8 rex = (rex_base | byte_rex);
        u8 encode_rex = byte_rex != 0;
        *it = rex;
        it += encode_rex;
        
        u8 encode_prefix_0f = encoding.opcode.prefix_0f;
        *it = 0x0f * encode_prefix_0f;
        it += encode_prefix_0f;

        u8 encode_three_byte_opcode = encoding.opcode.bytes[1] != 0;
        *it = encoding.opcode.bytes[1] * encode_three_byte_opcode;
        it += encode_three_byte_opcode;

        *it = encoding.opcode.bytes[0] | ((encoding.rm_register & 0b111) * encoding.opcode.plus_register);        // *it = encoding.opcode.bytes[0] | 
        it += 1;
        
        u8 encode_mod_rm = ((encoding.invariant.is_rm_register | encoding.invariant.is_reg_register) & (!encoding.opcode.plus_register)) | encoding.invariant.is_displacement;

        // Mod:
        // 00: No displacement (except when R/M = 101, where a 32-bit displacement follows).
        // 01: 8-bit signed displacement follows.
        // 10: 32-bit signed displacement follows.
        // 11: Register addressing (no memory access).
        
        u8 mod_is_displacement32 = encoding.invariant.is_displacement & encoding.invariant.displacement_size;
        u8 mod_is_displacement8 = (encoding.invariant.is_displacement & !(encoding.invariant.displacement_size)) & ((encoding.displacement.bytes[0] != 0) | (encoding.invariant.is_rm_register & ((encoding.rm_register & 0b111) == REGISTER_X86_64_RBP)));
        // TODO: fix if necessary
        u8 mod = (((mod_is_displacement32 * has_base_register) << 1) | (mod_is_displacement8 * has_base_register)) | ((is_reg_direct_addressing_mode << 1) | is_reg_direct_addressing_mode);
        // A register operand.
        // An opcode extension (in some instructions).
        u8 reg = (reg_register & 0b111) | encoding.opcode.extension;
        // When mod is 00, 01, or 10: Specifies a memory address or a base register.
        // When mod is 11: Specifies a register.
        u8 rm = (rm_register & 0b111) | (!has_base_register * 0b100);
        u8 mod_rm = (mod << 6) | (reg << 3) | rm;
        *it = mod_rm;
        it += encode_mod_rm;

        // When mod is 00, 01, or 10 and rm = 100, a SIB (Scale-Index-Base) byte follows the ModR/M byte to further specify the addressing mode.
        u8 encode_sib = (mod != 0b11) & (rm == 0b100);
        u8 sib_scale = 0;
        u8 sib_index = 0b100;
        u8 sib_base = ((rm_register & 0b111) * encoding.invariant.is_rm_register) | (!encoding.invariant.is_rm_register * 0b101);
        u8 sib_byte = sib_scale << 6 | sib_index << 3 | sib_base;
        *it = sib_byte;
        it += encode_sib;

        *(s8*)it = encoding.displacement.bytes[0];
        it += mod_is_displacement8 * sizeof(s8);

        *(s32*)it = encoding.displacement.value;
        it += mod_is_displacement32 * sizeof(s32);

        *(u8*) it = encoding.immediate.bytes[0];
        it += (encoding.invariant.is_immediate & (encoding.invariant.immediate_size == 0)) * sizeof(u8);

        *(u16*) it = *(u16*)(&encoding.immediate.bytes[0]);
        it += (encoding.invariant.is_immediate & (encoding.invariant.immediate_size == 1)) * sizeof(u16);

        *(u32*) it = *(u32*)(&encoding.immediate.bytes[0]);
        it += (encoding.invariant.is_immediate & (encoding.invariant.immediate_size == 2)) * sizeof(u32);

        *(u64*) it = encoding.immediate.value;
        it += (encoding.invariant.is_immediate & (encoding.invariant.immediate_size == 3)) * sizeof(u64);

        *(s8*)it = encoding.displacement.bytes[0];
        it += (encoding.invariant.is_relative & !encoding.invariant.displacement_size) * sizeof(s8);

        *(s32*)it = encoding.displacement.value;
        it += (encoding.invariant.is_relative & encoding.invariant.displacement_size) * sizeof(s32);

        let_cast(u8, instruction_length, it - start);
        instruction_lengths[encoding_index] = instruction_length;
    }

    u8* restrict it = output;

    for (u32 encoding_index = 0; encoding_index < MIN(encoding_count, batch_element_count); encoding_index += 1)
    {
        let(instruction_length, instruction_lengths[encoding_index]);
#if USE_MEMCPY
        memcpy(it, &buffers[encoding_index], instruction_length);
#else
        for (u8 byte = 0; byte < instruction_length; byte += 1)
        {
            it[byte] = buffers[encoding_index][byte];
        }
#endif
        it += instruction_length;
    }

    let(length, (u32)(it - output));
    assert(it - output != 0);
    assert(length);
    return length;
}

#define cc_count(x) ((MNEMONIC_x86_64_ ## x ## z - MNEMONIC_x86_64_ ## x ## a) + 1)
// #define cmov_count ((MNEMONIC_x86_64_cmovz - MNEMONIC_x86_64_cmova) + 1)
// #define jcc_count ((MNEMONIC_x86_64_jz - MNEMONIC_x86_64_ja) + 1)
#define cmov_count cc_count(cmov)
#define jcc_count cc_count(j)
#define setcc_count cc_count(set)

#define cc_index(x) \
fn u8 x ## _index(Mnemonic_x86_64 mnemonic) \
{\
    assert(mnemonic >= MNEMONIC_x86_64_ ## x ## a && mnemonic <= MNEMONIC_x86_64_ ## x ## z);\
    return (u8)(mnemonic - MNEMONIC_x86_64_ ## x ## a);\
}

cc_index(cmov)
cc_index(j)
cc_index(set)

global_variable const u8 cc_opcodes_low[] = {
    0x07,
    0x03,
    0x02,
    0x06,
    0x02,
    0x04,
    0x0F,
    0x0D,
    0x0C,
    0x0E,
    0x06,
    0x02,
    0x03,
    0x07,
    0x03,
    0x05,
    0x0E,
    0x0C,
    0x0D,
    0x0F,
    0x01,
    0x0B,
    0x09,
    0x05,
    0x00,
    0x0A,
    0x0A,
    0x0B,
    0x08,
    0x04,
};
static_assert(array_length(cc_opcodes_low) == cmov_count); 
static_assert(array_length(cc_opcodes_low) == jcc_count); 
static_assert(array_length(cc_opcodes_low) == setcc_count); 

ENUM(OperandId, u8,
    op_none,
    op_al,
    op_ax,
    op_eax,
    op_rax,
    op_cl,
    op_cx,
    op_ecx,
    op_rcx,
    op_dl,
    op_dx,
    op_edx,
    op_rdx,
    op_r8,
    op_r16,
    op_r32,
    op_r64,
    op_rm8,
    op_rm16,
    op_rm32,
    op_rm64,
    op_imm8,
    op_imm16,
    op_imm32,
    op_imm64,
    op_rel8,
    op_rel32,
    op_m8,
    op_m16,
    op_m32,
    op_m64,
    op_m128,

    op_ds_rsi_m8,
    op_ds_rsi_m16,
    op_ds_rsi_m32,
    op_ds_rsi_m64,

    op_es_rdi_m8,
    op_es_rdi_m16,
    op_es_rdi_m32,
    op_es_rdi_m64,

    op_one_literal,
);

#define operand_kind_array_element_count (4)

fn String operand_to_string(OperandId operand_id)
{
    switch (operand_id)
    {
        case_to_name(op_, none);
        case op_al:  return strlit("al");
        case op_ax: return strlit("ax");
        case op_eax: return strlit("eax");
        case op_rax: return strlit("rax");
        case op_cl:  return strlit("cl");
        case op_cx: return strlit("cx");
        case op_ecx: return strlit("ecx");
        case op_rcx: return strlit("rcx");
        case op_dl:  return strlit("dl");
        case op_dx: return strlit("dx");
        case op_edx: return strlit("edx");
        case op_rdx: return strlit("rdx");
        case_to_name(op_, r8);
        case_to_name(op_, r16);
        case_to_name(op_, r32);
        case_to_name(op_, r64);
        case_to_name(op_, rm8);
        case_to_name(op_, rm16);
        case_to_name(op_, rm32);
        case_to_name(op_, rm64);
        case_to_name(op_, imm8);
        case_to_name(op_, imm16);
        case_to_name(op_, imm32);
        case_to_name(op_, imm64);
        case_to_name(op_, rel8);
        case_to_name(op_, rel32);
        case_to_name(op_, m8);
        case_to_name(op_, m16);
        case_to_name(op_, m32);
        case_to_name(op_, m64);
        case_to_name(op_, m128);
        case_to_name(op_, ds_rsi_m8);
        case_to_name(op_, ds_rsi_m16);
        case_to_name(op_, ds_rsi_m32);
        case_to_name(op_, ds_rsi_m64);

        case_to_name(op_, es_rdi_m8);
        case_to_name(op_, es_rdi_m16);
        case_to_name(op_, es_rdi_m32);
        case_to_name(op_, es_rdi_m64);
        case op_one_literal: return strlit("1");
    }
}

STRUCT(Operands)
{
    OperandId values[operand_kind_array_element_count];
    u8 count:7;
    u8 implicit_operands:1;
};

STRUCT(Encoding)
{
    Operands operands;
    Opcode opcode;
    u8 rex_w:1;
    u8 operand_size_override:1;
};
decl_vb(Encoding);

STRUCT(Batch)
{
    Mnemonic_x86_64 mnemonic;
    u64 legacy_prefixes:LEGACY_PREFIX_COUNT;
    u32 encoding_offset;
    u32 encoding_count;
};
decl_vb(Batch);

fn u8 op_is_gpra(OperandId operand_kind)
{
    return operand_kind >= op_al && operand_kind <= op_rax;
}

fn u8 op_gpra_get_index(OperandId operand)
{
    assert(op_is_gpra(operand));
    return operand - op_al;
}

fn String op_gpra_to_string(OperandId operand)
{
    let(index, op_gpra_get_index(operand));
    String register_a_names[] = {
        strlit("al"),
        strlit("ax"),
        strlit("eax"),
        strlit("rax"),
    };

    return register_a_names[index];
}

fn u8 op_is_gprd(OperandId operand_kind)
{
    return operand_kind >= op_dl && operand_kind <= op_rdx;
}

fn String op_gprd_to_string(OperandId operand)
{
    assert(op_is_gprd(operand));
    switch (operand)
    {
        case op_dl: return strlit("dl");
        case op_dx: return strlit("dx");
        case op_edx: return strlit("edx");
        case op_rdx: return strlit("rdx");
        default: unreachable();
    }
}

fn u8 op_is_imm(OperandId operand_kind)
{
    return operand_kind >= op_imm8 && operand_kind <= op_imm64;
}

fn u8 op_is_gpr_no_gpra_exclusive(OperandId operand_kind)
{
    return operand_kind >= op_r8 && operand_kind <= op_r64;
}

fn u8 op_is_rm(OperandId operand_kind)
{
    return operand_kind >= op_rm8 && operand_kind <= op_rm64;
}

fn u8 op_is_gpr_no_gpra(OperandId operand_kind)
{
    return op_is_gpr_no_gpra_exclusive(operand_kind) | op_is_rm(operand_kind);
}

fn u8 op_is_relative(OperandId operand_kind)
{
    return operand_kind >= op_rel8 && operand_kind <= op_rel32;
}

fn u8 op_is_memory(OperandId operand)
{
    return operand >= op_m8 && operand <= op_m128;
}

fn u8 op_is_es_rdi_memory(OperandId operand)
{
    return operand >= op_es_rdi_m8 && operand <= op_es_rdi_m64;
}

fn u8 op_is_ds_rsi_memory(OperandId operand)
{
    return operand >= op_ds_rsi_m8 && operand <= op_ds_rsi_m64;
}

fn u8 op_rm_get_index(OperandId operand_kind)
{
    assert(op_is_rm(operand_kind));
    return operand_kind - op_rm8;
}

fn u8 op_gprd_get_index(OperandId operand_kind)
{
    assert(op_is_gprd(operand_kind));
    return operand_kind >= op_dl && operand_kind <= op_rdx;
}

fn u8 op_gpr_exclusive_get_index(OperandId operand_kind)
{
    assert(op_is_gpr_no_gpra_exclusive(operand_kind));
    return operand_kind - op_r8;
}

fn u8 op_gpr_get_index(OperandId operand_kind)
{
    assert(op_is_gpr_no_gpra(operand_kind));
    return op_is_rm(operand_kind) ? op_rm_get_index(operand_kind) : op_gpr_exclusive_get_index(operand_kind);
}

fn u8 op_imm_get_index(OperandId operand_kind)
{
    assert(op_is_imm(operand_kind));
    return operand_kind - op_imm8;
}

fn u8 op_get_size_out_of_index(u8 index)
{
    return 1 << index;
}

STRUCT(TestDataset)
{
    const Batch* const restrict batches;
    u64 batch_count;
    const Encoding* const restrict encodings;
    u64 encoding_count;
};

fn String sample_immediate_strings(u8 index)
{
    global_variable const String strings[] = {
        strlit("10"),
        strlit("1000"),
        strlit("10000000"),
        strlit("1000000000000000"),
    };

    return strings[index];
}

fn u64 sample_immediate_values(u8 index)
{
    global_variable const u64 immediates[] = {
        10,
        1000,
        10000000,
        1000000000000000,
    };
    return immediates[index];
}

fn String gpr_to_string(GPR_x86_64 gpr, u8 index, u8 switcher)
{
    assert(switcher == 0 || switcher == 1);
    global_variable const String gpr_names[X86_64_GPR_COUNT][4] = {
        [REGISTER_X86_64_AX] = {
            strlit("al"),
            strlit("ax"),
            strlit("eax"),
            strlit("rax"),
        },
        [REGISTER_X86_64_CX] = {
            strlit("cl"),
            strlit("cx"),
            strlit("ecx"),
            strlit("rcx"),
        },
        [REGISTER_X86_64_DX] = {
            strlit("dl"),
            strlit("dx"),
            strlit("edx"),
            strlit("rdx"),
        },
        [REGISTER_X86_64_BX] = {
            strlit("bl"),
            strlit("bx"),
            strlit("ebx"),
            strlit("rbx"),
        },
        [REGISTER_X86_64_SP] = {
            strlit("ah"), // Check alt names
            strlit("sp"),
            strlit("esp"),
            strlit("rsp"),
        },
        [REGISTER_X86_64_BP] = {
            strlit("ch"),
            strlit("bp"),
            strlit("ebp"),
            strlit("rbp"),
        },
        [REGISTER_X86_64_SI] = {
            strlit("dh"),
            strlit("si"),
            strlit("esi"),
            strlit("rsi"),
        },
        [REGISTER_X86_64_DI] = {
            strlit("bh"),
            strlit("di"),
            strlit("edi"),
            strlit("rdi"),
        },
        [REGISTER_X86_64_R8] = {
            strlit("r8b"),
            strlit("r8w"),
            strlit("r8d"),
            strlit("r8"),
        },
        [REGISTER_X86_64_R9] = {
            strlit("r9b"),
            strlit("r9w"),
            strlit("r9d"),
            strlit("r9"),
        },
        [REGISTER_X86_64_R10] = {
            strlit("r10b"),
            strlit("r10w"),
            strlit("r10d"),
            strlit("r10"),
        },
        [REGISTER_X86_64_R11] = {
            strlit("r11b"),
            strlit("r11w"),
            strlit("r11d"),
            strlit("r11"),
        },
        [REGISTER_X86_64_R12] = {
            strlit("r12b"),
            strlit("r12w"),
            strlit("r12d"),
            strlit("r12"),
        },
        [REGISTER_X86_64_R13] = {
            strlit("r13b"),
            strlit("r13w"),
            strlit("r13d"),
            strlit("r13"),
        },
        [REGISTER_X86_64_R14] = {
            strlit("r14b"),
            strlit("r14w"),
            strlit("r14d"),
            strlit("r14"),
        },
        [REGISTER_X86_64_R15] = {
            strlit("r15b"),
            strlit("r15w"),
            strlit("r15d"),
            strlit("r15"),
        },
    };

    global_variable const String alt_register_names[] = {
        strlit("spl"),
        strlit("bpl"),
        strlit("sil"),
        strlit("dil"),
    };

    return (unlikely(((gpr & 0b100) >> 2) & ((switcher != 0) & (index == 0)))) ? alt_register_names[gpr & 0b11] : gpr_names[gpr][index];
}

fn String format_instruction1(String buffer, String mnemonic, String op)
{
    u64 i = 0;

    memcpy(buffer.pointer + i, mnemonic.pointer, mnemonic.length);
    i += mnemonic.length;

    buffer.pointer[i] = ' ';
    i += 1;

    memcpy(buffer.pointer + i, op.pointer, op.length);
    i += op.length;

    assert(i < buffer.length);
    buffer.pointer[i] = 0;

    return (String) {
        .pointer = buffer.pointer,
        .length = i,
    };
}

fn String format_instruction2(String buffer, String mnemonic, String op1, String op2)
{
    u64 i = 0;

    memcpy(buffer.pointer + i, mnemonic.pointer, mnemonic.length);
    i += mnemonic.length;

    buffer.pointer[i] = ' ';
    i += 1;

    memcpy(buffer.pointer + i, op1.pointer, op1.length);
    i += op1.length;

    buffer.pointer[i] = ',';
    buffer.pointer[i + 1] = ' ';
    i += 2;

    memcpy(buffer.pointer + i, op2.pointer, op2.length);
    i += op2.length;

    assert(i < buffer.length);
    buffer.pointer[i] = 0;

    return (String) {
        .pointer = buffer.pointer,
        .length = i,
    };
}

fn String format_instruction3(String buffer, String mnemonic, String op1, String op2, String op3)
{
    u64 i = 0;

    memcpy(buffer.pointer + i, mnemonic.pointer, mnemonic.length);
    i += mnemonic.length;

    buffer.pointer[i] = ' ';
    i += 1;

    memcpy(buffer.pointer + i, op1.pointer, op1.length);
    i += op1.length;

    buffer.pointer[i] = ',';
    buffer.pointer[i + 1] = ' ';
    i += 2;

    memcpy(buffer.pointer + i, op2.pointer, op2.length);
    i += op2.length;

    buffer.pointer[i] = ',';
    buffer.pointer[i + 1] = ' ';
    i += 2;

    memcpy(buffer.pointer + i, op3.pointer, op3.length);
    i += op3.length;

    assert(i < buffer.length);
    buffer.pointer[i] = 0;

    return (String) {
        .pointer = buffer.pointer,
        .length = i,
    };
}

fn String format_displacement(String buffer, String register_string, String displacement_string, u8 register_index)
{
    u64 length = 0;
    String result = {
        .pointer = buffer.pointer,
    };

    const String indirect_types[] = {
        strlit("byte ptr "),
        strlit("word ptr "),
        strlit("dword ptr "),
        strlit("qword ptr "),
        strlit("xmmword ptr "),
    };

    String indirect_type = indirect_types[register_index];

    memcpy(&buffer.pointer[length], indirect_type.pointer, indirect_type.length);
    length += indirect_type.length;

    buffer.pointer[length] = '[';
    length += 1;

    memcpy(&buffer.pointer[length], register_string.pointer, register_string.length);
    length += register_string.length;

    u8 omit_displacement = displacement_string.pointer[0] == '0' && displacement_string.length == 1;
    buffer.pointer[length] = ' ';
    length += !omit_displacement;

    buffer.pointer[length] = '+';
    length += !omit_displacement;

    buffer.pointer[length] = ' ';
    length += !omit_displacement;

    memcpy(&buffer.pointer[length], displacement_string.pointer, displacement_string.length);
    length += displacement_string.length * !omit_displacement;

    buffer.pointer[length] = ']';
    length += 1;

    result.length = length;

    return result;
}

STRUCT(ClangCompileAssembly)
{
    String instruction;
    String clang_path;
    VirtualBuffer(u8)* clang_pipe_buffer;
};

fn String clang_compile_assembly(Arena* arena, ClangCompileAssembly args)
{
    String my_assembly_path = strlit(BUILD_DIR "/my_assembly_source.S");
    FileWriteOptions options = {
        .path = my_assembly_path,
        .content = args.instruction,
    };
    file_write(options);

    String out_path = strlit(BUILD_DIR "/my_assembly_output");

    char* arguments[] = {
        string_to_c(args.clang_path),
        string_to_c(my_assembly_path),
        "-o",
        string_to_c(out_path),
        "-masm=intel",
        "-nostdlib",
        "-Wl,--oformat=binary",
        0,
    };
    RunCommandOptions run_options = {
        .stdout_stream = {
            .buffer = args.clang_pipe_buffer->pointer,
            .length = &args.clang_pipe_buffer->length,
            .capacity = args.clang_pipe_buffer->capacity,
            .policy = CHILD_PROCESS_STREAM_PIPE,
        },
        // .stderr_stream = {
        //     .policy = CHILD_PROCESS_STREAM_IGNORE,
        // },
    };
    RunCommandResult result = run_command(arena, (CStringSlice)array_to_slice(arguments), environment_pointer, run_options);
    let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0);
    if (!success)
    {
        os_exit(1);
    }

    String bytes = file_read(arena, out_path);
    return bytes;
}

STRUCT(DisassemblyResult)
{
    String whole;
    String instruction;
};

STRUCT(DisassemblyArguments)
{
    String binary;
    LLVMDisasmContextRef context;
    String disassembly_buffer;
    u64 gross:1;
};

#define llvm_initialize_macro(target, fn_prefix) \
    fn_prefix LLVMInitialize ## target ## Target();\
    fn_prefix LLVMInitialize ## target ## TargetInfo();\
    fn_prefix LLVMInitialize ## target ## TargetMC();\
    fn_prefix LLVMInitialize ## target ## AsmParser();\
    fn_prefix LLVMInitialize ## target ## AsmPrinter();\
    fn_prefix LLVMInitialize ## target ## Disassembler()

#define _null_prefix_()

llvm_initialize_macro(X86, extern void);

fn String disassemble_binary(Arena* arena, DisassemblyArguments arguments)
{
    unused(arena);
    unused(arguments);
    String result = {};
    let(instruction_bytes, LLVMDisasmInstruction(arguments.context, arguments.binary.pointer, arguments.binary.length, 0, (char*)arguments.disassembly_buffer.pointer, arguments.disassembly_buffer.length));

    if (instruction_bytes)
    {
        result = cstr(arguments.disassembly_buffer.pointer);

        assert(result.pointer[0] == '\t');
        result.pointer += 1;
        result.length -= 1;
        for (u64 i = 0; i < result.length; i += 1)
        {
            if (result.pointer[i] == '\t')
            {
                result.pointer[i] = ' ';
            }
        }
    }
    
    return result;
}

STRUCT(CheckInstructionArguments)
{
    String clang_path;
    String text;
    String binary;
    String error_buffer;
    u64* error_buffer_length;
    VirtualBuffer(u8)* clang_pipe_buffer;
    LLVMDisasmContextRef disassembler;
    u64 reserved:63;
};

fn Mnemonic_x86_64 parse_cmov(String instruction)
{
    let(space_index, string_first_ch(instruction, ' '));
    assert(space_index != STRING_NO_MATCH);
    String mnemonic_string = s_get_slice(u8, instruction, 0, space_index);
    String cmov_prefix = strlit("cmov");
    assert(string_starts_with(mnemonic_string, cmov_prefix));
    String cmov_suffix = s_get_slice(u8, mnemonic_string, cmov_prefix.length, mnemonic_string.length);
    String suffixes[] = {
        strlit("a"),
        strlit("ae"),
        strlit("b"),
        strlit("be"),
        strlit("c"),
        strlit("e"),
        strlit("g"),
        strlit("ge"),
        strlit("l"),
        strlit("le"),
        strlit("na"),
        strlit("nae"),
        strlit("nb"),
        strlit("nbe"),
        strlit("nc"),
        strlit("ne"),
        strlit("ng"),
        strlit("nge"),
        strlit("nl"),
        strlit("nle"),
        strlit("no"),
        strlit("np"),
        strlit("ns"),
        strlit("nz"),
        strlit("o"),
        strlit("p"),
        strlit("pe"),
        strlit("po"),
        strlit("s"),
        strlit("z"),
    };
    u64 suffix;
    for (suffix = 0; suffix < array_length(suffixes); suffix += 1)
    {
        if (s_equal(cmov_suffix, suffixes[suffix]))
        {
            break;
        }
    }

    assert(suffix != array_length(suffixes));
    Mnemonic_x86_64 result = suffix + MNEMONIC_x86_64_cmova;
    return result;
}

fn Mnemonic_x86_64 parse_cc_ext(String instruction, String prefix, Mnemonic_x86_64 base_mnemonic)
{
    let(space_index, string_first_ch(instruction, ' '));
    assert(space_index != STRING_NO_MATCH);
    String mnemonic_string = s_get_slice(u8, instruction, 0, space_index);
    assert(string_starts_with(mnemonic_string, prefix));
    String suffix = s_get_slice(u8, mnemonic_string, prefix.length, mnemonic_string.length);
    String suffixes[] = {
        strlit("a"),
        strlit("ae"),
        strlit("b"),
        strlit("be"),
        strlit("c"),
        strlit("e"),
        strlit("g"),
        strlit("ge"),
        strlit("l"),
        strlit("le"),
        strlit("na"),
        strlit("nae"),
        strlit("nb"),
        strlit("nbe"),
        strlit("nc"),
        strlit("ne"),
        strlit("ng"),
        strlit("nge"),
        strlit("nl"),
        strlit("nle"),
        strlit("no"),
        strlit("np"),
        strlit("ns"),
        strlit("nz"),
        strlit("o"),
        strlit("p"),
        strlit("pe"),
        strlit("po"),
        strlit("s"),
        strlit("z"),
    };
    u64 suffix_index;
    for (suffix_index = 0; suffix_index < array_length(suffixes); suffix_index += 1)
    {
        if (s_equal(suffix, suffixes[suffix_index]))
        {
            break;
        }
    }

    assert(suffix_index != array_length(suffixes));
    Mnemonic_x86_64 result = base_mnemonic + suffix_index;
    return result;
}

fn String parse_operand(String instruction, u8 operand_index)
{
    String result = {};
    String it = instruction;
    u8 index = 0;

    it = s_get_slice(u8, it, string_first_ch(it, ' ') + 1, it.length);

    while (1)
    {
        if (it.length == 0)
        {
            break;
        }

        if (operand_index == index)
        {
            let(length, MIN(string_first_ch(it, ','), it.length));
            result = s_get_slice(u8, it, 0, length);
            break;
        }
        
        let(next, MIN(string_first_ch(it, ','), it.length));
        it = s_get_slice(u8, it, next + 2, it.length);
        index += 1;
    }

    return result;
}

#define parse_cc(i, cc_i_kind) parse_cc_ext(i, strlit(TOSTRING(cc_i_kind)), (MNEMONIC_x86_64_ ## cc_i_kind ## a))

fn u64 check_instruction(Arena* arena, CheckInstructionArguments arguments)
{
    StringFormatter error_buffer = {
        .buffer = arguments.error_buffer,
    };
    u8 disassembly_buffer[256];
    assert(arguments.binary.length);

    u8 result = 1;

    DisassemblyArguments disassemble_arguments = {
        .binary = arguments.binary,
        .disassembly_buffer = (String)array_to_slice(disassembly_buffer),
        .context = arguments.disassembler,
    };
    String disassembly_text = disassemble_binary(arena, disassemble_arguments);

    result = disassembly_text.length == arguments.text.length;
    if (result)
    {
        for (u64 i = 0; i < arguments.text.length; i += 1)
        {
            if (disassembly_text.pointer[i] != arguments.text.pointer[i])
            {
                result = 0;

                break;
            }
        }
    }

    if (!result) 
    {
        if (string_starts_with(arguments.text, strlit("ud0")))
        {
            // TODO: figure out
            // Somehow clang doesn't disassemble this instruction properly
            assert(disassembly_text.pointer == 0);
            assert(disassembly_text.length == 0);
            result = 1;
        }
        else if (string_starts_with(arguments.text, strlit("xchg ")))
        {
            if (s_equal(disassembly_text, strlit("nop")))
            {
                result = 1;
            }
            else
            {
                String my_op0 = parse_operand(arguments.text, 0);
                String my_op1 = parse_operand(arguments.text, 1);

                String their_op0 = parse_operand(disassembly_text, 0);
                String their_op1 = parse_operand(disassembly_text, 1);

                result = s_equal(my_op0, their_op1) && s_equal(my_op1, their_op0);
            }
        }
        if (string_starts_with(arguments.text, strlit("cmov")) && string_starts_with(disassembly_text, strlit("cmov")))
        {
            Mnemonic_x86_64 mine = parse_cc(arguments.text, cmov);
            Mnemonic_x86_64 theirs = parse_cc(disassembly_text, cmov);
            u8 my_opcode = cc_opcodes_low[cmov_index(mine)];
            u8 their_opcode = cc_opcodes_low[cmov_index(theirs)];
            result = my_opcode == their_opcode;
        }
        else if (string_starts_with(arguments.text, strlit("j")) && string_starts_with(disassembly_text, strlit("j")))
        {
            Mnemonic_x86_64 mine = parse_cc(arguments.text, j);
            Mnemonic_x86_64 theirs = parse_cc(disassembly_text, j);
            u8 my_opcode = cc_opcodes_low[j_index(mine)];
            u8 their_opcode = cc_opcodes_low[j_index(theirs)];
            result = my_opcode == their_opcode;
        }
        else if (string_starts_with(arguments.text, strlit("set")) && string_starts_with(disassembly_text, strlit("set")))
        {
            Mnemonic_x86_64 mine = parse_cc(arguments.text, set);
            Mnemonic_x86_64 theirs = parse_cc(disassembly_text, set);
            u8 my_opcode = cc_opcodes_low[set_index(mine)];
            u8 their_opcode = cc_opcodes_low[set_index(theirs)];
            result = my_opcode == their_opcode;
        }
        else if (string_starts_with(arguments.text, strlit("mov r")) && string_starts_with(disassembly_text, strlit("movabs r")))
        {
            result = 1;
        }
        else if (string_starts_with(arguments.text, strlit("sal ")) && string_starts_with(disassembly_text, strlit("shl ")))
        {
            result = 1;
        }
    }

    if (!result)
    {
        if (disassembly_text.length)
        {
            formatter_append(&error_buffer, "Disassembly mismatch. Intended to assemble:\n\t{s}\nbut got from LLVM:\n\t{s}\n", arguments.text, disassembly_text);
        }
        assert(arguments.binary.length);
        ClangCompileAssembly args = {
            .instruction = arguments.text,
            .clang_path = arguments.clang_path,
            .clang_pipe_buffer = arguments.clang_pipe_buffer,
        };
        String clang_binary = clang_compile_assembly(arena, args);

        if (clang_binary.pointer && s_equal(clang_binary, arguments.binary))
        {
            formatter_append_string(&error_buffer, strlit("Clang and this binary generated the same output (earlier string comparison failed):\n\t"));
            for (u64 bin_i = 0; bin_i < arguments.binary.length; bin_i += 1)
            {
                formatter_append(&error_buffer, "0x{u32:x,w=2} ", (u32)arguments.binary.pointer[bin_i]);
            }
        }
        else
        {
            formatter_append_string(&error_buffer, strlit("Failed to match correct output. Got:\n\t"));

            for (u64 bin_i = 0; bin_i < arguments.binary.length; bin_i += 1)
            {
                formatter_append(&error_buffer, "0x{u32:x,w=2} ", (u32)arguments.binary.pointer[bin_i]);
            }

            formatter_append_character(&error_buffer, '\n');

            formatter_append_string(&error_buffer, strlit("While clang generated the following:\n\t"));

            for (u64 bin_i = 0; bin_i < clang_binary.length; bin_i += 1)
            {
                formatter_append(&error_buffer, "0x{u32:x,w=2} ", (u32)clang_binary.pointer[bin_i]);
            }

            formatter_append_character(&error_buffer, '\n');
        }
    }

    assert(!!error_buffer.index == !result);

    return error_buffer.index;
}

STRUCT(EncodingTestOptions)
{
    u64 scalar:1;
    u64 wide:1;
};

#if defined(__x86_64__)
#include <immintrin.h>
#endif
typedef u64 Bitset;

STRUCT(GPR)
{
    Bitset mask[4];
};

STRUCT(VectorOpcode)
{
    Bitset prefix_0f;
    Bitset plus_register;
    u8 values[2][64];
    u8 extension[64];
};

STRUCT(EncodingBatch)
{
    Bitset legacy_prefixes[LEGACY_PREFIX_COUNT];
    Bitset is_rm_register;
    Bitset is_reg_register;
    GPR rm_register;
    GPR reg_register;
    Bitset implicit_register;
    VectorOpcode opcode;
    Bitset is_relative;
    Bitset is_displacement;
    Bitset displacement_size;
    Bitset rex_w;
    u8 segment_register_override[64];
    Bitset is_immediate;
    Bitset immediate_size[2];
    u8 immediate[8][64];
    u8 displacement[4][64];
};

fn Bitset bitset_from_bit(u8 bit)
{
    return -(u64)(bit != 0);
}

fn GPR register_mask_batch_from_scalar(u8 scalar_register)
{
    u64 reg = scalar_register & 0b1111;
    assert(reg == scalar_register);
    u64 value64 = (reg << 60) | (reg << 56) | (reg << 52) | (reg << 48) | (reg << 44) | (reg << 40) | (reg << 36) | (reg << 32) | (reg << 28) | (reg << 24) | (reg << 20) | (reg << 16) | (reg << 12) | (reg << 8) | (reg << 4) | reg;
    GPR result = { value64, value64, value64, value64 };
    return result;
}

fn EncodingBatch encoding_batch_from_scalar(EncodingScalar scalar)
{
    EncodingBatch batch = {
        .rm_register = register_mask_batch_from_scalar(scalar.rm_register),
        .reg_register = register_mask_batch_from_scalar(scalar.reg_register),
        .is_rm_register = bitset_from_bit(scalar.invariant.is_rm_register),
        .is_reg_register = bitset_from_bit(scalar.invariant.is_reg_register),
        .is_displacement = bitset_from_bit(scalar.invariant.is_displacement),
        .is_relative = bitset_from_bit(scalar.invariant.is_relative),
        .displacement_size = bitset_from_bit(scalar.invariant.displacement_size),
        .rex_w = bitset_from_bit(scalar.invariant.rex_w),
        .implicit_register = bitset_from_bit(scalar.invariant.implicit_register),
        .is_immediate = bitset_from_bit(scalar.invariant.is_immediate),
        .opcode = {
            .plus_register = bitset_from_bit(scalar.opcode.plus_register),
            .prefix_0f = bitset_from_bit(scalar.opcode.prefix_0f),
        },
    };

    for (u64 i = 0; i < array_length(batch.immediate_size); i += 1)
    {
        batch.immediate_size[i] = bitset_from_bit(scalar.invariant.immediate_size & (1 << i));
    }

    for (LegacyPrefix legacy_prefix = 0; legacy_prefix < LEGACY_PREFIX_COUNT; legacy_prefix += 1)
    {
        batch.legacy_prefixes[legacy_prefix] = bitset_from_bit((scalar.legacy_prefixes & (1 << legacy_prefix)) >> legacy_prefix);
    }

    for (u64 i = 0; i < batch_element_count; i += 1)
    {
        batch.opcode.values[0][i] = scalar.opcode.bytes[0];
        batch.opcode.values[1][i] = scalar.opcode.bytes[1];
        batch.opcode.extension[i] = scalar.opcode.extension;
    }

    for (u32 immediate_index = 0; immediate_index < array_length(scalar.immediate.bytes); immediate_index += 1)
    {
        for (u32 batch_index = 0; batch_index < batch_element_count; batch_index += 1)
        {
            batch.immediate[immediate_index][batch_index] = scalar.immediate.bytes[immediate_index];
        }
    }

    for (u32 displacement_index = 0; displacement_index < array_length(scalar.displacement.bytes); displacement_index += 1)
    {
        for (u32 batch_index = 0; batch_index < batch_element_count; batch_index += 1)
        {
            batch.displacement[displacement_index][batch_index] = scalar.displacement.bytes[displacement_index];
        }
    }

    return batch;
}

u32 encode_wide(u8* restrict buffer, const EncodingBatch* const restrict batch)
{
    __m512i prefixes[LEGACY_PREFIX_COUNT];
    __mmask64 prefix_masks[LEGACY_PREFIX_COUNT];
    for (LegacyPrefix prefix = 0; prefix < LEGACY_PREFIX_COUNT; prefix += 1)
    {
        prefix_masks[prefix] = _cvtu64_mask64(batch->legacy_prefixes[prefix]);
        prefixes[prefix] = _mm512_maskz_set1_epi8(prefix_masks[prefix], legacy_prefixes[prefix]);
    }

    __m512i instruction_length;

    u8 prefix_group1_bytes[64];
    u8 prefix_group1_positions[64];
    {
        __mmask64 prefix_group1_mask = _kor_mask64(_kor_mask64(prefix_masks[LEGACY_PREFIX_F0], prefix_masks[LEGACY_PREFIX_F2]), prefix_masks[LEGACY_PREFIX_F3]);
        __m512i prefix_group1 = _mm512_or_epi32(_mm512_or_epi32(prefixes[LEGACY_PREFIX_F0], prefixes[LEGACY_PREFIX_F2]), prefixes[LEGACY_PREFIX_F3]);
        __m512i prefix_group1_position = _mm512_maskz_set1_epi8(_knot_mask64(prefix_group1_mask), 0x0f);
        instruction_length = _mm512_maskz_set1_epi8(prefix_group1_mask, 0x01);

        _mm512_storeu_epi8(prefix_group1_bytes, prefix_group1);
        _mm512_storeu_epi8(prefix_group1_positions, prefix_group1_position);
    }

    u8 prefix_group2_bytes[64];
    u8 prefix_group2_positions[64];
    {
        __mmask64 prefix_group2_mask = _kor_mask64(_kor_mask64(_kor_mask64(prefix_masks[LEGACY_PREFIX_2E], prefix_masks[LEGACY_PREFIX_36]), _kor_mask64(prefix_masks[LEGACY_PREFIX_3E], prefix_masks[LEGACY_PREFIX_26])), _kor_mask64(prefix_masks[LEGACY_PREFIX_64], prefix_masks[LEGACY_PREFIX_65]));
        __m512i prefix_group2 = _mm512_or_epi32(_mm512_or_epi32(_mm512_or_epi32(prefixes[LEGACY_PREFIX_2E], prefixes[LEGACY_PREFIX_36]), _mm512_or_epi32(prefixes[LEGACY_PREFIX_3E], prefixes[LEGACY_PREFIX_26])), _mm512_or_epi32(prefixes[LEGACY_PREFIX_64], prefixes[LEGACY_PREFIX_65]));
        __m512i prefix_group2_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group2_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group2_mask, 0x01));

        _mm512_storeu_epi8(prefix_group2_bytes, prefix_group2);
        _mm512_storeu_epi8(prefix_group2_positions, prefix_group2_position);
    }

    u8 prefix_group3_bytes[64];
    u8 prefix_group3_positions[64];
    {
        __mmask64 prefix_group3_mask = prefix_masks[LEGACY_PREFIX_66];
        __m512i prefix_group3 = prefixes[LEGACY_PREFIX_66];
        __m512i prefix_group3_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group3_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group3_mask, 0x01));

        _mm512_storeu_epi8(prefix_group3_bytes, prefix_group3);
        _mm512_storeu_epi8(prefix_group3_positions, prefix_group3_position);
    }

    u8 prefix_group4_bytes[64];
    u8 prefix_group4_positions[64];
    {
        __mmask64 prefix_group4_mask = prefix_masks[LEGACY_PREFIX_67];
        __m512i prefix_group4 = prefixes[LEGACY_PREFIX_67];
        __m512i prefix_group4_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group4_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group4_mask, 0x01));

        _mm512_storeu_epi8(prefix_group4_bytes, prefix_group4);
        _mm512_storeu_epi8(prefix_group4_positions, prefix_group4_position);
    }

    __mmask64 is_plus_register = _cvtu64_mask64(batch->opcode.plus_register);
    __mmask64 is_implicit_register = _cvtu64_mask64(batch->implicit_register);

    __mmask64 is_displacement8 = _kand_mask64(_cvtu64_mask64(batch->is_displacement), _knot_mask64(_cvtu64_mask64(batch->displacement_size)));
    __mmask64 is_displacement32 = _kand_mask64(_cvtu64_mask64(batch->is_displacement), _cvtu64_mask64(batch->displacement_size));

    __mmask64 is_relative8 = _kand_mask64(_cvtu64_mask64(batch->is_relative), _knot_mask64(_cvtu64_mask64(batch->displacement_size)));
    __mmask64 is_relative32 = _kand_mask64(_cvtu64_mask64(batch->is_relative), _cvtu64_mask64(batch->displacement_size));

    __mmask64 is_rm_register;
    __m512i rm_register;
    {
        __m256i register_mask_256 = _mm256_loadu_epi8(&batch->rm_register);
        __m256i selecting_mask = _mm256_set1_epi8(0x0f);
        __m256i low_bits = _mm256_and_si256(register_mask_256, selecting_mask);
        __m256i high_bits = _mm256_and_si256(_mm256_srli_epi64(register_mask_256, 4), selecting_mask);
        __m256i low_bytes = _mm256_unpacklo_epi8(low_bits, high_bits);
        __m256i high_bytes = _mm256_unpackhi_epi8(low_bits, high_bits);
        rm_register = _mm512_inserti64x4(_mm512_castsi256_si512(low_bytes), high_bytes, 1);
        is_rm_register = _cvtu64_mask64(batch->is_rm_register);
    }

    __mmask64 is_reg_register;
    __m512i reg_register;
    {
        __m256i register_mask_256 = _mm256_loadu_epi8(&batch->reg_register);
        __m256i selecting_mask = _mm256_set1_epi8(0x0f);
        __m256i low_bits = _mm256_and_si256(register_mask_256, selecting_mask);
        __m256i high_bits = _mm256_and_si256(_mm256_srli_epi64(register_mask_256, 4), selecting_mask);
        __m256i low_bytes = _mm256_unpacklo_epi8(low_bits, high_bits);
        __m256i high_bytes = _mm256_unpackhi_epi8(low_bits, high_bits);
        reg_register = _mm512_inserti64x4(_mm512_castsi256_si512(low_bytes), high_bytes, 1);
        is_reg_register = _cvtu64_mask64(batch->is_reg_register);
    }

    __mmask64 is_reg_direct_addressing_mode = _knot_mask64(_kor_mask64(is_displacement8, is_displacement32));
    __mmask64 has_base_register = _kor_mask64(_kor_mask64(is_rm_register, is_reg_register), is_implicit_register);

    __m512i rex_b = _mm512_maskz_set1_epi8(_mm512_test_epi8_mask(rm_register, _mm512_set1_epi8(0b1000)), 1 << 0);
    __m512i rex_x = _mm512_set1_epi8(0); // TODO
    __m512i rex_r = _mm512_maskz_set1_epi8(_mm512_test_epi8_mask(reg_register, _mm512_set1_epi8(0b1000)), 1 << 2);
    __m512i rex_w = _mm512_maskz_set1_epi8(_cvtu64_mask64(batch->rex_w), 1 << 3);
    __m512i rex_byte = _mm512_or_epi32(_mm512_set1_epi32(0x40), _mm512_or_epi32(_mm512_or_epi32(rex_b, rex_x), _mm512_or_epi32(rex_r, rex_w)));
    __mmask64 rex_mask = _mm512_test_epi8_mask(rex_byte, _mm512_set1_epi8(0x0f));
    __m512i rex_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), rex_mask, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(rex_mask, 0x01));

    u8 rex_bytes[64];
    u8 rex_positions[64];
    _mm512_storeu_epi8(rex_bytes, rex_byte);
    _mm512_storeu_epi8(rex_positions, rex_position);

    __m512i plus_register = _mm512_and_si512(rm_register, _mm512_set1_epi8(0b111));
    __m512i opcode_extension = _mm512_loadu_epi8(&batch->opcode.extension[0]);

    __mmask64 prefix_0f_mask = _cvtu64_mask64(batch->opcode.prefix_0f);
    __m512i prefix_0f = _mm512_maskz_set1_epi8(prefix_0f_mask, 0x0f);
    __m512i prefix_0f_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_0f_mask, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_0f_mask, 0x01));

    u8 prefix_0f_bytes[64];
    u8 prefix_0f_positions[64];
    _mm512_storeu_epi8(prefix_0f_bytes, prefix_0f);
    _mm512_storeu_epi8(prefix_0f_positions, prefix_0f_position);

    __m512i three_byte_opcode = _mm512_loadu_epi8(&batch->opcode.values[1]);
    __mmask64 three_byte_opcode_mask = _mm512_test_epi8_mask(three_byte_opcode, _mm512_set1_epi8(0xff));
    __m512i three_byte_opcode_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), three_byte_opcode_mask, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(three_byte_opcode_mask, 0x01));

    u8 three_byte_opcode_bytes[64];
    u8 three_byte_opcode_positions[64];
    _mm512_storeu_epi8(three_byte_opcode_bytes, three_byte_opcode);
    _mm512_storeu_epi8(three_byte_opcode_positions, three_byte_opcode_position);
    
    __m512i base_opcode = _mm512_or_epi32(_mm512_loadu_epi8(&batch->opcode.values[0]), _mm512_maskz_mov_epi8(is_plus_register, plus_register));
    __m512i base_opcode_position = instruction_length;
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_set1_epi8(0x01));

    u8 base_opcode_bytes[64];
    u8 base_opcode_positions[64];
    _mm512_storeu_epi8(base_opcode_bytes, base_opcode);
    _mm512_storeu_epi8(base_opcode_positions, base_opcode_position);

    __m512i displacement8 = _mm512_loadu_epi8(batch->displacement[0]);
    __mmask64 mod_is_displacement32 = is_displacement32;
    __mmask64 mod_is_displacement8 = _kand_mask64(is_displacement8, _kor_mask64(_mm512_test_epi8_mask(displacement8, displacement8), _kand_mask64(is_rm_register, _mm512_cmpeq_epi8_mask(_mm512_and_si512(rm_register, _mm512_set1_epi8(0b111)), _mm512_set1_epi8(REGISTER_X86_64_BP)))));
    
    __mmask64 mod_rm_mask = _kor_mask64(_kand_mask64(_kor_mask64(is_rm_register, is_reg_register), _knot_mask64(is_plus_register)), _kor_mask64(is_displacement8, is_displacement32));
    __m512i register_direct_address_mode = _mm512_maskz_set1_epi8(is_reg_direct_addressing_mode, 1);
    __m512i mod = _mm512_or_epi32(_mm512_or_epi32(_mm512_slli_epi32(_mm512_maskz_set1_epi8(_kand_mask64(mod_is_displacement32, has_base_register), 1), 1), _mm512_maskz_set1_epi8(mod_is_displacement8, 1)), _mm512_or_epi32(_mm512_slli_epi32(register_direct_address_mode, 1), register_direct_address_mode));
    __m512i rm = _mm512_or_epi32(_mm512_and_si512(rm_register, _mm512_set1_epi8(0b111)), _mm512_maskz_set1_epi8(_knot_mask64(has_base_register), 0b100));
    __m512i reg = _mm512_or_epi32(_mm512_and_si512(reg_register, _mm512_set1_epi8(0b111)), opcode_extension);
    __m512i mod_rm = _mm512_or_epi32(_mm512_or_epi32(rm, _mm512_slli_epi32(reg, 3)), _mm512_slli_epi32(mod, 6));
    __m512i mod_rm_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_rm_mask, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_rm_mask, 0x01));

    u8 mod_rm_bytes[64];
    u8 mod_rm_positions[64];
    _mm512_storeu_epi8(mod_rm_bytes, mod_rm);
    _mm512_storeu_epi8(mod_rm_positions, mod_rm_position);

    __mmask64 sib_mask = _kand_mask64(_mm512_cmpneq_epi8_mask(mod, _mm512_set1_epi8(0b11)), _mm512_cmpeq_epi8_mask(rm, _mm512_set1_epi8(0b100)));
    __m512i sib_scale = _mm512_set1_epi8(0);
    __m512i sib_index = _mm512_maskz_set1_epi8(sib_mask, 0b100 << 3);
    __m512i sib_base = _mm512_or_epi32(_mm512_and_si512(rm_register, _mm512_maskz_set1_epi8(is_rm_register, 0b111)), _mm512_maskz_set1_epi8(_knot_mask64(is_rm_register), 0b101));
    __m512i sib = _mm512_or_epi32(_mm512_or_epi32(sib_index, sib_base), sib_scale);
    __m512i sib_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), sib_mask, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(sib_mask, 0x01));

    u8 sib_bytes[64];
    u8 sib_positions[64];
    _mm512_storeu_epi8(sib_bytes, sib);
    _mm512_storeu_epi8(sib_positions, sib_position);

    __m512i displacement8_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_is_displacement8, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_is_displacement8, sizeof(s8)));
    u8 displacement8_positions[64];
    _mm512_storeu_epi8(displacement8_positions, displacement8_position);

    __m512i displacement32_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_is_displacement32, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_is_displacement32, sizeof(s32)));
    u8 displacement32_positions[64];
    _mm512_storeu_epi8(displacement32_positions, displacement32_position);

    __m512i relative8_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), is_relative8, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(is_relative8, sizeof(s8)));
    u8 relative8_positions[64];
    _mm512_storeu_epi8(relative8_positions, relative8_position);

    __m512i relative32_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), is_relative32, instruction_length);
    instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(is_relative32, sizeof(s32)));
    u8 relative32_positions[64];
    _mm512_storeu_epi8(relative32_positions, relative32_position);

    __mmask64 is_immediate_mask = _cvtu64_mask64(batch->is_immediate);
    __mmask64 mask0 = _cvtu64_mask64(batch->immediate_size[0]);
    __m512i mask_v0 = _mm512_maskz_set1_epi8(_kand_mask64(is_immediate_mask, mask0), 1 << 0);
    __mmask64 mask1 = _cvtu64_mask64(batch->immediate_size[1]);
    __m512i mask_v1 = _mm512_maskz_set1_epi8(_kand_mask64(is_immediate_mask, mask1), 1 << 1);
    __m512i immediate_size = _mm512_or_si512(mask_v0, mask_v1);
    __mmask64 is_immediate[4];
    u8 immediate_positions[array_length(is_immediate)][64];
    for (u64 i = 0; i < array_length(is_immediate); i += 1)
    {
        __mmask64 immediate_mask = _mm512_cmpeq_epi8_mask(immediate_size, _mm512_set1_epi8(i));
        __m512i immediate_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), immediate_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(immediate_mask, 1 << i));
        _mm512_storeu_epi8(immediate_positions[i], immediate_position);
    }

    u8 separate_buffers[64][max_instruction_byte_count];
    u8 separate_lengths[64];
    _mm512_storeu_epi8(separate_lengths, instruction_length);

    for (u32 i = 0; i < array_length(separate_lengths); i += 1)
    {
        separate_buffers[i][prefix_group1_positions[i]] = prefix_group1_bytes[i];
        separate_buffers[i][prefix_group2_positions[i]] = prefix_group2_bytes[i];
        separate_buffers[i][prefix_group3_positions[i]] = prefix_group3_bytes[i];
        separate_buffers[i][prefix_group4_positions[i]] = prefix_group4_bytes[i];

        separate_buffers[i][rex_positions[i]] = rex_bytes[i];

        separate_buffers[i][prefix_0f_positions[i]] = prefix_0f_bytes[i];
        separate_buffers[i][three_byte_opcode_positions[i]] = three_byte_opcode_bytes[i];
        separate_buffers[i][base_opcode_positions[i]] = base_opcode_bytes[i];

        separate_buffers[i][mod_rm_positions[i]] = mod_rm_bytes[i];

        separate_buffers[i][sib_positions[i]] = sib_bytes[i];

        for (u32 immediate_position_index = 0; immediate_position_index < array_length(immediate_positions); immediate_position_index += 1)
        {
            u8 start_position = immediate_positions[immediate_position_index][i];
            for (u32 byte = 0; byte < 1 << immediate_position_index; byte += 1)
            {
                u8 destination_index = start_position + byte * (start_position != 0xf);
                separate_buffers[i][destination_index] = batch->immediate[byte][i];
            }
        }

        separate_buffers[i][displacement8_positions[i]] = batch->displacement[0][i];

        u8 displacement32_start = displacement32_positions[i];
        for (u32 byte = 0; byte < 4; byte += 1)
        {
            u8 destination_index = displacement32_start + byte * (displacement32_start != 0xf);
            separate_buffers[i][destination_index] = batch->displacement[byte][i];
        }

        separate_buffers[i][relative8_positions[i]] = batch->displacement[0][i];
        
        u8 relative32_start = relative32_positions[i];
        for (u32 byte = 0; byte < 4; byte += 1)
        {
            u8 destination_index = relative32_start + byte * (relative32_start != 0xf);
            separate_buffers[i][destination_index] = batch->displacement[byte][i];
        }
    }

    u32 buffer_i = 0;

    for (u32 i = 0; i < array_length(separate_lengths); i += 1)
    {
        let(separate_length, separate_lengths[i]);
        if (separate_length >= 1 && separate_length <= 15)
        {
            memcpy(&buffer[buffer_i], &separate_buffers[i], separate_length);
            buffer_i += separate_length;
        }
        else
        {
            unreachable();
        }
    }

    return buffer_i;
}

STRUCT(TestCounter)
{
    u64 total;
    u64 failure;
};

typedef enum TestMode
{
    TEST_MODE_SCALAR,
    TEST_MODE_WIDE,
    TEST_MODE_COUNT,
} TestMode;

fn String test_mode_to_string(TestMode test_mode)
{
    switch (test_mode)
    {
        case_to_name(TEST_MODE_, SCALAR);
        case_to_name(TEST_MODE_, WIDE);
        case TEST_MODE_COUNT: unreachable();
    }
}

STRUCT(TestSetup)
{
    String instruction_binary_buffer;
    String clang_path;
    String error_buffer;
    VirtualBuffer(u8)* clang_pipe_buffer;
    LLVMDisasmContextRef disassembler;
    Arena* arena;
    TestCounter counters[TEST_MODE_COUNT];
    EncodingTestOptions options;
};

STRUCT(TestInstruction)
{
    EncodingScalar encoding;
    String text;
};

fn void test_instruction(TestSetup* setup, TestInstruction* instruction)
{
    if (setup->options.scalar)
    {
        let(length, encode_scalar(setup->instruction_binary_buffer.pointer, &instruction->encoding, 1));
        assert(length <= setup->instruction_binary_buffer.length);
        String instruction_bytes = {
            .pointer = setup->instruction_binary_buffer.pointer,
            .length = length,
        };
        CheckInstructionArguments check_args = {
            .clang_path = setup->clang_path,
            .text = instruction->text,
            .binary = instruction_bytes,
            .error_buffer = setup->error_buffer,
            .clang_pipe_buffer = setup->clang_pipe_buffer,
            .disassembler = setup->disassembler,
        };
        u64 error_buffer_length = check_instruction(setup->arena, check_args);
        setup->counters[TEST_MODE_SCALAR].total += 1;
        let(first_failure, setup->counters[TEST_MODE_SCALAR].total == 0);
        setup->counters[TEST_MODE_SCALAR].failure += error_buffer_length != 0;
        String error_string = { .pointer = setup->error_buffer.pointer, .length = error_buffer_length };
        if (error_buffer_length != 0)
        {
            print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", setup->counters[TEST_MODE_SCALAR].total, instruction->text, error_string);
            os_exit(1);
        }
    }

    if (setup->options.wide)
    {
        EncodingBatch batch = encoding_batch_from_scalar(instruction->encoding);
        let(wide_length, encode_wide(setup->instruction_binary_buffer.pointer, &batch));
        assert(wide_length % batch_element_count == 0);
        let(length, wide_length / batch_element_count);

        String instruction_bytes = {
            .pointer = setup->instruction_binary_buffer.pointer,
            .length = length,
        };
        CheckInstructionArguments check_args = {
            .clang_path = setup->clang_path,
            .text = instruction->text,
            .binary = instruction_bytes,
            .error_buffer = setup->error_buffer,
            .clang_pipe_buffer = setup->clang_pipe_buffer,
            .disassembler = setup->disassembler,
        };
        u64 error_buffer_length = check_instruction(setup->arena, check_args);
        setup->counters[TEST_MODE_WIDE].total += 1;
        let(first_failure, setup->counters[TEST_MODE_WIDE].total == 0);
        setup->counters[TEST_MODE_WIDE].failure += error_buffer_length != 0;
        String error_string = { .pointer = setup->error_buffer.pointer, .length = error_buffer_length };
        if (error_buffer_length != 0)
        {
            print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", setup->counters[TEST_MODE_WIDE].total, instruction->text, error_string);
        }
    }
}

fn u8 encoding_test_instruction_batches(Arena* arena, TestDataset dataset, EncodingTestOptions options)
{
    u8 result = 0;
    u8 instruction_binary_buffer[256 * batch_element_count];
    u8 instruction_text_buffer[256];
    u8 error_buffer[4096];
    String instruction_text_buffer_slice = array_to_slice(instruction_text_buffer);
    VirtualBuffer(u8) clang_pipe_buffer = {};
    vb_ensure_capacity(&clang_pipe_buffer, 1024*1024);
    llvm_initialize_macro(X86, _null_prefix_());
    let(disassembler, LLVMCreateDisasmCPU("x86_64-freestanding", "znver4", 0, 0, 0, 0));
    u64 disassembly_options = LLVMDisassembler_Option_AsmPrinterVariant | LLVMDisassembler_Option_PrintImmHex;
    if (!LLVMSetDisasmOptions(disassembler, disassembly_options))
    {
        failed_execution();
    }

    String clang_path = executable_find_in_path(arena, strlit("clang"), cstr(getenv("PATH")));
    assert(clang_path.pointer);

    global_variable const s32 displacements[] = {
        0,
        10,
        10000000,
    };

    global_variable const String displacement_strings[] = {
        strlit("0"),
        strlit("10"),
        strlit("10000000"),
    };

    TestSetup setup = {
        .instruction_binary_buffer = array_to_slice(instruction_binary_buffer),
        .clang_path = clang_path,
        .error_buffer = array_to_slice(error_buffer),
        .clang_pipe_buffer = &clang_pipe_buffer,
        .options = options,
        .disassembler = disassembler,
        .arena = arena,
    };

    for (u64 batch_index = 0; batch_index < dataset.batch_count; batch_index += 1)
    {
        let(batch, &dataset.batches[batch_index]);

        String mnemonic_string = mnemonic_x86_64_to_string(batch->mnemonic);
        print("============================\n~~~~~~~ MNEMONIC {s} ~~~~~~~\n============================\n", mnemonic_string);

        u64 encoding_top = batch->encoding_offset + batch->encoding_count;

        for (u64 encoding_index = batch->encoding_offset; encoding_index < encoding_top; encoding_index += 1)
        {
            memset(setup.counters, 0, sizeof(setup.counters));
            let(encoding, &dataset.encodings[encoding_index]);
            OperandId first_operand = encoding->operands.values[0];
            OperandId second_operand = encoding->operands.values[1];
            u8 operand_count = encoding->operands.count;

            u8 encoding_buffer[256];
            u8 encoding_separator[256];
            u64 encoding_buffer_i = 0;
            String encoding_string;
            String encoding_separator_string;
            {
                memcpy(encoding_buffer + encoding_buffer_i, mnemonic_string.pointer, mnemonic_string.length);
                encoding_buffer_i += mnemonic_string.length;

                encoding_buffer[encoding_buffer_i] = ' ';
                encoding_buffer_i += operand_count != 0;

                for (u8 operand_i = 0; operand_i < operand_count; operand_i += 1)
                {
                    String operand_string = operand_to_string(encoding->operands.values[operand_i]);
                    memcpy(encoding_buffer + encoding_buffer_i, operand_string.pointer, operand_string.length);
                    encoding_buffer_i += operand_string.length;

                    u8 not_last_operand = operand_i != operand_count - 1;

                    encoding_buffer[encoding_buffer_i] = ',';
                    encoding_buffer_i += not_last_operand;

                    encoding_buffer[encoding_buffer_i] = ' ';
                    encoding_buffer_i += not_last_operand;
                }
                memcpy(&encoding_buffer[encoding_buffer_i], "... ", 4);
                encoding_buffer_i += 4;

                encoding_buffer[encoding_buffer_i] = 0;

                encoding_string = (String) { .pointer = encoding_buffer, .length = encoding_buffer_i };

                let(failed_string, strlit("FAILED"));
                encoding_separator_string = (String) { .pointer = encoding_separator, .length = encoding_buffer_i + 3 + 1 + failed_string.length };
                memset(encoding_separator, '-', encoding_separator_string.length);
                print_string(encoding_separator_string);
                print_string(strlit("\n"));
                print_string(encoding_string);
            }

            if (operand_count == 0)
            {
                TestInstruction instruction = {
                    .encoding = {
                        .invariant = {
                            .rex_w = encoding->rex_w,
                        },
                        .legacy_prefixes = batch->legacy_prefixes | (encoding->operand_size_override << LEGACY_PREFIX_66),
                        .opcode = encoding->opcode,
                    },
                    .text = mnemonic_string,
                };

                test_instruction(&setup, &instruction);
            }
            else if (op_is_gpra(first_operand))
            {
                let(first_operand_index, op_gpra_get_index(first_operand));
                String register_a_names[] = {
                    strlit("al"),
                    strlit("ax"),
                    strlit("eax"),
                    strlit("rax"),
                };
                String first_operand_register_name = register_a_names[first_operand_index];
                String first_operand_string = first_operand_register_name;

                switch (operand_count)
                {
                    case 1:
                        {
                            if (encoding->operands.implicit_operands)
                            {
                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || (first_operand_index == 3),
                                            .implicit_register = 1,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .opcode = encoding->opcode,
                                    },
                                    .text = mnemonic_string,
                                };

                                test_instruction(&setup, &instruction);
                            }
                            else
                            {
                                todo();
                            }
                        } break;
                    case 2:
                        {
                            if (op_is_gpr_no_gpra(second_operand))
                            {
                                u8 second_operand_index = op_gpr_get_index(second_operand);
                                GPR_x86_64 second_operand_register_count = (unlikely(second_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                u8 second_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                String second_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];
                                u8 second_is_rm = op_is_rm(second_operand);

                                if (second_is_rm)
                                {
                                    for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                    {
                                        String second_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            second_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(second_rm_buffer[gpr][displacement_index]), second_operand_rm_name, displacement_strings[displacement_index], second_operand_index);
                                        }
                                    }
                                }

                                for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                {
                                    String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w || second_operand_index == 3,
                                                .is_rm_register = 1,
                                            },
                                            .rm_register = second_gpr,
                                            .legacy_prefixes = batch->legacy_prefixes | ((second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }

                                if (second_is_rm)
                                {
                                    for (GPR_x86_64 second_gpr = 0; second_gpr < X86_64_GPR_COUNT; second_gpr += 1)
                                    {
                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            String second_operand_string = second_rm_strings[second_gpr][displacement_index];

                                            TestInstruction instruction = {
                                                .encoding = {
                                                    .invariant = {
                                                        .rex_w = encoding->rex_w || second_operand_index == 3,
                                                        .is_rm_register = 1,
                                                        .is_displacement = 1,
                                                        .displacement_size = displacement_index == 2,
                                                    },
                                                    .rm_register = second_gpr,
                                                    .legacy_prefixes = batch->legacy_prefixes | ((second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                    .displacement = { .value = displacements[displacement_index] },
                                                    .opcode = encoding->opcode,
                                                },
                                                .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                            };

                                            test_instruction(&setup, &instruction);
                                        }
                                    }
                                }
                            }
                            else if (op_is_imm(second_operand))
                            {
                                let(second_operand_index, op_imm_get_index(second_operand));
                                // We output the string directly to avoid formatting cost
                                String second_operand_string = sample_immediate_strings(second_operand_index);
                                u64 immediate = sample_immediate_values(second_operand_index);
                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                            .implicit_register = 1,
                                            .is_immediate = 1,
                                            .immediate_size = second_operand_index,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .immediate = { .value = immediate, },
                                        .opcode = encoding->opcode,
                                    },
                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                };
                                test_instruction(&setup, &instruction);
                            }
                            else if (op_is_gprd(second_operand))
                            {
                                assert(encoding->operands.implicit_operands);
                                String second_operand_string = op_gprd_to_string(second_operand);
                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                            .implicit_register = 1,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .opcode = encoding->opcode,
                                    },
                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                };
                                test_instruction(&setup, &instruction);
                            }
                            else if (op_is_ds_rsi_memory(second_operand))
                            {
                                // u8 second_operand_index = second_operand - op_ds_rsi_m8;
                                String second_operand_string;
                                switch (second_operand)
                                {
                                    case op_ds_rsi_m8:  second_operand_string = strlit("byte ptr [rsi]"); break;
                                    case op_ds_rsi_m16: second_operand_string = strlit("word ptr [rsi]"); break;
                                    case op_ds_rsi_m32: second_operand_string = strlit("dword ptr [rsi]"); break;
                                    case op_ds_rsi_m64: second_operand_string = strlit("qword ptr [rsi]"); break;
                                    default: unreachable();
                                }

                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .opcode = encoding->opcode,
                                    },
                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                };

                                test_instruction(&setup, &instruction);
                            }
                            else if (op_is_es_rdi_memory(second_operand))
                            {
                                // u8 second_operand_index = second_operand - op_ds_rsi_m8;
                                String second_operand_string;
                                switch (second_operand)
                                {
                                    case op_es_rdi_m8:  second_operand_string = strlit("byte ptr es:[rdi]"); break;
                                    case op_es_rdi_m16: second_operand_string = strlit("word ptr es:[rdi]"); break;
                                    case op_es_rdi_m32: second_operand_string = strlit("dword ptr es:[rdi]"); break;
                                    case op_es_rdi_m64: second_operand_string = strlit("qword ptr es:[rdi]"); break;
                                    default: unreachable();
                                }

                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .opcode = encoding->opcode,
                                    },
                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                };

                                test_instruction(&setup, &instruction);
                            }
                            else
                            {
                                todo();
                            }
                        } break;
                    case 3:
                        {
                            todo();
                        } break;
                    case 4:
                        {
                            todo();
                        } break;
                    default: unreachable();
                }
            }
            else
            {
                switch (operand_count)
                {
                    case 1:
                        {
                            if (op_is_gpr_no_gpra(first_operand))
                            {
                                u8 first_operand_index = op_gpr_get_index(first_operand);
                                GPR_x86_64 first_operand_register_count = (unlikely(first_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                u8 first_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                String first_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];
                                u8 first_is_rm = op_is_rm(first_operand);

                                if (first_is_rm)
                                {
                                    for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                    {
                                        String first_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            first_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(first_rm_buffer[gpr][displacement_index]), first_operand_rm_name, displacement_strings[displacement_index], first_operand_index);
                                        }
                                    }
                                }

                                for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                {
                                    String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w || first_operand_index == 3,
                                                .is_rm_register = 1,
                                            },
                                            .rm_register = first_gpr,
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }

                                if (first_is_rm)
                                {
                                    for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                    {
                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            String first_operand_string = first_rm_strings[first_gpr][displacement_index];

                                            TestInstruction instruction = {
                                                .encoding = {
                                                    .invariant = {
                                                        .rex_w = encoding->rex_w || first_operand_index == 3,
                                                        .is_rm_register = 1,
                                                        .is_displacement = 1,
                                                        .displacement_size = displacement_index == 2,
                                                    },
                                                    .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                    .displacement = { .value = displacements[displacement_index] },
                                                    .rm_register = first_gpr,
                                                    .opcode = encoding->opcode,
                                                },
                                                .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                            };

                                            test_instruction(&setup, &instruction);
                                        }
                                    }
                                }
                            }
                            else if (op_is_relative(first_operand))
                            {
                                String first_operand_string = strlit("-1");
                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w,
                                            .is_relative = 1,
                                            .displacement_size = first_operand == op_rel32,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | (encoding->operand_size_override << LEGACY_PREFIX_66),
                                        .opcode = encoding->opcode,
                                        .displacement = { .value = 0xffffffff },
                                    },
                                    .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                };

                                test_instruction(&setup, &instruction);
                            }
                            else if (op_is_memory(first_operand))
                            {
                                u8 first_operand_index = first_operand - op_m8;
                                String first_operand_indirect_string;
                                switch (first_operand_index)
                                {
                                    case 0: first_operand_indirect_string = strlit("byte ptr "); break;
                                    case 1: first_operand_indirect_string = strlit("word ptr "); break;
                                    case 2: first_operand_indirect_string = strlit("dword ptr "); break;
                                    case 3: first_operand_indirect_string = strlit("qword ptr "); break;
                                    case 4: first_operand_indirect_string = strlit("xmmword ptr "); break;
                                    default: unreachable();
                                }

                                // Segment overrides
                                {
                                    let_cast(u32, memory_value, sample_immediate_values(2));
                                    String memory_string = sample_immediate_strings(2);

                                    for (SegmentRegisterOverride segment_register_override = 0; segment_register_override < SEGMENT_REGISTER_OVERRIDE_COUNT; segment_register_override += 1)
                                    {
                                        String segment_register_string = segment_register_override_to_register_string(segment_register_override);

                                        String parts[] = {
                                            first_operand_indirect_string,
                                            segment_register_string,
                                            strlit(":["),
                                            memory_string,
                                            strlit("]"),
                                        };
                                        String first_operand_string = arena_join_string(setup.arena, (Slice(String)) array_to_slice(parts));

                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 4,
                                                    .is_displacement = 1,
                                                    .displacement_size = 1,
                                                },
                                                .legacy_prefixes = batch->legacy_prefixes | (1 << segment_register_overrides[segment_register_override]) | (encoding->operand_size_override << LEGACY_PREFIX_66),
                                                .displacement = { .value = memory_value, },
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }

                                // No segment override
                                {
                                    let_cast(u32, memory_value, sample_immediate_values(2));
                                    String memory_string = sample_immediate_strings(2);

                                    String parts[] = {
                                        first_operand_indirect_string,
                                        strlit("["),
                                        memory_string,
                                        strlit("]"),
                                    };
                                    String first_operand_string = arena_join_string(setup.arena, (Slice(String)) array_to_slice(parts));

                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w || first_operand_index == 4,
                                                .is_displacement = 1,
                                                .displacement_size = 1,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | (encoding->operand_size_override << LEGACY_PREFIX_66),
                                            .displacement = { .value = memory_value, },
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }

                                for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                {
                                    String first_operand_rm_name = gpr_to_string(first_gpr, 3, 0);

                                    for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                    {
                                        u8 first_operand_buffer[256];
                                        String first_operand_string = format_displacement((String)array_to_slice(first_operand_buffer), first_operand_rm_name, displacement_strings[displacement_index], first_operand_index);

                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .is_displacement = 1,
                                                    .displacement_size = displacement_index == 2,
                                                    .rex_w = encoding->rex_w || first_operand_index == 4,
                                                    .is_rm_register = 1,
                                                },
                                                .rm_register = first_gpr,
                                                .legacy_prefixes = batch->legacy_prefixes | (encoding->operand_size_override << LEGACY_PREFIX_66),
                                                .displacement = { .value = displacements[displacement_index] },
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }
                            }
                            else if (op_is_imm(first_operand))
                            {
                                u8 first_operand_index = op_imm_get_index(first_operand);
                                String first_operand_string = sample_immediate_strings(first_operand_index);
                                u64 immediate = sample_immediate_values(first_operand_index);

                                TestInstruction instruction = {
                                    .encoding = {
                                        .invariant = {
                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                            .is_immediate = 1,
                                            .immediate_size = first_operand_index,
                                        },
                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                        .immediate = { .value = immediate },
                                        .opcode = encoding->opcode,
                                    },
                                    .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                };

                                test_instruction(&setup, &instruction);
                            }
                            else
                            {
                                todo();
                            }
                        } break;
                    case 2:
                        {
                            if (op_is_gpr_no_gpra(first_operand))
                            {
                                u8 first_operand_index = op_gpr_get_index(first_operand);
                                GPR_x86_64 first_operand_register_count = (unlikely(first_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;

                                u8 first_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                String first_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];
                                u8 first_is_rm = op_is_rm(first_operand);

                                if (first_is_rm)
                                {
                                    for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                    {
                                        String first_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            first_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(first_rm_buffer[gpr][displacement_index]), first_operand_rm_name, displacement_strings[displacement_index], first_operand_index);
                                        }
                                    }
                                }

                                if (op_is_gpr_no_gpra(second_operand))
                                {
                                    u8 second_operand_index = op_gpr_get_index(second_operand);
                                    GPR_x86_64 second_operand_register_count = (unlikely(second_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                    u8 second_is_rm = op_is_rm(second_operand);
                                    u8 second_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                    String second_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];

                                    if (second_is_rm)
                                    {
                                        for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                        {
                                            String second_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                            for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                            {
                                                second_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(second_rm_buffer[gpr][displacement_index]), second_operand_rm_name, displacement_strings[displacement_index], second_operand_index);
                                            }
                                        }
                                    }

                                    // Only test with rm_r and not r_rm with register direct addressing mode because it makes no sense otherwise
                                    if (first_is_rm)
                                    {
                                        for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                        {
                                            String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                            for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                            {
                                                String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);

                                                TestInstruction instruction = {
                                                    .encoding = {
                                                        .invariant = {
                                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                                            .is_rm_register = 1,
                                                            .is_reg_register = 1,
                                                        },
                                                        .rm_register = first_gpr,
                                                        .reg_register = second_gpr,
                                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                        .opcode = encoding->opcode,
                                                    },
                                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                                };

                                                test_instruction(&setup, &instruction);
                                            }
                                        }
                                    }

                                    if (first_is_rm)
                                    {
                                        for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                        {
                                            for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                            {
                                                String first_operand_string = first_rm_strings[first_gpr][displacement_index];

                                                for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                                {
                                                    String second_operand_string = gpr_to_string(second_gpr, second_operand_index, gpr_is_extended(first_gpr));

                                                    TestInstruction instruction = {
                                                        .encoding = {
                                                            .invariant = {
                                                                .rex_w = encoding->rex_w || first_operand_index == 3,
                                                                .is_rm_register = 1,
                                                                .is_reg_register = 1,
                                                                .is_displacement = 1,
                                                                .displacement_size = displacement_index == 2,
                                                            },
                                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                            .rm_register = first_gpr,
                                                            .reg_register = second_gpr,
                                                            .displacement = { .value = displacements[displacement_index] },
                                                            .opcode = encoding->opcode,
                                                        },
                                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                                    };

                                                    test_instruction(&setup, &instruction);
                                                }
                                            }
                                        }
                                    }

                                    if (second_is_rm)
                                    {
                                        for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                        {
                                            for (GPR_x86_64 second_gpr = 0; second_gpr < X86_64_GPR_COUNT; second_gpr += 1)
                                            {
                                                String first_operand_string = gpr_to_string(first_gpr, first_operand_index, gpr_is_extended(second_gpr));

                                                for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                                {
                                                    String second_operand_string = second_rm_strings[second_gpr][displacement_index];

                                                    TestInstruction instruction = {
                                                        .encoding = {
                                                            .invariant = {
                                                                .rex_w = encoding->rex_w || first_operand_index == 3,
                                                                .is_rm_register = 1,
                                                                .is_reg_register = 1,
                                                                .is_displacement = 1,
                                                                .displacement_size = displacement_index == 2,
                                                            },
                                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                            .displacement = { .value = displacements[displacement_index] },
                                                            .rm_register = second_gpr,
                                                            .reg_register = first_gpr,
                                                            .opcode = encoding->opcode,
                                                        },
                                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                                    };

                                                    test_instruction(&setup, &instruction);
                                                }
                                            }
                                        }
                                    }
                                }
                                else if (op_is_gpra(second_operand))
                                {
                                    String second_operand_string = op_gpra_to_string(second_operand);
                                    for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                    {
                                        String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);
                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 3,
                                                    .is_rm_register = 1,
                                                },
                                                .rm_register = first_gpr,
                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }
                                else if (op_is_imm(second_operand))
                                {
                                    u8 second_operand_index = op_imm_get_index(second_operand);
                                    String second_operand_string = sample_immediate_strings(second_operand_index);
                                    u64 immediate = sample_immediate_values(second_operand_index);

                                    for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                    {
                                        String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);
                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 3,
                                                    .is_rm_register = 1,
                                                    .is_immediate = 1,
                                                    .immediate_size = second_operand_index,
                                                },
                                                .rm_register = first_gpr,
                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                .immediate = { .value = immediate },
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }

                                    if (first_is_rm)
                                    {
                                        for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                        {
                                            for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                            {
                                                String first_operand_string = first_rm_strings[first_gpr][displacement_index];

                                                TestInstruction instruction = {
                                                    .encoding = {
                                                        .invariant = {
                                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                                            .is_rm_register = 1,
                                                            .is_immediate = 1,
                                                            .immediate_size = second_operand_index,
                                                            .is_displacement = 1,
                                                            .displacement_size = displacement_index == 2,
                                                        },
                                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                        .immediate = { .value = immediate },
                                                        .displacement = { .value = displacements[displacement_index] },
                                                        .rm_register = first_gpr,
                                                        .opcode = encoding->opcode,
                                                    },
                                                    .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                                };

                                                test_instruction(&setup, &instruction);
                                            }
                                        }
                                    }
                                }
                                else if (op_is_memory(second_operand))
                                {
                                    u8 second_operand_index = second_operand - op_m8;
                                    String second_operand_indirect_string;
                                    String memory_string = sample_immediate_strings(2);
                                    switch (second_operand_index)
                                    {
                                        case 0: second_operand_indirect_string = strlit(""); break;
                                        case 1: second_operand_indirect_string = strlit(""); break;
                                        case 2: second_operand_indirect_string = strlit(""); break;
                                        case 3: second_operand_indirect_string = strlit(""); break;
                                        case 4: second_operand_indirect_string = strlit(""); break;
                                        default: unreachable();
                                    }
                                    String parts[] = {
                                        second_operand_indirect_string,
                                        strlit("["),
                                        memory_string,
                                        strlit("]"),
                                    };
                                    String second_operand_string = arena_join_string(setup.arena, (Slice(String)) array_to_slice(parts));

                                    for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                    {
                                        String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                        let_cast(u32, memory_value, sample_immediate_values(2));
                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 3 || second_operand_index == 3,
                                                    .is_reg_register = 0,
                                                    .is_displacement = 1,
                                                    .displacement_size = 1,
                                                },
                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                .displacement = { .value = memory_value, },
                                                .reg_register = first_gpr,
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }
                                else if (second_operand == op_one_literal)
                                {
                                    GPR_x86_64 first_operand_register_count = (unlikely(first_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                    for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                    {
                                        String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 3,
                                                    .is_rm_register = 1,
                                                },
                                                .rm_register = first_gpr,
                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction1(instruction_text_buffer_slice, mnemonic_string, first_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }
                                else if (second_operand == op_cl)
                                {
                                    String second_operand_string = strlit("cl");
                                    GPR_x86_64 first_operand_register_count = (unlikely(first_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                    for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                    {
                                        String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                        TestInstruction instruction = {
                                            .encoding = {
                                                .invariant = {
                                                    .rex_w = encoding->rex_w || first_operand_index == 3,
                                                    .is_rm_register = 1,
                                                },
                                                .rm_register = first_gpr,
                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                .opcode = encoding->opcode,
                                            },
                                            .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                        };

                                        test_instruction(&setup, &instruction);
                                    }
                                }
                                else
                                {
                                    todo();
                                }
                            }
                            else if (op_is_ds_rsi_memory(first_operand))
                            {
                                u8 first_operand_index = first_operand - op_ds_rsi_m8;
                                String first_operand_string;
                                switch (first_operand)
                                {
                                    case op_ds_rsi_m8:  first_operand_string = strlit("byte ptr [rsi]"); break;
                                    case op_ds_rsi_m16: first_operand_string = strlit("word ptr [rsi]"); break;
                                    case op_ds_rsi_m32: first_operand_string = strlit("dword ptr [rsi]"); break;
                                    case op_ds_rsi_m64: first_operand_string = strlit("qword ptr [rsi]"); break;
                                    default: unreachable();
                                }

                                if (op_is_es_rdi_memory(second_operand))
                                {
                                    String second_operand_string;
                                    switch (second_operand)
                                    {
                                        case op_es_rdi_m8:  second_operand_string = strlit("byte ptr es:[rdi]"); break;
                                        case op_es_rdi_m16: second_operand_string = strlit("word ptr es:[rdi]"); break;
                                        case op_es_rdi_m32: second_operand_string = strlit("dword ptr es:[rdi]"); break;
                                        case op_es_rdi_m64: second_operand_string = strlit("qword ptr es:[rdi]"); break;
                                        default: unreachable();
                                    }

                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w || first_operand_index == 3,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else
                                {
                                    todo();
                                }
                            }
                            else if (op_is_es_rdi_memory(first_operand))
                            {
                                u8 first_operand_index = first_operand - op_es_rdi_m8;
                                String first_operand_string;
                                switch (first_operand)
                                {
                                    case op_es_rdi_m8:  first_operand_string = strlit("byte ptr es:[rdi]"); break;
                                    case op_es_rdi_m16: first_operand_string = strlit("word ptr es:[rdi]"); break;
                                    case op_es_rdi_m32: first_operand_string = strlit("dword ptr es:[rdi]"); break;
                                    case op_es_rdi_m64: first_operand_string = strlit("qword ptr es:[rdi]"); break;
                                    default: unreachable();
                                }

                                if (op_is_ds_rsi_memory(second_operand))
                                {
                                    u8 second_operand_index = second_operand - op_ds_rsi_m8;
                                    String second_operand_string;
                                    switch (second_operand)
                                    {
                                        case op_ds_rsi_m8:  second_operand_string = strlit("byte ptr [rsi]"); break;
                                        case op_ds_rsi_m16: second_operand_string = strlit("word ptr [rsi]"); break;
                                        case op_ds_rsi_m32: second_operand_string = strlit("dword ptr [rsi]"); break;
                                        case op_ds_rsi_m64: second_operand_string = strlit("qword ptr [rsi]"); break;
                                        default: unreachable();
                                    }
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else if (op_is_gpra(second_operand))
                                {
                                    u8 second_operand_index = op_gpra_get_index(second_operand);
                                    String second_operand_string = op_gpra_to_string(second_operand);
                                    
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w || second_operand_index == 3,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else if (second_operand == op_dx)
                                {
                                    String second_operand_string = strlit("dx");
                                    
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else
                                {
                                    todo();
                                }
                            }
                            else if (op_is_imm(first_operand))
                            {
                                u8 first_operand_index = op_imm_get_index(first_operand);
                                u64 first_operand_value = sample_immediate_values(first_operand_index);
                                String first_operand_string = sample_immediate_strings(first_operand_index);

                                if (op_is_gpra(second_operand))
                                {
                                    let(second_operand_index, op_gpra_get_index(second_operand));
                                    String second_operand_string = op_gpra_to_string(second_operand);
                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w,
                                                .is_immediate = 1,
                                                .immediate_size = first_operand_index,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                            .immediate = { .value = first_operand_value },
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else
                                {
                                    todo();
                                }
                            }
                            else if (first_operand == op_dx)
                            {
                                String first_operand_string = strlit("dx");

                                if (op_is_gpra(second_operand))
                                {
                                    let(second_operand_index, op_gpra_get_index(second_operand));
                                    let(second_operand_string, op_gpra_to_string(second_operand));

                                    TestInstruction instruction = {
                                        .encoding = {
                                            .invariant = {
                                                .rex_w = encoding->rex_w,
                                            },
                                            .legacy_prefixes = batch->legacy_prefixes | ((encoding->operand_size_override || second_operand_index == 1) << LEGACY_PREFIX_66),
                                            .opcode = encoding->opcode,
                                        },
                                        .text = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string),
                                    };

                                    test_instruction(&setup, &instruction);
                                }
                                else
                                {
                                    todo();
                                }
                            }
                            else
                            {
                                todo();
                            }
                        } break;
                    case 3:
                        {
                            OperandId third_operand = encoding->operands.values[2];
                            if (op_is_gpr_no_gpra(first_operand))
                            {
                                u8 first_operand_index = op_gpr_get_index(first_operand);
                                GPR_x86_64 first_operand_register_count = (unlikely(first_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;

                                u8 first_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                String first_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];
                                u8 first_is_rm = op_is_rm(first_operand);

                                if (first_is_rm)
                                {
                                    for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                    {
                                        String first_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                        for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                        {
                                            first_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(first_rm_buffer[gpr][displacement_index]), first_operand_rm_name, displacement_strings[displacement_index], first_operand_index);
                                        }
                                    }
                                }

                                if (op_is_gpr_no_gpra(second_operand))
                                {
                                    u8 second_operand_index = op_gpr_get_index(second_operand);
                                    GPR_x86_64 second_operand_register_count = (unlikely(second_operand_index == 0)) ? (X86_64_GPR_COUNT / 2) : X86_64_GPR_COUNT;
                                    u8 second_is_rm = op_is_rm(second_operand);
                                    u8 second_rm_buffer[X86_64_GPR_COUNT][array_length(displacements)][32];
                                    String second_rm_strings[X86_64_GPR_COUNT][array_length(displacements)];

                                    if (second_is_rm)
                                    {
                                        for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                        {
                                            String second_operand_rm_name = gpr_to_string(gpr, 3, 0);

                                            for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                            {
                                                second_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(second_rm_buffer[gpr][displacement_index]), second_operand_rm_name, displacement_strings[displacement_index], second_operand_index);
                                            }
                                        }
                                    }

                                    if (op_is_imm(third_operand))
                                    {
                                        u8 third_operand_index = op_imm_get_index(third_operand);
                                        String third_operand_string = sample_immediate_strings(third_operand_index);
                                        u64 third_operand_value = sample_immediate_values(third_operand_index);

                                        for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                        {
                                            String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                            for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                            {
                                                String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);
                                                
                                                TestInstruction instruction = {
                                                    .encoding = {
                                                        .invariant = {
                                                            .rex_w = encoding->rex_w || first_operand_index == 3,
                                                            .is_rm_register = 1,
                                                            .is_reg_register = 1,
                                                            .is_immediate = 1,
                                                            .immediate_size = third_operand_index,
                                                        },
                                                        .rm_register = first_is_rm ? first_gpr : second_gpr,
                                                        .reg_register = first_is_rm ? second_gpr : first_gpr,
                                                        .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                        .immediate = { .value = third_operand_value, },
                                                        .opcode = encoding->opcode,
                                                    },
                                                    .text = format_instruction3(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string, third_operand_string),
                                                };
                                                
                                                test_instruction(&setup, &instruction);
                                            }
                                        }

                                        if (first_is_rm)
                                        {
                                            for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                            {
                                                for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                                {
                                                    // String first_operand_string = first_rm_strings[first_gpr][displacement_index];

                                                    for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                                    {
                                                        // String second_operand_string = gpr_to_string(second_gpr, second_operand_index, gpr_is_extended(first_gpr));

                                                        todo();
                                                    }
                                                }
                                            }
                                        }

                                        if (second_is_rm)
                                        {
                                            for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                            {
                                                for (GPR_x86_64 second_gpr = 0; second_gpr < X86_64_GPR_COUNT; second_gpr += 1)
                                                {
                                                    String first_operand_string = gpr_to_string(first_gpr, first_operand_index, gpr_is_extended(second_gpr));

                                                    for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                                    {
                                                        String second_operand_string = second_rm_strings[second_gpr][displacement_index];
                                                        TestInstruction instruction = {
                                                            .encoding = {
                                                                .invariant = {
                                                                    .rex_w = encoding->rex_w || first_operand_index == 3,
                                                                    .is_rm_register = 1,
                                                                    .is_reg_register = 1,
                                                                    .is_immediate = 1,
                                                                    .immediate_size = third_operand_index,
                                                                    .is_displacement = 1,
                                                                    .displacement_size = displacement_index == 2,
                                                                },
                                                                .rm_register = first_is_rm ? first_gpr : second_gpr,
                                                                .reg_register = first_is_rm ? second_gpr : first_gpr,
                                                                .legacy_prefixes = batch->legacy_prefixes | ((first_operand_index == 1 || second_operand_index == 1 || encoding->operand_size_override) << LEGACY_PREFIX_66),
                                                                .immediate = { .value = third_operand_value, },
                                                                .displacement = { .value = displacements[displacement_index] },
                                                                .opcode = encoding->opcode,
                                                            },
                                                            .text = format_instruction3(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string, third_operand_string),
                                                        };
                                                        
                                                        test_instruction(&setup, &instruction);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        todo();
                                    }
                                }
                            }
                            else
                            {
                                todo();
                            }
                        } break;
                    case 4:
                        {
                            todo();
                        } break;
                }
            }

            u64 failure_count = 0;
            static_assert(array_length(setup.counters) == TEST_MODE_COUNT);
            print_string(strlit("\n"));
            for (TestMode test_mode = 0; test_mode < TEST_MODE_COUNT; test_mode += 1)
            {
                String test_mode_string = test_mode_to_string(test_mode);
                TestCounter test_counter = setup.counters[test_mode];
                failure_count += test_counter.failure;
                if (test_counter.failure)
                {
                    print("[{s}] {s}... [FAILED] {u64}/{u64} failures\n", test_mode_string, encoding_string, test_counter.failure, test_counter.total);
                }
                else
                {
                    print("[{s}] [OK] ({u64}/{u64})\n", test_mode_string, test_counter.total, test_counter.total);
                }
            }

            print_string(strlit("\n"));
            print_string(encoding_separator_string);
            print_string(strlit("\n"));
            
            if (failure_count)
            {
                failed_execution();
            }
        }
    }

    return result;
}

#define encode_instruction(_opcode, _operands)\
    do{\
        Encoding encoding = {\
            .opcode = _opcode,\
            .operands = _operands,\
        };\
        *vb_add(&builder->encodings, 1) = encoding;\
    } while (0)

#define ops(...) ((Operands){ .values = { __VA_ARGS__ }, .count = array_length(((OperandId[]){ __VA_ARGS__ })), })
#define ops_implicit_operands(...) ((Operands){ .values = { __VA_ARGS__ }, .count = array_length(((OperandId[]){ __VA_ARGS__ })), .implicit_operands = 1 })
#define extension_and_opcode(_opcode_extension, ...) ((Opcode) { .length = array_length(((u8[]){__VA_ARGS__})), .bytes = { __VA_ARGS__ }, _opcode_extension })
#define opcode3(y, x, ...) ((Opcode) { .prefix_0f = 1, .bytes = { (x), (y) }, __VA_ARGS__ })
#define opcode2(b, ...) ((Opcode) { .prefix_0f = 1, .bytes = { (b) }, __VA_ARGS__ })
#define opcode1(b, ...) ((Opcode) { .bytes = { (b) }, __VA_ARGS__ })

#define imm8_l  0x10
#define imm16_l 0x1000
#define imm32_l 0x10000000
#define imm64_l 0x1000000000000000

#define imm8_s  "0x10"
#define imm16_s "0x1000"
#define imm32_s "0x10000000"
#define imm64_s "0x1000000000000000"

#define imm8_a  0x10,
#define imm16_a 0x00, 0x10,
#define imm32_a 0x00, 0x00, 0x00, 0x10,
#define imm64_a 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,

STRUCT(TestBuilder)
{
    VirtualBuffer(Batch) batches;
    VirtualBuffer(Encoding) encodings;
};

STRUCT(ArithmeticOptions)
{
    u8 ra_imm;
    u8 rm_imm_extension;
    u8 rm_r;
    u8 r_rm;
};

fn Batch batch_start(TestBuilder* builder, Mnemonic_x86_64 mnemonic)
{
    Batch batch = {
        .mnemonic = mnemonic,
        .encoding_offset = builder->encodings.length,
    };

    return batch;
}

fn Batch batch_start_legacy_prefixes(TestBuilder* builder, Mnemonic_x86_64 mnemonic, u64 legacy_prefixes)
{
    Batch batch = {
        .mnemonic = mnemonic,
        .legacy_prefixes = legacy_prefixes,
        .encoding_offset = builder->encodings.length,
    };

    return batch;
}

fn void batch_end(TestBuilder* builder, Batch batch)
{
    batch.encoding_count = builder->encodings.length - batch.encoding_offset;
    *vb_add(&builder->batches, 1) = batch;
}

fn void encode_arithmetic_ex(TestBuilder* builder, Mnemonic_x86_64 mnemonic, ArithmeticOptions options)
{
    Batch batch = batch_start(builder, mnemonic);

    let(ra_imm, opcode1(options.ra_imm - 1));
    encode_instruction(ra_imm,         ops(op_al,  op_imm8));
    ra_imm.bytes[0] += 1;
    encode_instruction(ra_imm,  ops(op_ax, op_imm16));
    encode_instruction(ra_imm,  ops(op_eax, op_imm32));
    encode_instruction(ra_imm,  ops(op_rax, op_imm32));

    let(rm_imm, opcode1(0x80, .extension = options.rm_imm_extension));
    encode_instruction(rm_imm,        ops(op_rm8,  op_imm8));
    rm_imm.bytes[0] += 1;
    encode_instruction(rm_imm,  ops(op_rm16, op_imm16));
    encode_instruction(rm_imm,  ops(op_rm32, op_imm32));
    encode_instruction(rm_imm,  ops(op_rm64, op_imm32));

    let(rm_imm8, opcode1(0x83, .extension = options.rm_imm_extension));
    encode_instruction(rm_imm8, ops(op_rm16, op_imm8));
    encode_instruction(rm_imm8, ops(op_rm32, op_imm8));
    encode_instruction(rm_imm8, ops(op_rm64, op_imm8));

    let(rm_r, opcode1(options.rm_r - 1));
    encode_instruction(rm_r,           ops(op_rm8,  op_r8));
    rm_r.bytes[0] += 1;
    encode_instruction(rm_r,    ops(op_rm16, op_r16));
    encode_instruction(rm_r,    ops(op_rm32, op_r32));
    encode_instruction(rm_r,    ops(op_rm64, op_r64));

    let(r_rm, opcode1(options.r_rm - 1));
    encode_instruction(r_rm,           ops(op_r8,  op_rm8));
    r_rm.bytes[0] += 1;
    encode_instruction(r_rm,    ops(op_r16, op_rm16));
    encode_instruction(r_rm,    ops(op_r32, op_rm32));
    encode_instruction(r_rm,    ops(op_r64, op_rm64));

    batch_end(builder, batch);
}
#define encode_arithmetic(_mnemonic, ...) encode_arithmetic_ex(&builder, MNEMONIC_x86_64_ ## _mnemonic, (ArithmeticOptions) { __VA_ARGS__ })

fn void encode_unsigned_add_flag(TestBuilder* builder, Mnemonic_x86_64 mnemonic)
{
    let(prefix_66, mnemonic == MNEMONIC_x86_64_adcx);
    let(prefix_f3, mnemonic == MNEMONIC_x86_64_adox);
    let(legacy_prefixes, (prefix_66 << LEGACY_PREFIX_66) | (prefix_f3 << LEGACY_PREFIX_F3));

    Batch batch = batch_start_legacy_prefixes(builder, mnemonic, legacy_prefixes);

    let(opcode, opcode3(0x38, 0xf6));
    encode_instruction(opcode, ops(op_r32, op_rm32));
    encode_instruction(opcode, ops(op_r64, op_rm64));

    batch_end(builder, batch);
}

typedef enum BitScanKind
{
    BIT_SCAN_FORWARD = 0,
    BIT_SCAN_REVERSE = 1,
} BitScanKind;

fn void encode_bit_scan(TestBuilder* builder, BitScanKind bit_scan_kind)
{
    let(mnemonic, MNEMONIC_x86_64_bsf + bit_scan_kind);
    let(opcode_byte, 0xbc | bit_scan_kind);
    Batch batch = batch_start(builder, mnemonic);

    let(opcode, opcode2(opcode_byte));
    encode_instruction(opcode, ops(op_r16, op_rm16));
    encode_instruction(opcode, ops(op_r32, op_rm32));
    encode_instruction(opcode, ops(op_r64, op_rm64));

    batch_end(builder, batch);
}

fn void encode_bswap(TestBuilder* builder)
{
    let(mnemonic, MNEMONIC_x86_64_bswap);
    Batch batch = batch_start(builder, mnemonic);

    let(opcode, opcode2(0xc8, .plus_register = 1));

    encode_instruction(opcode, ops(op_r32));
    encode_instruction(opcode, ops(op_r64));

    batch_end(builder, batch);
}

fn void encode_bit_test(TestBuilder* builder, Mnemonic_x86_64 mnemonic, u8 opcode_last, u8 opcode_extension)
{
    Batch batch = batch_start(builder, mnemonic);

    {
        let(opcode, opcode2(opcode_last));

        encode_instruction(opcode,    ops(op_rm16, op_r16));
        encode_instruction(opcode,    ops(op_rm32, op_r32));
        encode_instruction(opcode,    ops(op_rm64, op_r64));
    }

    {
        let(opcode, opcode2(0xba, .extension = opcode_extension));

        encode_instruction(opcode,    ops(op_rm16, op_imm8));
        encode_instruction(opcode,    ops(op_rm32, op_imm8));
        encode_instruction(opcode,    ops(op_rm64, op_imm8));
    }

    batch_end(builder, batch);
}

fn void encode_call(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_call);
    {
        let(opcode, opcode1(0xe8));
        encode_instruction(opcode, ops(op_rel32));
    }

    {
        let(opcode, opcode1(0xff, .extension = 2));
        encode_instruction(opcode, ops(op_rm64));
    }

    // TODO: Figure out memory offset

    batch_end(builder, batch);
}

fn void encode_convert(TestBuilder* builder)
{
    u8 base_opcode = 0x98;

    Mnemonic_x86_64 mnemonics[2][3] = {
        { MNEMONIC_x86_64_cbw, MNEMONIC_x86_64_cwde, MNEMONIC_x86_64_cdqe },
        { MNEMONIC_x86_64_cwd, MNEMONIC_x86_64_cdq, MNEMONIC_x86_64_cqo },
    };

    OperandId operands[] = { op_ax, op_eax, op_rax };

    for (u32 category = 0; category < array_length(mnemonics); category += 1)
    {
        for (u32 i = 0; i < array_length(mnemonics[0]); i += 1)
        {
            Batch batch = batch_start(builder, mnemonics[category][i]);
            let(implicit_operand, ops(operands[i]));
            implicit_operand.implicit_operands = 1;
            let(opcode, opcode1(base_opcode + category));
            encode_instruction(opcode, implicit_operand);
            batch_end(builder, batch);
        }
    }
}

fn void encode_no_operand_instruction(TestBuilder* builder, Mnemonic_x86_64 mnemonic, Opcode opcode, u64 legacy_prefixes)
{
    Batch batch = batch_start_legacy_prefixes(builder, mnemonic, legacy_prefixes);
    Operands operands = {};
    encode_instruction(opcode, operands);
    batch_end(builder, batch);
}

fn void encode_clflush(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_clflush);
    let(opcode, opcode2(0xae, .extension = 7));
    encode_instruction(opcode, ops(op_m8));
    batch_end(builder, batch);
}

fn void encode_clflushopt(TestBuilder* builder)
{
    Batch batch = batch_start_legacy_prefixes(builder, MNEMONIC_x86_64_clflushopt, 1 << LEGACY_PREFIX_66);
    let(opcode, opcode2(0xae, .extension = 7));
    encode_instruction(opcode, ops(op_m8));
    batch_end(builder, batch);
}

fn void encode_cmov_instructions(TestBuilder* builder)
{
    for (u8 cmov_index = 0; cmov_index < cmov_count; cmov_index += 1)
    {
        Mnemonic_x86_64 mnemonic = MNEMONIC_x86_64_cmova + cmov_index;
        Batch batch = batch_start(builder, mnemonic);
        let(opcode, opcode2(0x40 | cc_opcodes_low[cmov_index]));
        encode_instruction(opcode, ops(op_r16, op_rm16));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        encode_instruction(opcode, ops(op_r64, op_rm64));
        batch_end(builder, batch);
    }
}

fn void encode_cmps(TestBuilder* builder)
{
    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_cmpsb + i);
        Operands operands = {
            .values = { op_ds_rsi_m8 + i, op_es_rdi_m8 + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0xa7 - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_cmpxchg(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_cmpxchg);
    let(opcode, opcode2(0xb0));
    encode_instruction(opcode, ops(op_rm8, op_r8));

    opcode.bytes[0] += 1;

    encode_instruction(opcode, ops(op_rm16, op_r16));
    encode_instruction(opcode, ops(op_rm32, op_r32));
    encode_instruction(opcode, ops(op_rm64, op_r64));
    batch_end(builder, batch);
}

fn void encode_cmpxchg_bytes(TestBuilder* builder)
{
    let(opcode, opcode2(0xc7, .extension = 1));
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_cmpxchg8b);
        encode_instruction(opcode, ops(op_m64));
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_cmpxchg16b);
        encode_instruction(opcode, ops(op_m128));
        batch_end(builder, batch);
    }
}

fn void encode_crc32(TestBuilder* builder)
{
    Batch batch = batch_start_legacy_prefixes(builder, MNEMONIC_x86_64_crc32, 1 << LEGACY_PREFIX_F2);
    {
        let(opcode, opcode3(0x38, 0xf0));
        encode_instruction(opcode, ops(op_r32, op_rm8));
    }

    let(opcode, opcode3(0x38, 0xf1));
    Encoding encoding = {
        .opcode = opcode,
        .operands = ops(op_r32, op_rm16),
        .operand_size_override = 1,
    };
    *vb_add(&builder->encodings, 1) = encoding;

    {
        let(opcode, opcode3(0x38, 0xf1));
        encode_instruction(opcode, ops(op_r32, op_rm32));
    }
    {
        let(opcode, opcode3(0x38, 0xf0));
        encode_instruction(opcode, ops(op_r64, op_rm8));
    }
    {
        let(opcode, opcode3(0x38, 0xf1));
        encode_instruction(opcode, ops(op_r64, op_rm64));
        batch_end(builder, batch);
    }
}

typedef enum IncDec
{
    OP_INC = 0,
    OP_DEC = 1,
} IncDec;

fn void encode_dec_inc(TestBuilder* builder, IncDec inc_dec)
{
    Batch batch = batch_start(builder, inc_dec == OP_DEC ? MNEMONIC_x86_64_dec : MNEMONIC_x86_64_inc);
    let(opcode, opcode1(0xfe, .extension = inc_dec));
    encode_instruction(opcode, ops(op_rm8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16));
    encode_instruction(opcode, ops(op_rm32));
    encode_instruction(opcode, ops(op_rm64));
    batch_end(builder, batch);
}

typedef enum Signedness
{
    SIGNEDNESS_UNSIGNED = 0,
    SIGNEDNESS_SIGNED = 1,
} Signedness;

fn void encode_div(TestBuilder* builder, Signedness signedness)
{
    global_variable const Mnemonic_x86_64 div_mnemonics[] = { MNEMONIC_x86_64_div, MNEMONIC_x86_64_idiv };
    Batch batch = batch_start(builder, div_mnemonics[signedness]);
    u8 opcode_extension = 6 | signedness;
    let(opcode, opcode1(0xf6, .extension = opcode_extension));
    encode_instruction(opcode, ops(op_rm8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16));
    encode_instruction(opcode, ops(op_rm32));
    encode_instruction(opcode, ops(op_rm64));
    batch_end(builder, batch);
}

fn void encode_imul(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_imul);

    {
        let(opcode, opcode1(0xf6, .extension = 5));
        encode_instruction(opcode, ops(op_rm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16));
        encode_instruction(opcode, ops(op_rm32));
        encode_instruction(opcode, ops(op_rm64));
    }

    {
        let(opcode, opcode2(0xaf));
        encode_instruction(opcode, ops(op_r16, op_rm16));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        encode_instruction(opcode, ops(op_r64, op_rm64));
    }

    {
        let(opcode, opcode1(0x6b));
        encode_instruction(opcode, ops(op_r16, op_rm16, op_imm8));
        encode_instruction(opcode, ops(op_r32, op_rm32, op_imm8));
        encode_instruction(opcode, ops(op_r64, op_rm64, op_imm8));
    }

    {
        let(opcode, opcode1(0x69));
        encode_instruction(opcode, ops(op_r16, op_rm16, op_imm16));
        encode_instruction(opcode, ops(op_r32, op_rm32, op_imm32));
        encode_instruction(opcode, ops(op_r64, op_rm64, op_imm32));
    }

    batch_end(builder, batch);
}

fn void encode_in(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_in);

    {
        let(opcode, opcode1(0xe4));
        encode_instruction(opcode, ops(op_al, op_imm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_ax, op_imm8));
        encode_instruction(opcode, ops(op_eax, op_imm8));
    }

    {
        let(opcode, opcode1(0xec));
        encode_instruction(opcode, ops_implicit_operands(op_al, op_dx));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops_implicit_operands(op_ax, op_dx));
        encode_instruction(opcode, ops_implicit_operands(op_eax, op_dx));
    }

    batch_end(builder, batch);
}

fn void encode_ins(TestBuilder* builder)
{
    for (u8 i = 0; i < 3; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_insb + i);
        Operands operands = {
            .values = { op_es_rdi_m8 + i, op_dx },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0x6d - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_int(TestBuilder* builder)
{
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_int);
        let(opcode, opcode1(0xcd));
        encode_instruction(opcode, ops(op_imm8));
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_int3);
        Operands operands = {};
        let(opcode, opcode1(0xcc));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_invlpg(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_invlpg);
    let(opcode, opcode2(0x01, .extension = 7));
    encode_instruction(opcode, ops(op_m8));
    batch_end(builder, batch);
}

fn void encode_iret(TestBuilder* builder)
{
    Operands operands = {};
    let(opcode, opcode1(0xcf));
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_iret);
        Encoding encoding = {
            .opcode = opcode,
            .operands = operands,
            .operand_size_override = 1,
        };
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_iretd);
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_iretq);
        Encoding encoding = {
            .opcode = opcode,
            .operands = operands,
            .rex_w = 1,
        };
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }
}

fn void encode_jmp(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_jmp);

    {
        let(opcode, opcode1(0xeb));
        encode_instruction(opcode, ops(op_rel8));
    }
    {
        let(opcode, opcode1(0xe9));
        encode_instruction(opcode, ops(op_rel32));
    }

    {
        let(opcode, opcode1(0xff, .extension = 4));
        encode_instruction(opcode, ops(op_rm64));
    }

    // TODO: (m16,m32,m64):(16,32,64)
    
    batch_end(builder, batch);
}

fn void encode_jcc(TestBuilder* builder)
{
    for (u8 jcc_i = 0; jcc_i < jcc_count; jcc_i += 1)
    {
        Mnemonic_x86_64 mnemonic = MNEMONIC_x86_64_ja + jcc_i;
        Batch batch = batch_start(builder, mnemonic);
        {
            let(opcode, opcode1(0x70 | cc_opcodes_low[jcc_i]));
            encode_instruction(opcode, ops(op_rel8));
        }
        {
            let(opcode, opcode2(0x80 | cc_opcodes_low[jcc_i]));
            encode_instruction(opcode, ops(op_rel32));
        }
        batch_end(builder, batch);
    }

    Mnemonic_x86_64 mnemonic = MNEMONIC_x86_64_jrcxz;
    Batch batch = batch_start(builder, mnemonic);
    let(opcode, opcode1(0xe3));
    encode_instruction(opcode, ops(op_rel8));
    batch_end(builder, batch);
}

fn void encode_lea(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_lea);
    let(opcode, opcode1(0x8d));
    encode_instruction(opcode, ops(op_r16, op_m16));
    encode_instruction(opcode, ops(op_r32, op_m32));
    encode_instruction(opcode, ops(op_r64, op_m64));
    batch_end(builder, batch);
}

fn void encode_lods(TestBuilder* builder)
{
    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_lodsb + i);
        Operands operands = {
            .values = { op_al + i, op_ds_rsi_m8 + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0xad - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_loop(TestBuilder* builder)
{
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_loop);
        let(opcode, opcode1(0xe2));
        encode_instruction(opcode, ops(op_rel8));
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_loope);
        let(opcode, opcode1(0xe1));
        encode_instruction(opcode, ops(op_rel8));
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_loopne);
        let(opcode, opcode1(0xe0));
        encode_instruction(opcode, ops(op_rel8));
        batch_end(builder, batch);
    }
}

fn void encode_mov(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_mov);

    {
        let(opcode, opcode1(0x88));
        encode_instruction(opcode, ops(op_rm8,  op_r8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16, op_r16));
        encode_instruction(opcode, ops(op_rm32, op_r32));
        encode_instruction(opcode, ops(op_rm64, op_r64));
    }

    {
        let(opcode, opcode1(0x8a));
        encode_instruction(opcode, ops(op_r8,  op_rm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_r16, op_rm16));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        encode_instruction(opcode, ops(op_r64, op_rm64));
    }

    // TODO: segments

    {
        let(opcode, opcode1(0xb0, .plus_register = 1));
        encode_instruction(opcode, ops(op_r8,  op_imm8));
        opcode.bytes[0] |= 8;
        encode_instruction(opcode, ops(op_r16, op_imm16));
        encode_instruction(opcode, ops(op_r32, op_imm32));
        encode_instruction(opcode, ops(op_r64, op_imm64));
    }


    {
        let(opcode, opcode1(0xc6, .extension = 0));
        encode_instruction(opcode, ops(op_rm8,  op_imm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16, op_imm16));
        encode_instruction(opcode, ops(op_rm32, op_imm32));
        encode_instruction(opcode, ops(op_rm64, op_imm32));
    }

    batch_end(builder, batch);
}

fn void encode_movs(TestBuilder* builder)
{
    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_movsb + i);
        Operands operands = {
            .values = { op_es_rdi_m8 + i, op_ds_rsi_m8 + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0xa5 - (i == 0)));
        Encoding encoding = {
            .operands = operands,
            .opcode = opcode,
            .rex_w = i == 3,
        };
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }
}

fn void encode_movsx(TestBuilder* builder)
{
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_movsx);
        {
            let(opcode, opcode2(0xbe));
            encode_instruction(opcode, ops(op_r16, op_rm8));
            encode_instruction(opcode, ops(op_r32, op_rm8));
            encode_instruction(opcode, ops(op_r64, op_rm8));
            opcode.bytes[0] += 1;
            encode_instruction(opcode, ops(op_r32, op_rm16));
            encode_instruction(opcode, ops(op_r64, op_rm16));
        }
        batch_end(builder, batch);
    }
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_movsxd);
        let(opcode, opcode1(0x63));
        encode_instruction(opcode, ops(op_r64, op_rm32));
        batch_end(builder, batch);
    }
}

fn void encode_movzx(TestBuilder* builder)
{
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_movzx);
        let(opcode, opcode2(0xb6));
        encode_instruction(opcode, ops(op_r16, op_rm8));
        encode_instruction(opcode, ops(op_r32, op_rm8));
        encode_instruction(opcode, ops(op_r64, op_rm8));

        opcode.bytes[0] += 1;

        encode_instruction(opcode, ops(op_r32, op_rm16));
        encode_instruction(opcode, ops(op_r64, op_rm16));
        batch_end(builder, batch);
    }
}

fn void encode_mul(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_mul);
    let(opcode, opcode1(0xf6, .extension = 4));
    encode_instruction(opcode, ops(op_rm8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16));
    encode_instruction(opcode, ops(op_rm32));
    encode_instruction(opcode, ops(op_rm64));
    batch_end(builder, batch);
}

fn void encode_neg(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_neg);
    let(opcode, opcode1(0xf6, .extension = 3));
    encode_instruction(opcode, ops(op_rm8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16));
    encode_instruction(opcode, ops(op_rm32));
    encode_instruction(opcode, ops(op_rm64));
    batch_end(builder, batch);
}

fn void encode_nop(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_nop);
    let(opcode, opcode1(0x90));
    encode_instruction(opcode, (Operands){});
    {
        let(opcode, opcode2(0x1f, .extension = 0));
        encode_instruction(opcode, ops(op_rm16));
        encode_instruction(opcode, ops(op_rm32));
    }
    batch_end(builder, batch);
}

fn void encode_not(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_not);
    let(opcode, opcode1(0xf6, .extension = 2));
    encode_instruction(opcode, ops(op_rm8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16));
    encode_instruction(opcode, ops(op_rm32));
    encode_instruction(opcode, ops(op_rm64));
    batch_end(builder, batch);
}

fn void encode_out(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_out);

    {
        let(opcode, opcode1(0xe6));
        encode_instruction(opcode, ops(op_imm8, op_al));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_imm8, op_ax));
        encode_instruction(opcode, ops(op_imm8, op_eax));
    }

    {
        let(opcode, opcode1(0xee));
        encode_instruction(opcode, ops_implicit_operands(op_dx, op_al));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops_implicit_operands(op_dx, op_ax));
        encode_instruction(opcode, ops_implicit_operands(op_dx, op_eax));
    }

    batch_end(builder, batch);
}

fn void encode_outs(TestBuilder* builder)
{
    for (u8 i = 0; i < 3; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_outsb + i);
        Operands operands = {
            .values = { op_dx, op_ds_rsi_m8 + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0x6f - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_pop(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_pop);

    {
        let(opcode, opcode1(0x8f, .extension = 0));
        encode_instruction(opcode, ops(op_rm16));
        encode_instruction(opcode, ops(op_rm64));
    }

    let(opcode, opcode1(0x58, .plus_register = 1));
    encode_instruction(opcode, ops(op_r16));
    encode_instruction(opcode, ops(op_r64));

    batch_end(builder, batch);
}

fn void encode_popcnt(TestBuilder* builder)
{
    Batch batch = batch_start_legacy_prefixes(builder, MNEMONIC_x86_64_popcnt, 1 << LEGACY_PREFIX_F3);

    let(opcode, opcode2(0xb8));
    encode_instruction(opcode, ops(op_r16, op_rm16));
    encode_instruction(opcode, ops(op_r32, op_rm32));
    encode_instruction(opcode, ops(op_r64, op_rm64));

    batch_end(builder, batch);
}

fn void encode_popf(TestBuilder* builder)
{
    Encoding encoding = {
        .opcode = opcode1(0x9d),
        .operand_size_override = 1,
    };

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_popf);
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_popfq);
        encoding.operand_size_override = 0;
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }
}

fn void encode_prefetch(TestBuilder* builder)
{
    for (u8 i = 0; i < 3; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_prefetcht0 + i);
        let(opcode, opcode2(0x18, .extension = i + 1));
        encode_instruction(opcode, ops(op_m8));
        batch_end(builder, batch);
    }

    Batch batch = batch_start(builder, MNEMONIC_x86_64_prefetchnta);
    let(opcode, opcode2(0x18, .extension = 0));
    encode_instruction(opcode, ops(op_m8));
    batch_end(builder, batch);
}

fn void encode_push(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_push);

    {
        let(opcode, opcode1(0xff, .extension = 6));
        encode_instruction(opcode, ops(op_rm16));
        encode_instruction(opcode, ops(op_rm64));
    }

    {
        let(opcode, opcode1(0x50, .plus_register = 1));
        encode_instruction(opcode, ops(op_r16));
        encode_instruction(opcode, ops(op_r64));
    }

    let(opcode, opcode1(0x6a));
    encode_instruction(opcode, ops(op_imm8));
    opcode.bytes[0] -= 2;
    encode_instruction(opcode, ops(op_imm16));
    encode_instruction(opcode, ops(op_imm32));

    batch_end(builder, batch);
}

fn void encode_pushf(TestBuilder* builder)
{
    Encoding encoding = {
        .opcode = {
            .bytes = { 0x9c },
        },
        .operand_size_override = 1,
    };

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_pushf);
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_pushfq);
        encoding.operand_size_override = 0;
        *vb_add(&builder->encodings, 1) = encoding;
        batch_end(builder, batch);
    }
}

fn void encode_rotate(TestBuilder* builder)
{
    Mnemonic_x86_64 mnemonics[] = { MNEMONIC_x86_64_rol, MNEMONIC_x86_64_ror, MNEMONIC_x86_64_rcl, MNEMONIC_x86_64_rcr };
    for (u8 extension = 0; extension < 4; extension += 1)
    {
        Batch batch = batch_start(builder, mnemonics[extension]);

        Opcode opcodes[] = {
            opcode1(0xd0, .extension = extension),
            opcode1(0xd2, .extension = extension),
            opcode1(0xc0, .extension = extension),
        };
        encode_instruction(opcodes[0], ops(op_rm8, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm8, op_cl));
        encode_instruction(opcodes[2], ops(op_rm8, op_imm8));

        for (u64 i = 0; i < array_length(opcodes); i += 1)
        {
            opcodes[i].bytes[0] += 1;
        }

        encode_instruction(opcodes[0], ops(op_rm16, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm16, op_cl));
        encode_instruction(opcodes[2], ops(op_rm16, op_imm8));

        encode_instruction(opcodes[0], ops(op_rm32, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm32, op_cl));
        encode_instruction(opcodes[2], ops(op_rm32, op_imm8));

        encode_instruction(opcodes[0], ops(op_rm64, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm64, op_cl));
        encode_instruction(opcodes[2], ops(op_rm64, op_imm8));

        batch_end(builder, batch);
    }
}

typedef enum ReturnType
{
    RETURN_TYPE_NEAR,
    RETURN_TYPE_FAR,
} ReturnType;

fn void encode_ret(TestBuilder* builder, ReturnType return_type)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_ret + (return_type == RETURN_TYPE_FAR));

    let(opcode_flag, (u8)safe_flag(0b1000, return_type == RETURN_TYPE_FAR));

    {
        let(opcode, opcode1(0xc3 | opcode_flag));
        Operands ops = {};
        encode_instruction(opcode, ops);
    }
    {
        let(opcode, opcode1(0xc2 | opcode_flag));
        encode_instruction(opcode, ops(op_imm16));
    }

    batch_end(builder, batch);
}

fn void encode_shift(TestBuilder* builder)
{
    Mnemonic_x86_64 mnemonics[] = { MNEMONIC_x86_64_sal, MNEMONIC_x86_64_sar, MNEMONIC_x86_64_shl, MNEMONIC_x86_64_shr };
    u8 opcode_extensions[] = { 4, 7, 4, 5 };

    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, mnemonics[i]);
        u8 extension = opcode_extensions[i];

        Opcode opcodes[] = {
            opcode1(0xd0, .extension = extension),
            opcode1(0xd2, .extension = extension),
            opcode1(0xc0, .extension = extension),
        };

        encode_instruction(opcodes[0], ops(op_rm8, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm8, op_cl));
        encode_instruction(opcodes[2], ops(op_rm8, op_imm8));

        for (u64 i = 0; i < array_length(opcodes); i += 1)
        {
            opcodes[i].bytes[0] += 1;
        }

        encode_instruction(opcodes[0], ops(op_rm16, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm16, op_cl));
        encode_instruction(opcodes[2], ops(op_rm16, op_imm8));

        encode_instruction(opcodes[0], ops(op_rm32, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm32, op_cl));
        encode_instruction(opcodes[2], ops(op_rm32, op_imm8));

        encode_instruction(opcodes[0], ops(op_rm64, op_one_literal));
        encode_instruction(opcodes[1], ops(op_rm64, op_cl));
        encode_instruction(opcodes[2], ops(op_rm64, op_imm8));

        batch_end(builder, batch);
    }
}

fn void encode_scas(TestBuilder* builder)
{
    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_scasb + i);
        Operands operands = {
            .values = { op_al + i, op_es_rdi_m8 + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0xaf - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_setcc(TestBuilder* builder)
{
    for (u8 i = 0; i < setcc_count; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_seta + i);
        let(opcode, opcode2(0x90 | cc_opcodes_low[i]));
        encode_instruction(opcode, ops(op_rm8));
        batch_end(builder, batch);
    }
}

fn void encode_stos(TestBuilder* builder)
{
    for (u8 i = 0; i < 4; i += 1)
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_stosb + i);
        Operands operands = {
            .values = { op_es_rdi_m8 + i, op_al + i },
            .count = 2,
            .implicit_operands = 1,
        };
        let(opcode, opcode1(0xab - (i == 0)));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_test(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_test);

    {
        let(opcode, opcode1(0xa8));
        encode_instruction(opcode, ops(op_al, op_imm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_ax, op_imm16));
        encode_instruction(opcode, ops(op_eax, op_imm32));
        encode_instruction(opcode, ops(op_rax, op_imm32));
    }

    {
        let(opcode, opcode1(0xf6, .extension = 0));
        encode_instruction(opcode, ops(op_rm8, op_imm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16, op_imm16));
        encode_instruction(opcode, ops(op_rm32, op_imm32));
        encode_instruction(opcode, ops(op_rm64, op_imm32));
    }

    {
        let(opcode, opcode1(0x84));
        encode_instruction(opcode, ops(op_rm8, op_r8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16, op_r16));
        encode_instruction(opcode, ops(op_rm32, op_r32));
        encode_instruction(opcode, ops(op_rm64, op_r64));
    }

    batch_end(builder, batch);
}

fn void encode_ud(TestBuilder* builder)
{
    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_ud0);
        let(opcode, opcode2(0xff));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        batch_end(builder, batch);
    }

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_ud1);
        let(opcode, opcode2(0xb9));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        batch_end(builder, batch);
    }

    {
        Batch batch = batch_start(builder, MNEMONIC_x86_64_ud2);
        Operands operands = {};
        let(opcode, opcode2(0x0b));
        encode_instruction(opcode, operands);
        batch_end(builder, batch);
    }
}

fn void encode_xadd(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_xadd);
    let(opcode, opcode2(0xc0));
    encode_instruction(opcode, ops(op_rm8, op_r8));
    opcode.bytes[0] += 1;
    encode_instruction(opcode, ops(op_rm16, op_r16));
    encode_instruction(opcode, ops(op_rm32, op_r32));
    encode_instruction(opcode, ops(op_rm64, op_r64));

    batch_end(builder, batch);
}

fn void encode_xchg(TestBuilder* builder)
{
    Batch batch = batch_start(builder, MNEMONIC_x86_64_xchg);

    let(opcode, opcode1(0x90, .plus_register = 1));

    encode_instruction(opcode, ops(op_ax, op_r16));
    encode_instruction(opcode, ops(op_r16, op_ax));
    encode_instruction(opcode, ops(op_eax, op_r32));
    encode_instruction(opcode, ops(op_r32, op_eax));
    encode_instruction(opcode, ops(op_rax, op_r64));
    encode_instruction(opcode, ops(op_r64, op_rax));

    {
        let(opcode, opcode1(0x86));
        encode_instruction(opcode, ops(op_r8,  op_rm8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_r16, op_rm16));
        encode_instruction(opcode, ops(op_r32, op_rm32));
        encode_instruction(opcode, ops(op_r64, op_rm64));

        opcode.bytes[0] -= 1;
        encode_instruction(opcode, ops(op_rm8,  op_r8));
        opcode.bytes[0] += 1;
        encode_instruction(opcode, ops(op_rm16, op_r16));
        encode_instruction(opcode, ops(op_rm32, op_r32));
        encode_instruction(opcode, ops(op_rm64, op_r64));
    }

    batch_end(builder, batch);
}

fn TestDataset construct_test_cases()
{
    TestBuilder builder = {};

    encode_arithmetic(adc, .ra_imm = 0x15, .rm_imm_extension = 2, .rm_r = 0x11, .r_rm = 0x13);
    encode_unsigned_add_flag(&builder, MNEMONIC_x86_64_adcx);
    encode_arithmetic(add, .ra_imm = 0x05, .rm_imm_extension = 0, .rm_r = 0x01, .r_rm = 0x03);
    encode_unsigned_add_flag(&builder, MNEMONIC_x86_64_adox);
    encode_arithmetic(and, .ra_imm = 0x25, .rm_imm_extension = 4, .rm_r = 0x21, .r_rm = 0x23);
    encode_bit_scan(&builder, BIT_SCAN_FORWARD); 
    encode_bit_scan(&builder, BIT_SCAN_REVERSE); 
    encode_bswap(&builder);
    encode_bit_test(&builder, MNEMONIC_x86_64_bt, 0xa3, 0x04);
    encode_bit_test(&builder, MNEMONIC_x86_64_btc, 0xbb, 0x07);
    encode_bit_test(&builder, MNEMONIC_x86_64_btr, 0xb3, 0x06);
    encode_bit_test(&builder, MNEMONIC_x86_64_bts, 0xab, 0x05);
    encode_call(&builder);
    encode_convert(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_clc, opcode1(0xf8), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_cld, opcode1(0xfc), 0);
    encode_clflush(&builder);
    encode_clflushopt(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_cli, opcode1(0xfa), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_clts, opcode2(0x06), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_cmc, opcode1(0xf5), 0);
    encode_cmov_instructions(&builder);
    encode_arithmetic(cmp, .ra_imm = 0x3d, .rm_imm_extension = 7, .rm_r = 0x39, .r_rm = 0x3b);
    encode_cmps(&builder);
    encode_cmpxchg(&builder);
    encode_cmpxchg_bytes(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_cpuid, opcode2(0xa2), 0);
    encode_crc32(&builder);
    encode_dec_inc(&builder, OP_DEC);
    encode_div(&builder, SIGNEDNESS_UNSIGNED);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_hlt, opcode1(0xf4), 0);
    encode_div(&builder, SIGNEDNESS_SIGNED);
    encode_imul(&builder);
    encode_in(&builder);
    encode_dec_inc(&builder, OP_INC);
    encode_ins(&builder);
    encode_int(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_invd, opcode2(0x08), 0);
    encode_invlpg(&builder);
    encode_iret(&builder);
    encode_jmp(&builder);
    encode_jcc(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_lahf, opcode1(0x9f), 0);
    encode_lea(&builder);
    encode_lods(&builder);
    encode_loop(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_monitor, opcode3(0x01, 0xc8), 0);
    encode_mov(&builder);
    encode_movs(&builder);
    encode_movsx(&builder);
    encode_movzx(&builder);
    encode_mul(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_mwait, opcode3(0x01, 0xc9), 0);
    encode_neg(&builder);
    encode_nop(&builder);
    encode_not(&builder);
    encode_arithmetic(or, .ra_imm = 0x0d, .rm_imm_extension = 1, .rm_r = 0x09, .r_rm = 0x0b);
    encode_out(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_pause, opcode1(0x90), 1 << LEGACY_PREFIX_F3);
    encode_pop(&builder);
    encode_popcnt(&builder);
    encode_popf(&builder);
    encode_prefetch(&builder);
    encode_push(&builder);
    encode_pushf(&builder);
    encode_rotate(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_rdmsr, opcode2(0x32), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_rdpmc, opcode2(0x33), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_rdtsc, opcode2(0x31), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_rdtscp, opcode3(0x01, 0xf9), 0);
    encode_ret(&builder, RETURN_TYPE_NEAR);
    encode_ret(&builder, RETURN_TYPE_FAR);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_rsm, opcode2(0xaa), 0);
    encode_shift(&builder);
    encode_arithmetic(sbb, .ra_imm = 0x1d, .rm_imm_extension = 3, .rm_r = 0x19, .r_rm = 0x1b);
    encode_scas(&builder);
    encode_setcc(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_stc, opcode1(0xf9), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_std, opcode1(0xfd), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_sti, opcode1(0xfb), 0);
    encode_stos(&builder);
    encode_arithmetic(sub, .ra_imm = 0x2d, .rm_imm_extension = 5, .rm_r = 0x29, .r_rm = 0x2b);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_syscall,    opcode2(0x05), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_sysenter,   opcode2(0x34), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_sysexit,    opcode2(0x35), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_sysret,     opcode2(0x07), 0);
    encode_test(&builder);
    encode_ud(&builder);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_wbinvd, opcode2(0x09), 0);
    encode_no_operand_instruction(&builder, MNEMONIC_x86_64_wrmsr, opcode2(0x30), 0);
    encode_xadd(&builder);
    encode_xchg(&builder);
    encode_arithmetic(xor, .ra_imm = 0x35, .rm_imm_extension = 6, .rm_r = 0x31, .r_rm = 0x33);

    TestDataset result = {
        .batches = builder.batches.pointer,
        .batch_count = builder.batches.length,
        .encodings = builder.encodings.pointer,
        .encoding_count = builder.encodings.length,
    };

    return result;
}

fn u8 is_asm_space(u8 ch)
{
    return ch == '\t' || ch == ' ' || ch == '\n' || ch == '\r';
}

fn u64 find_next_space(String string)
{
    return MIN(MIN(string_first_ch(string, ' '), string_first_ch(string, '\t')), MIN(string_first_ch(string, '\n'), string_first_ch(string, '\r')));
}

fn void n_word_mask(CStringSlice words, u8* mask, u8 length)
{
    for (u8 i = 0; i < length; i += 1)
    {
        mask[i] = 0xff;
    }

    for (u8 byte = 0; byte < length; byte += 1)
    {
        for (u8 bit = 0; bit < 8; bit += 1)
        {
            u8 old = mask[byte];
            mask[byte] &= ~(u8)(1 << bit);

            u8 map[16*16][16] = {};
            u32 map_item_count = 0;
            u8 candidate[16] = {};

            for (u64 word_index = 0; word_index < words.length; word_index += 1)
            {
                char* word = words.pointer[word_index];
                for (u8 mask_index = 0; mask_index < length; mask_index += 1)
                {
                    candidate[mask_index] = word[mask_index] & mask[mask_index];
                }

                u8 map_index;
                for (map_index = 0; map_index < map_item_count; map_index += 1)
                {
                    if (memcmp(map[map_index], candidate, length) == 0)
                    {
                        break;
                    }
                }

                if (map_index != map_item_count)
                {
                    mask[byte] = old;
                    break;
                }

                memcpy(map[map_item_count], candidate, length);
                map_item_count += 1;
            }
        }
    }
}

typedef enum OperandKind : u8
{
    OPERAND_KIND_REGISTER,
    OPERAND_KIND_IMMEDIATE,
    OPERAND_KIND_INDIRECT,
} OperandKind;
STRUCT(OperandWork)
{
    OperandKind kind:2;
    u8 size:6;
};
static_assert(sizeof(OperandWork) == 1);

STRUCT(OperandIndirect)
{
    x86_64_Register base;
    s8 displacement8;
    s32 displacement32;
};

STRUCT(MnemonicEncoding)
{
    OperandId operands[4];
};

String assemble(String text)
{
    u8* buffer = os_reserve(0, align_forward_u64(text.length + 0x4000, 0x1000), (OSReserveProtectionFlags) { .read = 1, .write = 1 }, (OSReserveMapFlags) { .priv = 1, .anon = 1, .populate = 1 });
    u8* source = text.pointer;

    u8* top = source + text.length;
    u8* destination = buffer;

    while (source < top)
    {
        u64 instruction_count = 0;
        u8* base = source;
        u32 mnemonic_offsets[64];
        u32 mnemonic_lengths[64];
#define operand_buffer_count (64*4)
        u32 operand_offsets[operand_buffer_count];
        u8 operand_lengths[operand_buffer_count];
        u32 instruction_operand_offsets[64];
        u8 instruction_operand_counters[64];
        OperandWork operand_works[operand_buffer_count];
        u64 immediates[operand_buffer_count];
        x86_64_Register registers[operand_buffer_count];
        OperandIndirect indirects[operand_buffer_count];
        u32 operand_count = 0;

        u64 operand_length_error_mask = 0;
        u64 operand_count_error_mask = 0;

        while (instruction_count < 64)
        {
            while (is_asm_space(*source))
            {
                source += 1;
            }

            if (source == top)
            {
                break;
            }

            let(instruction_length, MIN(string_first_ch((String) { .pointer = source, .length = top - source }, '\n'), (u64)(top - source)));

            String instruction = { .pointer = source, .length = instruction_length };
            let(instruction_top, source + instruction_length + (*(source + instruction_length) == '\n'));

            u32 mnemonic_offset = source - base;
            u32 mnemonic_length = find_next_space(instruction);
            mnemonic_offsets[instruction_count] = mnemonic_offset;
            mnemonic_lengths[instruction_count] = mnemonic_length;

            source += mnemonic_length;

            u32 instruction_operand_offset = operand_count;
            instruction_operand_offsets[instruction_count] = instruction_operand_offset;

            while (1)
            {
                while (is_asm_space(*source))
                {
                    source += 1;
                }

                if (source == instruction_top)
                {
                    break;
                }

                String whats_left = { .pointer = source, .length = instruction_top - source };
                u32 operand_offset = source - base;
                u32 operand_length = MIN(whats_left.length, MIN(string_first_ch(whats_left, ','), string_first_ch(whats_left, '\n')));
                operand_offsets[operand_count] = operand_offset;
                operand_lengths[operand_count] = operand_length;
                operand_length_error_mask |= operand_length >= UINT8_MAX;
                source += operand_length;
                source += *source == ',';

                operand_count += 1;
            }

            let_cast(u8, instruction_operand_count, operand_count - instruction_operand_offset);
            operand_count_error_mask |= instruction_operand_count > 4;
            instruction_operand_counters[instruction_count] = instruction_operand_count;

            instruction_count += 1;
        }

        if (unlikely((operand_length_error_mask | operand_count_error_mask | (source == top)) != 0))
        {
            if (source == top)
            {
                break;
            }

            todo();
        }

        let(lookup_result, pext_lookup_mnemonic_batch(base, mnemonic_offsets, mnemonic_lengths));

        __mmask32 lookup_error_m0 = _mm512_cmpeq_epi16_mask(lookup_result.v[0], _mm512_set1_epi16(0xffff));
        __mmask32 lookup_error_m1 = _mm512_cmpeq_epi16_mask(lookup_result.v[1], _mm512_set1_epi16(0xffff));
        __mmask32 lookup_error_mask = _kor_mask32(lookup_error_m0, lookup_error_m1);
        u32 lookup_error_mask_int = _cvtmask32_u32(lookup_error_mask);

        // Operand parsing
        // GPR
        // xmm{0-31}
        // ymm{0-31}
        // zmm{0-31}
        // indirect
        // immediate: decimal, hexadecimal, binary

        if (likely(operand_count != 0))
        {
            for (u32 operand_index = 0; operand_index < operand_count; operand_index += 1)
            {
                let(operand_string_pointer, base + operand_offsets[operand_index]);
                let(operand_string_length, operand_lengths[operand_index]);
                u8 first_ch = operand_string_pointer[0];
                if ((first_ch >= 'a') & (first_ch <= 'z'))
                {
                    let(value, pext_lookup_register_single(operand_string_pointer, operand_string_length));
                    if (value == 0xffff)
                    {
                        todo();
                    }

                    registers[operand_index] = value;
                    operand_works[operand_index].kind = OPERAND_KIND_REGISTER;
                }
                else if ((first_ch >= '0') & (first_ch <= '9'))
                {
                    switch (operand_string_pointer[1])
                    {
                        case 'x':
                            {
                                u8* it = &operand_string_pointer[2];

                                u8* hex_it = it;
                                while (is_hex_digit(*hex_it))
                                {
                                    hex_it += 1;
                                }

                                String operand_string = { .pointer = it, .length = hex_it - it };
                                u8 is_error;
                                u64 result = parse_hexadecimal(operand_string, &is_error);
                                if (is_error)
                                {
                                    todo();
                                }
                                immediates[operand_index] = result;

                                it = hex_it;
                            } break;
                        case 'b':
                            {
                                todo();
                            } break;
                        case 'o':
                            {
                                todo();
                            } break;
                        default: todo();
                    }

                    operand_works[operand_index].kind = OPERAND_KIND_IMMEDIATE;
                }
                else if (first_ch == '[')
                {
                    u8* end = &operand_string_pointer[operand_string_length - 1];

                    while (is_asm_space(*end))
                    {
                        end -= 1;
                    }

                    if (*end != ']')
                    {
                        todo();
                    }

                    u8* it = operand_string_pointer + 1;
                    s8 bias8 = 1;
                    s32 bias32 = 1;
                    s8 displacement8 = 0;
                    s32 displacement32 = 0;
                    x86_64_Register base = 0;

                    while (1)
                    {
                        while (is_asm_space(*it))
                        {
                            it += 1;
                        }

                        if (it == end)
                        {
                            break;
                        }

                        u8 first_ch = *it;
                        if ((first_ch >= 'a') & (first_ch <= 'z'))
                        {
                            let(suboperand_it, it);
                            while (is_alphanumeric(*suboperand_it))
                            {
                                suboperand_it += 1;
                            }

                            u8* operand_string_pointer = it;
                            u8 operand_string_length = suboperand_it - it;

                            let(value, pext_lookup_register_single(operand_string_pointer, operand_string_length));
                            if (value == 0xffff)
                            {
                                todo();
                            }

                            base = value;

                            it = suboperand_it;
                        }
                        else if (first_ch == '0')
                        {
                            it += 1;

                            switch (*it)
                            {
                                case 'x':
                                    {
                                        it += 1;

                                        u8* hex_it = it;
                                        while (is_hex_digit(*hex_it))
                                        {
                                            hex_it += 1;
                                        }

                                        String operand_string = { .pointer = it, .length = hex_it - it };
                                        u8 is_error;
                                        u64 result = parse_hexadecimal(operand_string, &is_error);
                                        if (is_error)
                                        {
                                            todo();
                                        }
                                        unused(result);

                                        it = hex_it;
                                    } break;
                                case 'b':
                                    {
                                        it += 1;
                                        todo();
                                    } break;
                                case 'o':
                                    {
                                        it += 1;
                                        todo();
                                    } break;
                                default: todo();
                            }
                        }
                        else
                        {
                            todo();
                        }

                        while (is_asm_space(*it))
                        {
                            it += 1;
                        }

                        switch (*it)
                        {
                            case '+':
                                {
                                    it += 1;
                                } break;
                            case '-':
                                {
                                    bias8 = -1;
                                    bias32 = -1;
                                    it += 1;
                                } break;
                            case ']':
                                {
                                } break;
                            default: todo();
                        }
                    }

                    assert(*it == ']');
                    it += 1;

                    indirects[operand_index].displacement8 = displacement8 * bias8;
                    indirects[operand_index].displacement32 = displacement32 * bias32;
                    indirects[operand_index].base = base;
                    operand_works[operand_index].kind = OPERAND_KIND_INDIRECT;
                }
                else
                {
                    todo();
                }
            }
        }

        if (unlikely(lookup_error_mask_int != 0))
        {
            todo();
        }

        // for (u64 instruction_index = 0; instruction_index < 64; instruction_index += 1)
        // {
        //     u8 instruction_operand_count = instruction_operand_counters[instruction_index];
        //     u32 instruction_operand_offset = instruction_operand_offsets[instruction_index];
        //     for (u8 instruction_operand_index = 0; instruction_operand_index < instruction_operand_count; instruction_operand_index += 1)
        //     {
        //         // u32 operand_index = instruction_operand_offset + instruction_operand_index;
        //         // OperandWork work = operand_works[operand_index];
        //         // switch (work.kind)
        //         // {
        //         //     // default: todo();
        //         // }
        //     }
        //     for (u8 instruction_operand_index = instruction_operand_count; instruction_operand_index < 4; instruction_operand_index += 1)
        //     {
        //         // Check encoding operand is zero
        //     }
        // }

        // =================================
        // TODO: START
        // =================================
        u8 immediate[8][64] = {}; // TODO
        u8 displacement[4][64] = {}; // TODO
        u8 relative[4][64] = {}; // TODO
                                 
        __mmask64 prefix_masks[LEGACY_PREFIX_COUNT] = {}; // TODO
        __mmask64 is_immediate[4] = {}; // TODO
        __mmask64 is_plus_register = {}; // TODO
        __mmask64 is_rm_register = {}; // TODO
        __mmask64 is_reg_register = {}; // TODO
        __mmask64 is_implicit_register = {}; // TODO
        __mmask64 is_displacement8 = {}; // TODO
        __mmask64 is_displacement32 = {}; // TODO
        __mmask64 is_relative8 = {}; // TODO
        __mmask64 is_relative32 = {}; // TODO
        __mmask64 is_rex_w = {}; // TODO

        __m256i rm_register_mask_256 = {}; // TODO
        __m256i reg_register_mask_256 = {}; // TODO
        __m128i opcode_lengths_128 = {}; // TODO
        __m512i opcode_extension = {}; // TODO
        __m512i opcode0_pre = {}; // TODO
        __m512i opcode1_pre = {}; // TODO
        __m512i opcode2_pre = {}; // TODO
        __m512i displacement8 = _mm512_loadu_epi8(&displacement[0][0]);
        // =================================
        // TODO: END
        // =================================

        __m512i prefixes[LEGACY_PREFIX_COUNT];
        for (LegacyPrefix prefix = 0; prefix < LEGACY_PREFIX_COUNT; prefix += 1)
        {
            prefixes[prefix] = _mm512_maskz_set1_epi8(prefix_masks[prefix], legacy_prefixes[prefix]);
        }

        __m512i instruction_length;

        u8 prefix_group1_bytes[64];
        u8 prefix_group1_positions[64];
        {
            __mmask64 prefix_group1_mask = _kor_mask64(_kor_mask64(prefix_masks[LEGACY_PREFIX_F0], prefix_masks[LEGACY_PREFIX_F2]), prefix_masks[LEGACY_PREFIX_F3]);
            __m512i prefix_group1 = _mm512_or_epi32(_mm512_or_epi32(prefixes[LEGACY_PREFIX_F0], prefixes[LEGACY_PREFIX_F2]), prefixes[LEGACY_PREFIX_F3]);
            __m512i prefix_group1_position = _mm512_maskz_set1_epi8(_knot_mask64(prefix_group1_mask), 0x0f);
            instruction_length = _mm512_maskz_set1_epi8(prefix_group1_mask, 0x01);

            _mm512_storeu_epi8(prefix_group1_bytes, prefix_group1);
            _mm512_storeu_epi8(prefix_group1_positions, prefix_group1_position);
        }

        u8 prefix_group2_bytes[64];
        u8 prefix_group2_positions[64];
        {
            __mmask64 prefix_group2_mask = _kor_mask64(_kor_mask64(_kor_mask64(prefix_masks[LEGACY_PREFIX_2E], prefix_masks[LEGACY_PREFIX_36]), _kor_mask64(prefix_masks[LEGACY_PREFIX_3E], prefix_masks[LEGACY_PREFIX_26])), _kor_mask64(prefix_masks[LEGACY_PREFIX_64], prefix_masks[LEGACY_PREFIX_65]));
            __m512i prefix_group2 = _mm512_or_epi32(_mm512_or_epi32(_mm512_or_epi32(prefixes[LEGACY_PREFIX_2E], prefixes[LEGACY_PREFIX_36]), _mm512_or_epi32(prefixes[LEGACY_PREFIX_3E], prefixes[LEGACY_PREFIX_26])), _mm512_or_epi32(prefixes[LEGACY_PREFIX_64], prefixes[LEGACY_PREFIX_65]));
            __m512i prefix_group2_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group2_mask, instruction_length);
            instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group2_mask, 0x01));

            _mm512_storeu_epi8(prefix_group2_bytes, prefix_group2);
            _mm512_storeu_epi8(prefix_group2_positions, prefix_group2_position);
        }

        u8 prefix_group3_bytes[64];
        u8 prefix_group3_positions[64];
        {
            __mmask64 prefix_group3_mask = prefix_masks[LEGACY_PREFIX_66];
            __m512i prefix_group3 = prefixes[LEGACY_PREFIX_66];
            __m512i prefix_group3_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group3_mask, instruction_length);
            instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group3_mask, 0x01));

            _mm512_storeu_epi8(prefix_group3_bytes, prefix_group3);
            _mm512_storeu_epi8(prefix_group3_positions, prefix_group3_position);
        }

        u8 prefix_group4_bytes[64];
        u8 prefix_group4_positions[64];
        {
            __mmask64 prefix_group4_mask = prefix_masks[LEGACY_PREFIX_67];
            __m512i prefix_group4 = prefixes[LEGACY_PREFIX_67];
            __m512i prefix_group4_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), prefix_group4_mask, instruction_length);
            instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(prefix_group4_mask, 0x01));

            _mm512_storeu_epi8(prefix_group4_bytes, prefix_group4);
            _mm512_storeu_epi8(prefix_group4_positions, prefix_group4_position);
        }

        __m512i rm_register;
        {
            __m256i selecting_mask = _mm256_set1_epi8(0x0f);
            __m256i low_bits = _mm256_and_si256(rm_register_mask_256, selecting_mask);
            __m256i high_bits = _mm256_and_si256(_mm256_srli_epi64(rm_register_mask_256, 4), selecting_mask);
            __m256i low_bytes = _mm256_unpacklo_epi8(low_bits, high_bits);
            __m256i high_bytes = _mm256_unpackhi_epi8(low_bits, high_bits);
            rm_register = _mm512_inserti64x4(_mm512_castsi256_si512(low_bytes), high_bytes, 1);
        }

        __m512i reg_register;
        {
            __m256i selecting_mask = _mm256_set1_epi8(0x0f);
            __m256i low_bits = _mm256_and_si256(reg_register_mask_256, selecting_mask);
            __m256i high_bits = _mm256_and_si256(_mm256_srli_epi64(rm_register_mask_256, 4), selecting_mask);
            __m256i low_bytes = _mm256_unpacklo_epi8(low_bits, high_bits);
            __m256i high_bytes = _mm256_unpackhi_epi8(low_bits, high_bits);
            reg_register = _mm512_inserti64x4(_mm512_castsi256_si512(low_bytes), high_bytes, 1);
        }

        __mmask64 is_reg_direct_addressing_mode = _knot_mask64(_kor_mask64(is_displacement8, is_displacement32));
        __mmask64 has_base_register = _kor_mask64(_kor_mask64(is_rm_register, is_reg_register), is_implicit_register);

        __m512i rex_b = _mm512_maskz_set1_epi8(_mm512_test_epi8_mask(rm_register, _mm512_set1_epi8(0b1000)), 1 << 0);
        __m512i rex_x = _mm512_set1_epi8(0); // TODO
        __m512i rex_r = _mm512_maskz_set1_epi8(_mm512_test_epi8_mask(reg_register, _mm512_set1_epi8(0b1000)), 1 << 2);
        __m512i rex_w = _mm512_maskz_set1_epi8(is_rex_w, 1 << 3);
        __m512i rex_byte = _mm512_or_epi32(_mm512_set1_epi32(0x40), _mm512_or_epi32(_mm512_or_epi32(rex_b, rex_x), _mm512_or_epi32(rex_r, rex_w)));
        __mmask64 rex_mask = _mm512_test_epi8_mask(rex_byte, _mm512_set1_epi8(0x0f));
        __m512i rex_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), rex_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(rex_mask, 0x01));

        u8 rex_bytes[64];
        u8 rex_positions[64];
        _mm512_storeu_epi8(rex_bytes, rex_byte);
        _mm512_storeu_epi8(rex_positions, rex_position);

        __m128i selecting_mask = _mm_set1_epi8(0x03);
        __m128i opcode_length_nibbles_0 = _mm_and_si128(opcode_lengths_128, selecting_mask);
        __m128i opcode_length_nibbles_1 = _mm_and_si128(_mm_srli_epi64(opcode_lengths_128, 2 * 1), selecting_mask);
        __m128i opcode_length_nibbles_2 = _mm_and_si128(_mm_srli_epi64(opcode_lengths_128, 2 * 2), selecting_mask);
        __m128i opcode_length_nibbles_3 = _mm_and_si128(_mm_srli_epi64(opcode_lengths_128, 2 * 3), selecting_mask);

        __m512i opcode_lengths_512 = _mm512_inserti64x4(_mm512_castsi256_si512(_mm256_inserti32x4(_mm256_castsi128_si256(_mm_unpacklo_epi8(opcode_length_nibbles_0, opcode_length_nibbles_1)), _mm_unpackhi_epi8(opcode_length_nibbles_0, opcode_length_nibbles_1), 1)), _mm256_inserti32x4(_mm256_castsi128_si256(_mm_unpacklo_epi8(opcode_length_nibbles_2, opcode_length_nibbles_3)), _mm_unpackhi_epi8(opcode_length_nibbles_2, opcode_length_nibbles_3), 1), 1);

        __mmask64 opcode_is_length_1 = _mm512_cmpeq_epi8_mask(opcode_lengths_512, _mm512_set1_epi8(1));
        __mmask64 opcode_is_length_2 = _mm512_cmpeq_epi8_mask(opcode_lengths_512, _mm512_set1_epi8(2));
        __mmask64 opcode_is_length_3 = _mm512_cmpeq_epi8_mask(opcode_lengths_512, _mm512_set1_epi8(3));

        __m512i plus_register = _mm512_and_si512(rm_register, _mm512_set1_epi8(0b111));

        __m512i opcode0 = _mm512_or_epi32(opcode0_pre, _mm512_maskz_mov_epi8(_kand_mask64(is_plus_register, opcode_is_length_1), plus_register));
        __m512i opcode0_position = instruction_length;
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_set1_epi8(0x01));

        u8 opcode0_bytes[64];
        u8 opcode0_positions[64];
        _mm512_storeu_epi8(opcode0_bytes, opcode0);
        _mm512_storeu_epi8(opcode0_positions, opcode0_position);

        __m512i opcode1 = _mm512_or_epi32(opcode1_pre, _mm512_maskz_mov_epi8(_kand_mask64(is_plus_register, opcode_is_length_2), plus_register));
        __mmask64 opcode1_mask = _mm512_test_epi8_mask(opcode_lengths_512, _mm512_set1_epi8(0b10));
        __m512i opcode1_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), opcode1_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(opcode1_mask, 0x01));

        u8 opcode1_bytes[64];
        u8 opcode1_positions[64];
        _mm512_storeu_epi8(opcode1_bytes, opcode1);
        _mm512_storeu_epi8(opcode1_positions, opcode1_position);

        __m512i opcode2 = _mm512_or_epi32(opcode2_pre, _mm512_maskz_mov_epi8(_kand_mask64(is_plus_register, opcode_is_length_3), plus_register));
        __mmask64 opcode2_mask = _mm512_cmpeq_epi8_mask(opcode_lengths_512, _mm512_set1_epi8(0b11));
        __m512i opcode2_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), opcode2_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(opcode2_mask, 0x01));

        u8 opcode2_bytes[64];
        u8 opcode2_positions[64];
        _mm512_storeu_epi8(opcode2_bytes, opcode2);
        _mm512_storeu_epi8(opcode2_positions, opcode2_position);

        __mmask64 mod_is_displacement32 = is_displacement32;
        __mmask64 mod_is_displacement8 = _kand_mask64(is_displacement8, _kor_mask64(_mm512_test_epi8_mask(displacement8, displacement8), _kand_mask64(is_rm_register, _mm512_cmpeq_epi8_mask(_mm512_and_si512(rm_register, _mm512_set1_epi8(0b111)), _mm512_set1_epi8(REGISTER_X86_64_BP)))));

        __mmask64 mod_rm_mask = _kor_mask64(_kand_mask64(_kor_mask64(is_rm_register, is_reg_register), _knot_mask64(is_plus_register)), _kor_mask64(is_displacement8, is_displacement32));
        __m512i register_direct_address_mode = _mm512_maskz_set1_epi8(is_reg_direct_addressing_mode, 1);
        __m512i mod = _mm512_or_epi32(_mm512_or_epi32(_mm512_slli_epi32(_mm512_maskz_set1_epi8(_kand_mask64(mod_is_displacement32, has_base_register), 1), 1), _mm512_maskz_set1_epi8(mod_is_displacement8, 1)), _mm512_or_epi32(_mm512_slli_epi32(register_direct_address_mode, 1), register_direct_address_mode));
        __m512i rm = _mm512_or_epi32(_mm512_and_si512(rm_register, _mm512_set1_epi8(0b111)), _mm512_maskz_set1_epi8(_knot_mask64(has_base_register), 0b100));
        __m512i reg = _mm512_or_epi32(_mm512_and_si512(reg_register, _mm512_set1_epi8(0b111)), opcode_extension);
        __m512i mod_rm = _mm512_or_epi32(_mm512_or_epi32(rm, _mm512_slli_epi32(reg, 3)), _mm512_slli_epi32(mod, 6));
        __m512i mod_rm_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_rm_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_rm_mask, 0x01));

        u8 mod_rm_bytes[64];
        u8 mod_rm_positions[64];
        _mm512_storeu_epi8(mod_rm_bytes, mod_rm);
        _mm512_storeu_epi8(mod_rm_positions, mod_rm_position);

        __mmask64 sib_mask = _kand_mask64(_mm512_cmpneq_epi8_mask(mod, _mm512_set1_epi8(0b11)), _mm512_cmpeq_epi8_mask(rm, _mm512_set1_epi8(0b100)));
        __m512i sib_scale = _mm512_set1_epi8(0);
        __m512i sib_index = _mm512_maskz_set1_epi8(sib_mask, 0b100 << 3);
        __m512i sib_base = _mm512_or_epi32(_mm512_and_si512(rm_register, _mm512_maskz_set1_epi8(is_rm_register, 0b111)), _mm512_maskz_set1_epi8(_knot_mask64(is_rm_register), 0b101));
        __m512i sib = _mm512_or_epi32(_mm512_or_epi32(sib_index, sib_base), sib_scale);
        __m512i sib_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), sib_mask, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(sib_mask, 0x01));

        u8 sib_bytes[64];
        u8 sib_positions[64];
        _mm512_storeu_epi8(sib_bytes, sib);
        _mm512_storeu_epi8(sib_positions, sib_position);

        __m512i displacement8_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_is_displacement8, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_is_displacement8, sizeof(s8)));
        u8 displacement8_positions[64];
        _mm512_storeu_epi8(displacement8_positions, displacement8_position);

        __m512i displacement32_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), mod_is_displacement32, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(mod_is_displacement32, sizeof(s32)));
        u8 displacement32_positions[64];
        _mm512_storeu_epi8(displacement32_positions, displacement32_position);

        __m512i relative8_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), is_relative8, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(is_relative8, sizeof(s8)));
        u8 relative8_positions[64];
        _mm512_storeu_epi8(relative8_positions, relative8_position);

        __m512i relative32_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), is_relative32, instruction_length);
        instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(is_relative32, sizeof(s32)));
        u8 relative32_positions[64];
        _mm512_storeu_epi8(relative32_positions, relative32_position);

        u8 immediate_positions[array_length(is_immediate)][64];
        for (u8 i = 0; i < array_length(immediate_positions); i += 1)
        {
            __mmask64 immediate_mask = is_immediate[i];
            __m512i immediate_position = _mm512_mask_mov_epi8(_mm512_set1_epi8(0x0f), immediate_mask, instruction_length);
            instruction_length = _mm512_add_epi8(instruction_length, _mm512_maskz_set1_epi8(immediate_mask, 1 << i));
            _mm512_storeu_epi8(immediate_positions[i], immediate_position);
        }

        u8 separate_buffers[64][max_instruction_byte_count];
        u8 separate_lengths[64];
        _mm512_storeu_epi8(separate_lengths, instruction_length);

        for (u32 i = 0; i < array_length(separate_lengths); i += 1)
        {
            separate_buffers[i][prefix_group1_positions[i]] = prefix_group1_bytes[i];
            separate_buffers[i][prefix_group2_positions[i]] = prefix_group2_bytes[i];
            separate_buffers[i][prefix_group3_positions[i]] = prefix_group3_bytes[i];
            separate_buffers[i][prefix_group4_positions[i]] = prefix_group4_bytes[i];

            separate_buffers[i][rex_positions[i]] = rex_bytes[i];

            separate_buffers[i][opcode0_positions[i]] = opcode0_bytes[i];
            separate_buffers[i][opcode1_positions[i]] = opcode1_bytes[i];
            separate_buffers[i][opcode2_positions[i]] = opcode2_bytes[i];

            separate_buffers[i][mod_rm_positions[i]] = mod_rm_bytes[i];

            separate_buffers[i][sib_positions[i]] = sib_bytes[i];

            for (u8 immediate_position_index = 0; immediate_position_index < array_length(immediate_positions); immediate_position_index += 1)
            {
                u8 start_position = immediate_positions[immediate_position_index][i];
                for (u32 byte = 0; byte < 1 << immediate_position_index; byte += 1)
                {
                    u8 destination_index = start_position + byte * (start_position != 0xf);
                    separate_buffers[i][destination_index] = immediate[byte][i];
                }
            }

            separate_buffers[i][displacement8_positions[i]] = displacement[0][i];

            u8 displacement32_start = displacement32_positions[i];
            for (u8 byte = 0; byte < 4; byte += 1)
            {
                u8 destination_index = displacement32_start + byte * (displacement32_start != 0xf);
                separate_buffers[i][destination_index] = displacement[byte][i];
            }

            separate_buffers[i][relative8_positions[i]] = relative[0][i];

            u8 relative32_start = relative32_positions[i];
            for (u8 byte = 0; byte < 4; byte += 1)
            {
                u8 destination_index = relative32_start + byte * (relative32_start != 0xf);
                separate_buffers[i][destination_index] = relative[byte][i];
            }
        }

        for (u32 i = 0; i < array_length(separate_lengths); i += 1)
        {
            let(separate_length, separate_lengths[i]);

            if (separate_length == 0) unreachable();
            if (separate_length > 15) unreachable();

            memcpy(destination, &separate_buffers[i], separate_length);
            destination += separate_length;
        }
    }

    String result = {};
    return result;
}

fn String assemble_file(Arena* arena, String path)
{
    String assembly_file = file_read(arena, path);
    String result = assemble(assembly_file);
    return result;
}

int main(int argc, char** argv, char** envp)
{
    unused(argc);
    unused(argv);

    environment_pointer = envp;
    Arena* arena = arena_initialize_default(MB(2));
    assemble_file(arena, strlit("large_assembly.s"));

    int result = 0;

    if (!BB_CI)
    {
        TestDataset dataset = construct_test_cases();
        EncodingTestOptions options = {
            .scalar = 1,
            .wide = 1,
        };
        result = encoding_test_instruction_batches(arena, dataset, options);
    }

    return result;
}
