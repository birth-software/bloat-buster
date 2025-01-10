#include <std/base.h>
#include <std/os.h>
#include <std/virtual_buffer.h>

#include <std/base.c>
#include <std/os.c>
#include <std/virtual_buffer.c>

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

#define X86_64_GPR_COUNT (16)

STRUCT(InstructionEncoding)
{
    u8 is_64_bit;
    u8 has_rex;
    u8 scaled_index_register;
    u8 opcode;
    u8 reg1;
    u8 reg2;
    u8 is_reg1;
    u8 is_reg2;
    u8 is_indirect1;
    u8 is_indirect2;
    u8 is_immediate8;
    u8 is_immediate16;
    u8 is_immediate32;
    u8 is_immediate64;
    u8 immediate8;
    u16 immediate16;
    u32 immediate32;
    u64 immediate64;
    u8 is_16_mode;
    s8 displacement8;
    s32 displacement32;
    u8 sib_scale;
    u8 sib_index;
    u8 sib_base;
};

#define batch_element_count (16)
#define max_instruction_byte_count (16)

u16 encode_instruction_batch(u8* restrict output, const InstructionEncoding* const restrict encodings, u64 encoding_count)
{
    u8 buffers[batch_element_count][max_instruction_byte_count];
    u8 instruction_lengths[batch_element_count];

    for (u32 i = 0; i < batch_element_count; i += 1)
    {
        InstructionEncoding encoding = encodings[i];
    
        const u8* const start = (const u8* const) &buffers[i];
        u8* restrict it = (u8* restrict) &buffers[i];

        u8 operand_size_override_prefix = 0x66;
        *it = operand_size_override_prefix;
        it += encoding.is_16_mode;

        u8 rex_base = 0x40;
        u8 rex_b = 0x01;
        u8 rex_x = 0x02;
        u8 rex_r = 0x04;
        u8 rex_w = 0x08;
        u8 byte_rex_b = rex_b * ((encoding.reg1 & 0b1000) >> 3);
        u8 byte_rex_x = rex_x * encoding.scaled_index_register;
        u8 byte_rex_r = rex_r * ((encoding.reg2 & 0b1000) >> 3);
        u8 byte_rex_w = rex_w * encoding.is_64_bit;
        u8 byte_rex = (byte_rex_b | byte_rex_x) | (byte_rex_r | byte_rex_w);
        u8 rex = (rex_base | byte_rex);
        u8 encode_rex = byte_rex != 0;
        *it = rex;
        it += encode_rex;

        *it = encoding.opcode;
        it += 1;

        u8 encode_modrm = encoding.is_reg1 | encoding.is_reg2;

        // Mod:
        // 00: No displacement (except when R/M = 101, where a 32-bit displacement follows).
        // 01: 8-bit signed displacement follows.
        // 10: 32-bit signed displacement follows.
        // 11: Register addressing (no memory access).
        
        u8 is_displacement32 = encoding.displacement32 != 0;
        u8 is_displacement8 = (encoding.displacement8 != 0) | (((encoding.is_indirect1 & ((encoding.reg1 & 0b111) == REGISTER_X86_64_RBP)) | (encoding.is_indirect2 & ((encoding.reg2 & 0b111) == REGISTER_X86_64_RBP))) & !is_displacement32);
        u8 is_reg_direct_addressing_mode = !(encoding.is_indirect1 | encoding.is_indirect1);
        u8 mod = ((is_displacement32 << 1) | is_displacement8) | ((is_reg_direct_addressing_mode << 1) | is_reg_direct_addressing_mode);
        // A register operand.
        // An opcode extension (in some instructions).
        u8 reg_opcode = encoding.reg2 & 0b111;
        // When mod is 00, 01, or 10: Specifies a memory address or a base register.
        // When mod is 11: Specifies a register.
        u8 rm = encoding.reg1 & 0b111;
        u8 modrm = (mod << 6) | (reg_opcode << 3) | rm;
        *it = modrm;
        it += encode_modrm;

        // When mod is 00, 01, or 10 and rm = 100, a SIB (Scale-Index-Base) byte follows the ModR/M byte to further specify the addressing mode.
        u8 sib_byte = encoding.sib_scale << 6 | encoding.sib_index << 3 | (encoding.sib_base & 0b111);
        *it = sib_byte;
        it += (mod != 0b11) & (rm == 0b100);

        *it = encoding.displacement8;
        it += is_displacement8;

        *(u32*)it = encoding.displacement32;
        it += sizeof(encoding.displacement32) * is_displacement32;

        *(typeof(encoding.immediate8)*) it = encoding.immediate8;
        it += encoding.is_immediate8 * sizeof(encoding.immediate8);

        *(typeof(encoding.immediate16)*) it = encoding.immediate16;
        it += encoding.is_immediate16 * sizeof(encoding.immediate16);

        *(typeof(encoding.immediate32)*) it = encoding.immediate32;
        it += encoding.is_immediate32 * sizeof(encoding.immediate32);

        *(typeof(encoding.immediate64)*) it = encoding.immediate64;
        it += encoding.is_immediate64 * sizeof(encoding.immediate64);

        let_cast(u8, instruction_length, it - start);
        instruction_lengths[i] = instruction_length;
    }

    u8* restrict it = output;

    for (u32 i = 0; i < MIN(encoding_count, batch_element_count); i += 1)
    {
        let(instruction_length, instruction_lengths[i]);
#if USE_MEMCPY
        memcpy(it, &buffers[i], instruction_length);
#else
        for (u8 byte = 0; byte < instruction_length; byte += 1)
        {
            it[byte] = buffers[i][byte];
        }
        it += instruction_length;
#endif
    }

    return it - output;
}

typedef enum Mnemonic_x86_64
{
    MNEMONIC_x86_64_add,
} Mnemonic_x86_64;

fn String mnemonic_x86_64_to_string(Mnemonic_x86_64 mnemonic)
{
    switch (mnemonic)
    {
        case_to_name(MNEMONIC_x86_64_, add);
    }
}

STRUCT(EncodingTestCase)
{
    InstructionEncoding encoding;
    String expected;
};

typedef enum BatchEncodingKind
{
    BATCH_ENCODING_KIND_RA8_IMM8,
    BATCH_ENCODING_KIND_RA16_IMM16,
    BATCH_ENCODING_KIND_RA32_IMM32,
    BATCH_ENCODING_KIND_RA64_IMM32,

    BATCH_ENCODING_KIND_RM8_IMM8,
    BATCH_ENCODING_KIND_RM16_IMM16,
    BATCH_ENCODING_KIND_RM32_IMM32,
    BATCH_ENCODING_KIND_RM64_IMM32,

    BATCH_ENCODING_KIND_RM16_IMM8,
    BATCH_ENCODING_KIND_RM32_IMM8,
    BATCH_ENCODING_KIND_RM64_IMM8,

    BATCH_ENCODING_KIND_RM8_R8,
    BATCH_ENCODING_KIND_RM16_R16,
    BATCH_ENCODING_KIND_RM32_R32,
    BATCH_ENCODING_KIND_RM64_R64,

    BATCH_ENCODING_KIND_R8_RM8,
    BATCH_ENCODING_KIND_R16_RM16,
    BATCH_ENCODING_KIND_R32_RM32,
    BATCH_ENCODING_KIND_R64_RM64,

    BATCH_ENCODING_COUNT,
} BatchEncodingKind;

STRUCT(BatchEncoding)
{
    u32 expected_offset;
    u32 text_offset;
    u8 expected_length;
    u8 text_length;
    u8 valid;
};
decl_vb(BatchEncoding);

STRUCT(Batch)
{
    Mnemonic_x86_64 mnemonic;

    BatchEncoding* encodings;
    u64 encoding_count;
};
decl_vb(Batch);

STRUCT(BatchBuilder)
{
    Mnemonic_x86_64 mnemonic;

    VirtualBuffer(BatchEncoding) encodings;
};

STRUCT(TestDataset)
{
    const Batch* const restrict batches;
    u64 batch_count;
    u8* restrict string_buffer;
};

fn u8 encoding_test_instruction_batches(TestDataset dataset)
{
    u8 result = 0;

    print("Dataset batch count: {u64}\n", dataset.batch_count);
    for (u64 i = 0; i < dataset.batch_count; i += 1)
    {
        const Batch* const restrict batch = &dataset.batches[i];
        unused(batch);

        print("Batch contains {u64} encodings\n", batch->encoding_count);

        for (u64 i = 0; i < batch->encoding_count; i += 1)
        {
            BatchEncoding* encoding = &batch->encodings[i];
            String text = {
                .pointer = dataset.string_buffer + encoding->text_offset,
                .length = encoding->text_length,
            };

            print("[{u64}] {s}\n", i, text);
        }

        // for (BatchEncodingKind kind = 0; kind < BATCH_ENCODING_COUNT; kind += 1)
        // {
        //     const BatchEncoding* const restrict batch_encoding = &batch->encodings[kind];
        //     if (batch_encoding->valid)
        //     {
        //         u8 buffer[max_instruction_byte_count];
        //         print("{s}", mnemonic_x86_64_to_string(batch->mnemonic));
        //
        //         InstructionEncoding encoding = {};
        //         let(length, encode_instruction_batch(buffer, &encoding, 1));
        //
        //         let(expected_length, batch_encoding->expected_length);
        //         let(expected_pointer, &dataset.string_buffer[batch_encoding->expected_offset]);
        //
        //         u8 error = length != expected_length;
        //         u64 error_byte = length;
        //
        //         if (!error)
        //         {
        //             for (u64 i = 0; i < length; i += 1)
        //             {
        //                 if (buffer[i] != expected_pointer[i])
        //                 {
        //                     error_byte = i;
        //                     break;
        //                 }
        //             }
        //         }
        //
        //         error = error | (error_byte != length);
        //
        //         if (unlikely(error))
        //         {
        //             result = 1;
        //
        //             print("[FAILED]\n");
        //
        //             print("=============================\n");
        //
        //             if (length != expected_length)
        //             {
        //                 print("error: mismatch in the length of the instruction\n");
        //             }
        //
        //             if (error_byte != length)
        //             {
        //                 print("error: byte {u64} does not match. Expected: 0x{u32:x}. Produced: 0x{u32:x}\n", error_byte, (u32)expected_pointer[error_byte], (u32)buffer[error_byte]);
        //             }
        //
        //             print("Expected {u64} bytes:\n", expected_length);
        //
        //             for (u64 i = 0; i < expected_length; i += 1)
        //             {
        //                 print("0x{u32:x} ", (u32)expected_pointer[i]);
        //             }
        //
        //             print("\nOutput {u64} bytes:\n", length);
        //
        //             for (u64 i = 0; i < length; i += 1)
        //             {
        //                 print("0x{u32:x} ", (u32)buffer[i]);
        //             }
        //
        //             print("\n");
        //             print("=============================\n");
        //         }
        //         else
        //         {
        //             print("[OK] [ ");
        //             for (u64 i = 0; i < length; i += 1)
        //             {
        //                 print("0x{u32:x} ", (u32)buffer[i]);
        //             }
        //             print("]\n");
        //         }
        //     }
        // }
    }

    return result;
}

STRUCT(DatasetPreparer)
{
    VirtualBuffer(u8) string_buffer;
    VirtualBuffer(Batch) batches;
};

STRUCT(BatchCreate)
{
    Mnemonic_x86_64 mnemonic;
};

STRUCT(Opcode)
{
    u8 length;
    u8 bytes[4];
};

typedef enum ImmediateKind
{
    IMMEDIATE_KIND_8 = 0,
    IMMEDIATE_KIND_16 = 1,
    IMMEDIATE_KIND_32 = 2,
    IMMEDIATE_KIND_64 = 3,
} ImmediateKind;

STRUCT(Immediate)
{
    u64 value;
    union
    {
        struct
        {
            u8 immediate8:1;
            u8 immediate16:1;
            u8 immediate32:1;
            u8 immediate64:1;
            u8 reserved:4;
        };
        u8 raw;
    };
};

typedef enum OperandKind
{
    op_none,
    op_ra8,
    op_ra16,
    op_ra32,
    op_ra64,
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
} OperandKind;

#define operand_kind_array_element_count (4)

STRUCT(Operands)
{
    OperandKind values[operand_kind_array_element_count];
    u8 count;
};
STRUCT(InstructionBytes)
{
    u8 bytes[max_instruction_byte_count];
    u8 length;
};

STRUCT(EncodingPrepare)
{
    Opcode opcode;
    // InstructionBytes expected;
    Operands operands;
};

fn Opcode opcode1(u8 opcode)
{
    Opcode result = {
        .length = 1,
        .bytes = { opcode },
    };
    return result;
}

fn u8 op_is_gpra(OperandKind operand_kind)
{
    return operand_kind >= op_ra8 && operand_kind <= op_ra64;
}

fn u8 op_is_imm(OperandKind operand_kind)
{
    return operand_kind >= op_imm8 && operand_kind <= op_imm64;
}

fn u8 op_is_gpr_no_gpra_exclusive(OperandKind operand_kind)
{
    return operand_kind >= op_r8 && operand_kind <= op_r64;
}

fn u8 op_is_rm(OperandKind operand_kind)
{
    return operand_kind >= op_rm8 && operand_kind <= op_rm64;
}

fn u8 op_is_gpr_no_gpra(OperandKind operand_kind)
{
    return op_is_gpr_no_gpra_exclusive(operand_kind) | op_is_rm(operand_kind);
}

fn u8 op_rm_get_index(OperandKind operand_kind)
{
    assert(op_is_rm(operand_kind));
    return operand_kind - op_rm8;
}

fn u8 op_gpr_exclusive_get_index(OperandKind operand_kind)
{
    assert(op_is_gpr_no_gpra_exclusive(operand_kind));
    return operand_kind - op_r8;
}

fn u8 op_gpr_get_index(OperandKind operand_kind)
{
    assert(op_is_gpr_no_gpra(operand_kind));
    return op_is_rm(operand_kind) ? op_rm_get_index(operand_kind) : op_gpr_exclusive_get_index(operand_kind);
}

fn u8 op_imm_get_index(OperandKind operand_kind)
{
    assert(op_is_imm(operand_kind));
    return operand_kind - op_imm8;
}

fn u8 op_get_size_out_of_index(u8 index)
{
    return 1 << index;
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
            strlit("r8l"),
            strlit("r8w"),
            strlit("r8d"),
            strlit("r8"),
        },
        [REGISTER_X86_64_R9] = {
            strlit("r9l"),
            strlit("r9w"),
            strlit("r9d"),
            strlit("r9"),
        },
        [REGISTER_X86_64_R10] = {
            strlit("r10l"),
            strlit("r10w"),
            strlit("r10d"),
            strlit("r10"),
        },
        [REGISTER_X86_64_R11] = {
            strlit("r11l"),
            strlit("r11w"),
            strlit("r11d"),
            strlit("r11"),
        },
        [REGISTER_X86_64_R12] = {
            strlit("r12l"),
            strlit("r12w"),
            strlit("r12d"),
            strlit("r12"),
        },
        [REGISTER_X86_64_R13] = {
            strlit("r13l"),
            strlit("r13w"),
            strlit("r13d"),
            strlit("r13"),
        },
        [REGISTER_X86_64_R14] = {
            strlit("r14l"),
            strlit("r14w"),
            strlit("r14d"),
            strlit("r14"),
        },
        [REGISTER_X86_64_R15] = {
            strlit("r15l"),
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

fn String sample_immediate_strings(u8 index)
{
    global_variable const String strings[] = {
        strlit("0x10"),
        strlit("0x1000"),
        strlit("0x10000000"),
        strlit("0x1000000000000000"),
    };

    return strings[index];
}

fn void format_instruction2_text(DatasetPreparer* restrict preparer, BatchEncoding* restrict encoding, String mnemonic, String op1, String op2)
{
    u8 buffer[256];
    String string = format_string((String)array_to_slice(buffer), "{s} {s}, {s}", mnemonic, op1, op2);
    u32 offset = vb_copy_string(&preparer->string_buffer, string);

    encoding->text_offset = offset;
    assign_cast(encoding->text_length, string.length);
}

fn String format_displacement(String buffer, String register_string, String displacement_string)
{
    u64 length = 0;
    String result = {
        .pointer = buffer.pointer,
    };

    buffer.pointer[length] = '[';
    length += 1;

    memcpy(&buffer.pointer[length], register_string.pointer, register_string.length);
    length += register_string.length;

    buffer.pointer[length] = '+';
    length += 1;

    memcpy(&buffer.pointer[length], displacement_string.pointer, displacement_string.length);
    length += displacement_string.length;

    buffer.pointer[length] = ']';
    length += 1;

    result.length = length;

    return result;
}

fn void prepare_batch_encoding(DatasetPreparer* restrict preparer, BatchBuilder* restrict batch, EncodingPrepare prepare)
{
    OperandKind first_operand = prepare.operands.values[0];
    let(operand_count, prepare.operands.count);
    // TODO: Do we need to compute `mnemonic_string` every encoding?
    String mnemonic_string = mnemonic_x86_64_to_string(batch->mnemonic);

    if (operand_count == 0)
    {
        todo();
    }
    else if (op_is_gpra(first_operand))
    {
        let(register_a_index, first_operand - op_ra8);
        String names[] = {
            strlit("al"),
            strlit("ax"),
            strlit("eax"),
            strlit("rax"),
        };
        String reg_name = names[register_a_index];

        switch (operand_count)
        {
            case 1:
                {
                    todo();
                } break;
            case 2:
                {
                    OperandKind second_operand = prepare.operands.values[1];
                    assert(op_is_imm(second_operand));
                    let(imm_index, op_imm_get_index(second_operand));
                    // We output the string directly to avoid formatting cost
                    String imm_string = sample_immediate_strings(imm_index);
                    BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                    format_instruction2_text(preparer, encoding, mnemonic_string, reg_name, imm_string);
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
                    todo();
                } break;
            case 2:
                {
                    OperandKind second_operand = prepare.operands.values[1];

                    s32 displacements[] = {
                        0,
                        0x10,
                        0x10000000,
                    };

                    String displacement_strings[] = {
                        strlit("0"),
                        strlit("0x10"),
                        strlit("0x10000000"),
                    };

                    if (op_is_gpr_no_gpra(first_operand))
                    {
                        // u8 is_indirect = 0;
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

                                for (u32 i = 0; i < array_length(displacements); i += 1)
                                {
                                    first_rm_strings[gpr][i] = format_displacement((String)array_to_slice(first_rm_buffer[gpr][i]), first_operand_rm_name, displacement_strings[i]);
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

                                    for (u32 i = 0; i < array_length(displacements); i += 1)
                                    {
                                        second_rm_strings[gpr][i] = format_displacement((String)array_to_slice(second_rm_buffer[gpr][i]), second_operand_rm_name, displacement_strings[i]);
                                    }
                                }
                            }

                            for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                            {
                                String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                {
                                    String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);
                                    BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                                    format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, second_operand_string);
                                }
                            }

                            if (first_is_rm)
                            {
                                for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                {
                                    for (u32 i = 0; i < array_length(displacements); i += 1)
                                    {
                                        String first_operand_string = first_rm_strings[first_gpr][i];

                                        for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                        {
                                            String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);
                                            BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                                            format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, second_operand_string);
                                        }
                                    }
                                }
                            }

                            if (second_is_rm)
                            {
                                for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                {
                                    String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                    for (GPR_x86_64 second_gpr = 0; second_gpr < X86_64_GPR_COUNT; second_gpr += 1)
                                    {
                                        for (u32 i = 0; i < array_length(displacements); i += 1)
                                        {
                                            String second_operand_string = second_rm_strings[second_gpr][i];
                                            BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                                            format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, second_operand_string);
                                        }
                                    }
                                }
                            }

                            if (first_is_rm && second_is_rm)
                            {
                                for (GPR_x86_64 first_gpr = 0; first_gpr < X86_64_GPR_COUNT; first_gpr += 1)
                                {
                                    for (u32 first_displacement_i = 0; first_displacement_i < array_length(displacements); first_displacement_i += 1)
                                    {
                                        String first_operand_string = first_rm_strings[first_gpr][first_displacement_i];
                                        for (GPR_x86_64 second_gpr = 0; second_gpr < X86_64_GPR_COUNT; second_gpr += 1)
                                        {
                                            for (u32 second_displacement_i = 0; second_displacement_i < array_length(displacements); second_displacement_i += 1)
                                            {
                                                String second_operand_string = second_rm_strings[second_gpr][second_displacement_i];
                                                BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                                                format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, second_operand_string);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            assert(op_is_imm(second_operand));
                            u8 second_operand_index = op_imm_get_index(second_operand);
                            String imm_string = sample_immediate_strings(second_operand_index);

                            for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                            {
                                BatchEncoding* encoding = vb_add(&batch->encodings, 1);

                                String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);
                                format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, imm_string);
                            }

                            if (first_is_rm)
                            {
                                for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                {
                                    for (u32 i = 0; i < array_length(displacements); i += 1)
                                    {
                                        BatchEncoding* encoding = vb_add(&batch->encodings, 1);
                                        String first_operand_string = first_rm_strings[gpr][i];
                                        format_instruction2_text(preparer, encoding, mnemonic_string, first_operand_string, imm_string);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        todo();
                    }
                }; break;
            case 3:
                {
                    todo();
                } break;
            case 4:
                {
                    todo();
                } break;
        }
    }
}

STRUCT(BatchStart)
{
    Mnemonic_x86_64 mnemonic;
};

fn void batch_start_extended(BatchBuilder* restrict batch_builder, BatchStart start)
{
    *batch_builder = (BatchBuilder) {
        .mnemonic = start.mnemonic,
    };
}

fn void batch_end_extended(DatasetPreparer* restrict preparer, BatchBuilder* restrict batch_builder)
{
    Batch* batch = vb_add(&preparer->batches, 1);
    *batch = (Batch) {
        .mnemonic = batch_builder->mnemonic,
        .encodings = batch_builder->encodings.pointer,
        .encoding_count = batch_builder->encodings.length,
    };
}

#define batch_start(_mnemonic) BatchBuilder batch_builder; batch_start_extended(&batch_builder, (BatchStart) { .mnemonic = MNEMONIC_x86_64_ ## _mnemonic })
// { .mnemonic =  (MNEMONIC_x86_64_ ## _mnemonic), }
#define encode(_opcode, _operands) prepare_batch_encoding(preparer, &batch_builder, ((EncodingPrepare) { .opcode = _opcode, .operands = _operands, }));
#define batch_end() batch_end_extended(preparer, &batch_builder);
// #define exp(...) ((InstructionBytes) { .length = array_length(((u8[]){__VA_ARGS__})), .bytes = { __VA_ARGS__ } })
#define ops(...) ((Operands){ .values = { __VA_ARGS__ }, .count = array_length(((OperandKind[]){ __VA_ARGS__ })), })
#define opc(...) ((Opcode) { .length = array_length(((u8[]){__VA_ARGS__})), .bytes = { __VA_ARGS__ }})

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

fn TestDataset construct_test_cases()
{
    DatasetPreparer preparer_memory = {};
    DatasetPreparer* restrict preparer = &preparer_memory;

    {
        batch_start(add);

        encode(opc(0x04), ops(op_ra8,  op_imm8));
        encode(opc(0x05), ops(op_ra16, op_imm16));
        encode(opc(0x05), ops(op_ra32, op_imm32));
        encode(opc(0x05), ops(op_ra64, op_imm32));

        encode(opc(0x80), ops(op_rm8,  op_imm8));
        encode(opc(0x81), ops(op_rm16, op_imm16));
        encode(opc(0x81), ops(op_rm32, op_imm32));
        encode(opc(0x81), ops(op_rm64, op_imm32));

        encode(opc(0x83), ops(op_rm16, op_imm8));
        encode(opc(0x83), ops(op_rm32, op_imm8));
        encode(opc(0x83), ops(op_rm64, op_imm8));

        encode(opc(0x00), ops(op_rm8,  op_r8));
        encode(opc(0x01), ops(op_rm16, op_r16));
        encode(opc(0x01), ops(op_rm32, op_r32));
        encode(opc(0x01), ops(op_rm64, op_r64));

        encode(opc(0x02), ops(op_r8,  op_rm8));
        encode(opc(0x03), ops(op_r16, op_rm16));
        encode(opc(0x03), ops(op_r32, op_rm32));
        encode(opc(0x03), ops(op_r64, op_rm64));

        batch_end();
    }

    TestDataset result = {
        .string_buffer = preparer->string_buffer.pointer,
        .batches = preparer->batches.pointer,
        .batch_count = preparer->batches.length,
    };
    return result;
}

int main(int argc, char** argv, char** envp)
{
    unused(argc);
    unused(argv);
    unused(envp);

    TestDataset dataset = construct_test_cases();
    u8 result = encoding_test_instruction_batches(dataset);
    return result;
}
