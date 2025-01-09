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
    u8 expected_length;
    u8 valid;
};

STRUCT(Batch)
{
    Mnemonic_x86_64 mnemonic;

    BatchEncoding encodings[BATCH_ENCODING_COUNT];
};
decl_vb(Batch);

STRUCT(TestDataset)
{
    const Batch* const restrict batches;
    u64 batch_count;
    u8* restrict expected_buffer;
};

fn u8 encoding_test_instruction_batches(TestDataset dataset)
{
    u8 result = 0;

    print("Dataset batch count: {u64}\n", dataset.batch_count);
    for (u64 i = 0; i < dataset.batch_count; i += 1)
    {
        const Batch* const restrict batch = &dataset.batches[i];

        for (BatchEncodingKind kind = 0; kind < BATCH_ENCODING_COUNT; kind += 1)
        {
            const BatchEncoding* const restrict batch_encoding = &batch->encodings[kind];
            if (batch_encoding->valid)
            {
                u8 buffer[max_instruction_byte_count];
                print("{s}", mnemonic_x86_64_to_string(batch->mnemonic));

                InstructionEncoding encoding = {};
                let(length, encode_instruction_batch(buffer, &encoding, 1));

                let(expected_length, batch_encoding->expected_length);
                let(expected_pointer, &dataset.expected_buffer[batch_encoding->expected_offset]);

                u8 error = length != expected_length;
                u64 error_byte = length;

                if (!error)
                {
                    for (u64 i = 0; i < length; i += 1)
                    {
                        if (buffer[i] != expected_pointer[i])
                        {
                            error_byte = i;
                            break;
                        }
                    }
                }

                error = error | (error_byte != length);

                if (unlikely(error))
                {
                    result = 1;

                    print("[FAILED]\n");

                    print("=============================\n");

                    if (length != expected_length)
                    {
                        print("error: mismatch in the length of the instruction\n");
                    }

                    if (error_byte != length)
                    {
                        print("error: byte {u64} does not match. Expected: 0x{u32:x}. Produced: 0x{u32:x}\n", error_byte, (u32)expected_pointer[error_byte], (u32)buffer[error_byte]);
                    }

                    print("Expected {u64} bytes:\n", expected_length);

                    for (u64 i = 0; i < expected_length; i += 1)
                    {
                        print("0x{u32:x} ", (u32)expected_pointer[i]);
                    }

                    print("\nOutput {u64} bytes:\n", length);

                    for (u64 i = 0; i < length; i += 1)
                    {
                        print("0x{u32:x} ", (u32)buffer[i]);
                    }

                    print("\n");
                    print("=============================\n");
                }
                else
                {
                    print("[OK] [ ");
                    for (u64 i = 0; i < length; i += 1)
                    {
                        print("0x{u32:x} ", (u32)buffer[i]);
                    }
                    print("]\n");
                }
            }
        }
    }

    return result;
}

STRUCT(DatasetPreparer)
{
    VirtualBuffer(u8) expected_buffer;
    VirtualBuffer(Batch) batches;
};

STRUCT(BatchCreate)
{
    Mnemonic_x86_64 mnemonic;
};

fn Batch* prepare_get_batch(DatasetPreparer* restrict preparer, BatchCreate create)
{
    Batch* batch = vb_add(&preparer->batches, 1);
    batch->mnemonic = create.mnemonic;
    return batch;
}

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
    InstructionBytes expected;
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

fn void prepare_batch_encoding(DatasetPreparer* restrict preparer, Batch* restrict batch, EncodingPrepare prepare)
{
    unused(preparer);
    unused(batch);
    unused(prepare);
}

#define batch_start(_mnemonic) let(batch, prepare_get_batch(preparer, (BatchCreate) { .mnemonic = (MNEMONIC_x86_64_ ## _mnemonic), }));
#define encode(_opcode, _expected, _operands) prepare_batch_encoding(preparer, batch, ((EncodingPrepare) { .opcode = _opcode, .expected = _expected, .operands = _operands, }));
#define batch_end()
#define exp(...) ((InstructionBytes) { .length = array_length(((u8[]){__VA_ARGS__})), .bytes = { __VA_ARGS__ } })
#define ops(...) ((Operands){ .values = { __VA_ARGS__ }, .count = array_length(((OperandKind[]){ __VA_ARGS__ })), })
#define opc(...) ((Opcode) { .length = array_length(((u8[]){__VA_ARGS__})), .bytes = { __VA_ARGS__ }})

fn TestDataset construct_test_cases()
{
    DatasetPreparer preparer_memory = {};
    DatasetPreparer* restrict preparer = &preparer_memory;

    {
        batch_start(add);
        encode(opc(0x04), exp(0x04), ops(op_ra8, op_imm8));
        batch_end();
    }

    TestDataset result = {
        .expected_buffer = preparer->expected_buffer.pointer,
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

    // EncodingTestCase test_cases[] = {
    //     {
    //         .encoding = {
    //             .opcode = 0x04,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x04, immediate8_array })),
    //         .text = strlit("add al, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x05,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x05, immediate16_array })),
    //         .text = strlit("add ax, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x05,
    //             .is_immediate32 = 1,
    //             .immediate32 = immediate32_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x05, immediate32_array })),
    //         .text = strlit("add eax, " immediate32_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x05,
    //             .is_immediate32 = 1,
    //             .immediate32 = immediate32_literal,
    //             .is_64_bit = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x48, 0x05, immediate32_array })),
    //         .text = strlit("add rax, " immediate32_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_AL,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc0, immediate8_array })),
    //         .text = strlit("add al, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_CL,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc1, immediate8_array })),
    //         .text = strlit("add cl, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_DL,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc2, immediate8_array })),
    //         .text = strlit("add dl, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_BL,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc3, immediate8_array })),
    //         .text = strlit("add bl, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_AH,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc4, immediate8_array })),
    //         .text = strlit("add ah, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_CH,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc5, immediate8_array })),
    //         .text = strlit("add ch, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_DH,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc6, immediate8_array })),
    //         .text = strlit("add dh, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_BH,
    //             .is_reg1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0xc7, immediate8_array })),
    //         .text = strlit("add bh, " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RAX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x00, immediate8_array })),
    //         .text = strlit("add byte ptr [rax], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RCX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x01, immediate8_array })),
    //         .text = strlit("add byte ptr [rcx], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RDX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x02, immediate8_array })),
    //         .text = strlit("add byte ptr [rdx], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RBX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x03, immediate8_array })),
    //         .text = strlit("add byte ptr [rbx], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RSP,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //             .sib_base = REGISTER_X86_64_RSP,
    //             .sib_index = 0b100,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x04, 0x24, immediate8_array })),
    //         .text = strlit("add byte ptr [rsp], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RBP,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x45, 0x00, immediate8_array })),
    //         .text = strlit("add byte ptr [rbp], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RSI,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x06, immediate8_array })),
    //         .text = strlit("add byte ptr [rsi], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_RDI,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x80, 0x07, immediate8_array })),
    //         .text = strlit("add byte ptr [rdi], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R8,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x00, immediate8_array })),
    //         .text = strlit("add byte ptr [r8], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R9,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x01, immediate8_array })),
    //         .text = strlit("add byte ptr [r9], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R10,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x02, immediate8_array })),
    //         .text = strlit("add byte ptr [r10], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R11,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x03, immediate8_array })),
    //         .text = strlit("add byte ptr [r11], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R12,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //             .sib_base = REGISTER_X86_64_R12,
    //             .sib_index = 0b100,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x04, 0x24, immediate8_array })),
    //         .text = strlit("add byte ptr [r12], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R13,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x45, 0x00, immediate8_array })),
    //         .text = strlit("add byte ptr [r13], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R14,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x06, immediate8_array })),
    //         .text = strlit("add byte ptr [r14], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x80,
    //             .reg1 = REGISTER_X86_64_R15,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate8 = 1,
    //             .immediate8 = immediate8_literal,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x07, immediate8_array })),
    //         .text = strlit("add byte ptr [r15], " immediate8_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_AX,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc0, immediate16_array })),
    //         .text = strlit("add ax, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_CX,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc1, immediate16_array })),
    //         .text = strlit("add cx, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_DX,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc2, immediate16_array })),
    //         .text = strlit("add dx, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_BX,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc3, immediate16_array })),
    //         .text = strlit("add bx, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_SP,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc4, immediate16_array })),
    //         .text = strlit("add sp, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_BP,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc5, immediate16_array })),
    //         .text = strlit("add bp, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_SI,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc6, immediate16_array })),
    //         .text = strlit("add si, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_DI,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc7, immediate16_array })),
    //         .text = strlit("add di, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R8W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc0, immediate16_array })),
    //         .text = strlit("add r8w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R9W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc1, immediate16_array })),
    //         .text = strlit("add r9w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R10W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc2, immediate16_array })),
    //         .text = strlit("add r10w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R11W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc3, immediate16_array })),
    //         .text = strlit("add r11w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R12W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc4, immediate16_array })),
    //         .text = strlit("add r12w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R13W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc5, immediate16_array })),
    //         .text = strlit("add r13w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R14W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc6, immediate16_array })),
    //         .text = strlit("add r14w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R15W,
    //             .is_reg1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc7, immediate16_array })),
    //         .text = strlit("add r15w, " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RAX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x00, immediate16_array })),
    //         .text = strlit("add word ptr [rax], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RCX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x01, immediate16_array })),
    //         .text = strlit("add word ptr [rcx], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RDX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x02, immediate16_array })),
    //         .text = strlit("add word ptr [rdx], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RBX,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x03, immediate16_array })),
    //         .text = strlit("add word ptr [rbx], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RSP,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .sib_base = REGISTER_X86_64_RSP,
    //             .sib_index = 0b100,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x04, 0x24, immediate16_array })),
    //         .text = strlit("add word ptr [rsp], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RBP,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x45, 0x00, immediate16_array })),
    //         .text = strlit("add word ptr [rbp], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RSI,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x06, immediate16_array })),
    //         .text = strlit("add word ptr [rsi], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_RDI,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x07, immediate16_array })),
    //         .text = strlit("add word ptr [rdi], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R8,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x00, immediate16_array })),
    //         .text = strlit("add word ptr [r8], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R9,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x01, immediate16_array })),
    //         .text = strlit("add word ptr [r9], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R10,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x02, immediate16_array })),
    //         .text = strlit("add word ptr [r10], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R11,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x03, immediate16_array })),
    //         .text = strlit("add word ptr [r11], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R12,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .sib_base = REGISTER_X86_64_R12,
    //             .sib_index = 0b100,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x04, 0x24, immediate16_array })),
    //         .text = strlit("add word ptr [r12], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R13,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x45, 0x00, immediate16_array })),
    //         .text = strlit("add word ptr [r13], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R14,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x06, immediate16_array })),
    //         .text = strlit("add word ptr [r14], " immediate16_string),
    //     },
    //     {
    //         .encoding = {
    //             .opcode = 0x81,
    //             .reg1 = REGISTER_X86_64_R15,
    //             .is_reg1 = 1,
    //             .is_indirect1 = 1,
    //             .is_immediate16 = 1,
    //             .immediate16 = immediate16_literal,
    //             .is_16_mode = 1,
    //         },
    //         .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x07, immediate16_array })),
    //         .text = strlit("add word ptr [r15], " immediate16_string),
    //     },
    // };

    // return encoding_test_all(test_cases, array_length(test_cases));
}
