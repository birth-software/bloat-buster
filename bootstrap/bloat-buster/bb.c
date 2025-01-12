#include <std/base.h>
#include <std/os.h>
#include <std/virtual_buffer.h>
#include <std/project.h>

#include <std/base.c>
#include <std/os.c>
#include <std/virtual_buffer.c>

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

STRUCT(InstructionEncoding)
{
    u64 is_64_bit:1;
    u64 has_rex:1;
    u64 scaled_index_register:1;
    u64 is_reg1:1;
    u64 is_reg2:1;
    u64 is_indirect1:1;
    u64 is_indirect2:1;
    u64 is_immediate:4;
    u64 is_16_mode:1;
    u64 immediate;
    // TODO: merge?
    s32 displacement;
    // TODO: support more bytes
    u8 opcode;
    u8 reg1;
    u8 reg2;
    u8 sib_scale;
    u8 sib_index;
    u8 sib_base;
};

#define batch_element_count (16)
#define max_instruction_byte_count (16)

fn u16 encode_instruction_batch(u8* restrict output, const InstructionEncoding* const restrict encodings, u64 encoding_count)
{
    u8 buffers[batch_element_count][max_instruction_byte_count];
    u8 instruction_lengths[batch_element_count];

    for (u32 i = 0; i < batch_element_count; i += 1)
    {
        InstructionEncoding encoding = encodings[i];
    
        const u8* const start = (const u8* const) &buffers[i];
        u8* restrict local_buffer = (u8* restrict)&buffers[i];
        u8* restrict it = local_buffer;

        u8 operand_size_override_prefix = 0x66;
        *it = operand_size_override_prefix;
        it += encoding.is_16_mode;

        u8 rex_base = 0x40;
        u8 rex_b = 0x01;
        u8 rex_x = 0x02;
        u8 rex_r = 0x04;
        u8 rex_w = 0x08;
        u8 byte_rex_b = rex_b * gpr_is_extended(encoding.reg1);
        u8 byte_rex_x = rex_x * encoding.scaled_index_register;
        u8 byte_rex_r = rex_r * gpr_is_extended(encoding.reg2); 
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
        
        u8 is_displacement32 = encoding.displacement != 0 && (s32)((s8)encoding.displacement) != encoding.displacement;
        u8 is_displacement8 = (!is_displacement32) & ((encoding.displacement != 0) | ((encoding.is_indirect1 & ((encoding.reg1 & 0b111) == REGISTER_X86_64_RBP)) | (encoding.is_indirect2 & ((encoding.reg2 & 0b111) == REGISTER_X86_64_RBP))));
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

        *(s8*)it = (s8)encoding.displacement;
        it += is_displacement8 * sizeof(s8);

        *(s32*)it = encoding.displacement;
        it += is_displacement32 * sizeof(s32);

        *(u8*) it = (u8)encoding.immediate;
        it += ((encoding.is_immediate & (1 << 0)) >> 0) * sizeof(u8);

        *(u16*) it = (u16)encoding.immediate;
        it += ((encoding.is_immediate & (1 << 1)) >> 1) * sizeof(u16);

        *(u32*) it = (u32)encoding.immediate;
        it += ((encoding.is_immediate & (1 << 2)) >> 2) * sizeof(u32);

        *(u64*) it = encoding.immediate;
        it += ((encoding.is_immediate & (1 << 3)) >> 3) * sizeof(u64);

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
#endif
        it += instruction_length;
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
        default: return (String){};
    }
}

STRUCT(Opcode)
{
    u8 length;
    u8 bytes[4];
};

ENUM(OperandId, u8,
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
);

#define operand_kind_array_element_count (4)

fn String operand_to_string(OperandId operand_id)
{
    switch (operand_id)
    {
        case_to_name(op_, none);
        case_to_name(op_, ra8);
        case_to_name(op_, ra16);
        case_to_name(op_, ra32);
        case_to_name(op_, ra64);
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
    }
}

STRUCT(Operands)
{
    OperandId values[operand_kind_array_element_count];
    u8 count;
};

STRUCT(Encoding)
{
    Operands operands;
    Opcode opcode;
};
decl_vb(Encoding);

STRUCT(Batch)
{
    Mnemonic_x86_64 mnemonic;
    u32 encoding_offset;
    u32 encoding_count;
};
decl_vb(Batch);

fn u8 op_is_gpra(OperandId operand_kind)
{
    return operand_kind >= op_ra8 && operand_kind <= op_ra64;
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

fn u8 op_rm_get_index(OperandId operand_kind)
{
    assert(op_is_rm(operand_kind));
    return operand_kind - op_rm8;
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
        strlit("0x10"),
        strlit("0x1000"),
        strlit("0x10000000"),
        strlit("0x1000000000000000"),
    };

    return strings[index];
}

fn u64 sample_immediate_values(u8 index)
{
    global_variable const u64 immediates[] = {
        0x10,
        0x1000,
        0x10000000,
        0x1000000000000000,
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

fn String format_displacement(String buffer, String register_string, String displacement_string, u8 register_index, u8 omit_displacement)
{
    u64 length = 0;
    String result = {
        .pointer = buffer.pointer,
    };

    const String indirect_types[] = {
        strlit("BYTE PTR "),
        strlit("WORD PTR "),
        strlit("DWORD PTR "),
        strlit("QWORD PTR "),
    };

    String indirect_type = indirect_types[register_index];

    memcpy(&buffer.pointer[length], indirect_type.pointer, indirect_type.length);
    length += indirect_type.length;

    buffer.pointer[length] = '[';
    length += 1;

    memcpy(&buffer.pointer[length], register_string.pointer, register_string.length);
    length += register_string.length;

    buffer.pointer[length] = '+';
    length += !omit_displacement;

    memcpy(&buffer.pointer[length], displacement_string.pointer, displacement_string.length);
    length += displacement_string.length * !omit_displacement;

    buffer.pointer[length] = ']';
    length += 1;

    result.length = length;

    return result;
}

fn String clang_compile_assembly(Arena* arena, String instruction_text, String clang_path)
{
    String my_assembly_path = strlit(BUILD_DIR "/my_assembly_source.S");
    FileWriteOptions options = {
        .path = my_assembly_path,
        .content = instruction_text,
    };
    file_write(options);

    String out_path = strlit(BUILD_DIR "/my_assembly_output");

    char* arguments[] = {
        string_to_c(clang_path),
        string_to_c(my_assembly_path),
        "-o",
        string_to_c(out_path),
        "-masm=intel",
        "-nostdlib",
        "-Wl,--oformat=binary",
        0,
    };
    RunCommandOptions run_options = {
        .capture_stderr = 1,
    };
    RunCommandResult result = run_command(arena, (CStringSlice)array_to_slice(arguments), environment_pointer, run_options);
    let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0);
    if (!success)
    {
        print("Clang failed: {s}\n", result.stderr_string);
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
    String objdump_path;
    u64 gross:1;
};

fn String disassemble_binary(Arena* arena, DisassemblyArguments arguments)
{
    assert(arguments.binary.length);
    String binary_path = strlit(BUILD_DIR "/my_binary_path");
    FileWriteOptions options = {
        .path = binary_path,
        .content = arguments.binary,
    };
    file_write(options);

    char* arguments_gross[] = {
        string_to_c(arguments.objdump_path),
        "-D",
        string_to_c(binary_path),
        "-m",
        "i386:x86-64:intel",
        "-b",
        "binary",
        "--disassemble-zeroes",
        0,
    };
    CStringSlice arguments_gross_slice = array_to_slice(arguments_gross);

    char* arguments_pruned[] = {
        string_to_c(arguments.objdump_path),
        "-D",
        string_to_c(binary_path),
        "--no-addresses",
        "--no-show-raw-insn",
        "-m",
        "i386:x86-64:intel",
        "-b",
        "binary",
        "--disassemble-zeroes",
        0,
    };
    CStringSlice arguments_pruned_slice = array_to_slice(arguments_pruned);
    RunCommandOptions run_options = {
        .capture_stdout = 1,
    };
    RunCommandResult run_result = run_command(arena, arguments.gross ? arguments_gross_slice : arguments_pruned_slice, environment_pointer, run_options);
    let(success, run_result.termination_kind == PROCESS_TERMINATION_EXIT && run_result.termination_code == 0);
    if (!success)
    {
        todo();
    }

    String search_token = strlit("<.data>:\n");
    let(index, string_first_occurrence(run_result.stdout_string, search_token));
    assert(index != STRING_NO_MATCH);
    String result = s_get_slice(u8, run_result.stdout_string, index + search_token.length, run_result.stdout_string.length);
    if (result.pointer[0] == '\t')
    {
        result.pointer += 1;
        result.length -= 1;
    }


    if (!arguments.gross)
    {
        index = string_first_ch(result, '\n');
        assert(index != STRING_NO_MATCH);
        result = s_get_slice(u8, result, 0, index);

        u8 buffer[256];
        u64 buffer_i = 0;

        u64 i = 0;
        while (result.pointer[i] != '\n' && result.pointer[i] != ' ')
        {
            i += 1;
        }

        String mnemonic = s_get_slice(u8, result, 0, i);
        memcpy(buffer + buffer_i, mnemonic.pointer, mnemonic.length);
        buffer_i += mnemonic.length;

        if (i != result.length)
        {
            buffer[buffer_i] = ' ';
            buffer_i += 1;

            while (result.pointer[i] != '\n')
            {
                while (result.pointer[i] == ' ')
                {
                    i += 1;
                }

                u64 operand_start = i;
                while (result.pointer[i] != ',' && result.pointer[i] != '\n')
                {
                    i += 1;
                }

                u64 operand_end = i;

                String operand = s_get_slice(u8, result, operand_start, operand_end);
                memcpy(buffer + buffer_i, operand.pointer, operand.length);
                buffer_i += operand.length;

                u8 more_operands_left = result.pointer[i] == ',';
                i += more_operands_left;

                buffer[buffer_i] = ',';
                buffer_i += more_operands_left;

                buffer[buffer_i] = ' ';
                buffer_i += more_operands_left;
            }
        }

        result = arena_duplicate_string(arena, (String) { .pointer = buffer, .length = buffer_i } );
    }

    return result;
}

STRUCT(CheckInstructionArguments)
{
    String objdump_path;
    String clang_path;
    String text;
    String binary;
    String error_buffer;
    u64* error_buffer_length;
    u64 check_text:1;
    u64 reserved:63;
};

fn u64 check_instruction(Arena* arena, CheckInstructionArguments arguments)
{
    StringFormatter error_buffer = {
        .buffer = arguments.error_buffer,
    };

    u8 result = 1;

    if (!arguments.check_text)
    {
        DisassemblyArguments disassemble_arguments = {
            .binary = arguments.binary,
            .objdump_path = arguments.objdump_path,
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
            formatter_append_string(&error_buffer, strlit("Failed to match correct output. Got:\n\t"));
            todo();

            for (u64 bin_i = 0; bin_i < arguments.binary.length; bin_i += 1)
            {
                formatter_append(&error_buffer, "0x{u32:x,w=2} ", (u32)arguments.binary.pointer[bin_i]);
            }

            formatter_append_character(&error_buffer, '\n');

            String clang_binary = clang_compile_assembly(arena, arguments.text, arguments.clang_path);
            if (clang_binary.pointer)
            {
                formatter_append_string(&error_buffer, strlit("While clang generated the following:\n\t"));

                for (u64 bin_i = 0; bin_i < clang_binary.length; bin_i += 1)
                {
                    formatter_append(&error_buffer, "0x{u32:x,w=2} ", (u32)clang_binary.pointer[bin_i]);
                }
                formatter_append_character(&error_buffer, '\n');
            }
            else
            {
                todo();
            }
        }
    }
    else
    {
        String clang_binary = clang_compile_assembly(arena, arguments.text, arguments.clang_path);
        String my_binary = arguments.binary;
        unused(clang_binary);
        unused(my_binary);
        todo();
    }

    assert(!!error_buffer.index == !result);

    return error_buffer.index;
}

fn u8 encoding_test_instruction_batches(Arena* arena, TestDataset dataset)
{
    u8 result = 0;
    u8 instruction_binary_buffer[256];
    u8 instruction_text_buffer[256];
    String instruction_text_buffer_slice = array_to_slice(instruction_text_buffer);
    u8 error_buffer[4096];
    String error_buffer_slice = array_to_slice(error_buffer);

    String clang_path = executable_find_in_path(arena, strlit("clang"), cstr(getenv("PATH")));
    assert(clang_path.pointer);

    String objdump_path = executable_find_in_path(arena, strlit("objdump"), cstr(getenv("PATH")));
    assert(objdump_path.pointer);

    for (u64 batch_index = 0; batch_index < dataset.batch_count; batch_index += 1)
    {
        let(batch, &dataset.batches[batch_index]);

        String mnemonic_string = mnemonic_x86_64_to_string(batch->mnemonic);
        print("============================\n~~~~~~~ MNEMONIC {s} ~~~~~~~\n============================\n", mnemonic_string);

        u64 encoding_top = batch->encoding_offset + batch->encoding_count;

        for (u64 encoding_index = batch->encoding_offset; encoding_index < encoding_top; encoding_index += 1)
        {
            let(encoding, &dataset.encodings[encoding_index]);
            OperandId first_operand = encoding->operands.values[0];
            OperandId second_operand = encoding->operands.values[1];
            let(operand_count, encoding->operands.count);

            u64 instance_index = 0;
            u64 failure_count = 0;
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

                // let(current_length, encoding_buffer_i);

                // encoding_buffer[encoding_buffer_i] = '\n';
                // encoding_buffer_i += 1;
                //
                // for (u64 ei = 0; ei < current_length; ei += 1)
                // {
                //     encoding_buffer[encoding_buffer_i] = '-';
                //     encoding_buffer_i += 1;
                // }

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
                todo();
            }
            else if (op_is_gpra(first_operand))
            {
                let(register_a_index, first_operand - op_ra8);
                String register_a_names[] = {
                    strlit("al"),
                    strlit("ax"),
                    strlit("eax"),
                    strlit("rax"),
                };
                String first_operand_register_name = register_a_names[register_a_index];
                String first_operand_string = first_operand_register_name;

                switch (operand_count)
                {
                    case 1:
                        {
                            todo();
                        } break;
                    case 2:
                        {
                            assert(op_is_imm(second_operand));
                            let(imm_index, op_imm_get_index(second_operand));
                            // We output the string directly to avoid formatting cost
                            String second_operand_string = sample_immediate_strings(imm_index);
                            u64 immediate = sample_immediate_values(imm_index);
                            String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                            InstructionEncoding batch_encoding = {
                                .is_64_bit = register_a_index == 3,
                                .has_rex = 0,
                                .scaled_index_register = 0,
                                .is_reg1 = 0,
                                .is_reg2 = 0,
                                .is_indirect1 = 0,
                                .is_indirect2 = 0,
                                .is_immediate = 1 << imm_index,
                                .is_16_mode = register_a_index == 1,
                                .immediate = immediate,
                                .displacement = 0,
                                .opcode = encoding->opcode.bytes[0],
                                .reg1 = 0,
                                .reg2 = 0,
                                .sib_scale = 0,
                                .sib_index = 0,
                                .sib_base = 0,
                            };
                            u16 length = encode_instruction_batch(instruction_binary_buffer, &batch_encoding, 1);
                            String instruction_bytes = {
                                .pointer = instruction_binary_buffer,
                                .length = length,
                            };
                            CheckInstructionArguments check_args = {
                                .clang_path = clang_path,
                                .objdump_path = objdump_path,
                                .text = instruction_string,
                                .binary = instruction_bytes,
                                .error_buffer = error_buffer_slice,
                            };
                            u64 error_buffer_length = check_instruction(arena, check_args);
                            instance_index += 1;
                            let(first_failure, failure_count == 0);
                            failure_count += error_buffer_length != 0;
                            String error_string = { .pointer = error_buffer, .length = error_buffer_length };
                            if (error_buffer_length != 0)
                            {
                                print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", instance_index, instruction_string, error_string);
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
                            todo();
                        } break;
                    case 2:
                        {
                            s32 displacements[] = {
                                0,
                                0x10,
                                0x10000000,
                            };

                            String displacement_strings[] = {
                                strlit("0x0"),
                                strlit("0x10"),
                                strlit("0x10000000"),
                            };

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
                                            u8 omit_displacement = displacements[displacement_index] == 0 && (gpr & 0b111) != REGISTER_X86_64_BP;
                                            first_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(first_rm_buffer[gpr][displacement_index]), first_operand_rm_name, displacement_strings[displacement_index], first_operand_index, omit_displacement);
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
                                                u8 omit_displacement = displacements[displacement_index] == 0 && (gpr & 0b111) != REGISTER_X86_64_BP;
                                                second_rm_strings[gpr][displacement_index] = format_displacement((String)array_to_slice(second_rm_buffer[gpr][displacement_index]), second_operand_rm_name, displacement_strings[displacement_index], second_operand_index, omit_displacement);
                                            }
                                        }
                                    }

                                    if (first_is_rm)
                                    {
                                        for (GPR_x86_64 first_gpr = 0; first_gpr < first_operand_register_count; first_gpr += 1)
                                        {
                                            String first_operand_string = gpr_to_string(first_gpr, first_operand_index, 0);

                                            for (GPR_x86_64 second_gpr = 0; second_gpr < second_operand_register_count; second_gpr += 1)
                                            {
                                                String second_operand_string = gpr_to_string(second_gpr, second_operand_index, 0);
                                                String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                                                InstructionEncoding batch_encoding = {
                                                    .is_64_bit = first_operand_index == 3,
                                                    .has_rex = 0,
                                                    .scaled_index_register = 0,
                                                    .is_reg1 = 1,
                                                    .is_reg2 = 1,
                                                    .is_indirect1 = 0,
                                                    .is_indirect2 = 0,
                                                    .is_immediate = 0,
                                                    .is_16_mode = first_operand_index == 1,
                                                    .immediate = 0,
                                                    .displacement = 0,
                                                    .opcode = encoding->opcode.bytes[0],
                                                    .reg1 = first_gpr,
                                                    .reg2 = second_gpr,
                                                    .sib_scale = 0,
                                                    .sib_index = 0,
                                                    .sib_base = 0,
                                                };
                                                u16 length = encode_instruction_batch(instruction_binary_buffer, &batch_encoding, 1);
                                                String instruction_bytes = {
                                                    .pointer = instruction_binary_buffer,
                                                    .length = length,
                                                };
                                                CheckInstructionArguments check_args = {
                                                    .clang_path = clang_path,
                                                    .objdump_path = objdump_path,
                                                    .text = instruction_string,
                                                    .binary = instruction_bytes,
                                                    .error_buffer = error_buffer_slice,
                                                    // .check_text = !first_is_rm && second_is_rm,
                                                };
                                                u64 error_buffer_length = check_instruction(arena, check_args);
                                                instance_index += 1;
                                                let(first_failure, failure_count == 0);
                                                failure_count = error_buffer_length != 0;
                                                String error_string = { .pointer = error_buffer, .length = error_buffer_length };
                                                if (error_buffer_length != 0)
                                                {
                                                    print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", instance_index, instruction_string, error_string);
                                                }
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
                                                    String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                                                    InstructionEncoding batch_encoding = {
                                                        .is_64_bit = first_operand_index == 3,
                                                        .has_rex = 0,
                                                        .scaled_index_register = 0,
                                                        .is_reg1 = 1,
                                                        .is_reg2 = 1,
                                                        .is_indirect1 = 1,
                                                        .is_indirect2 = 0,
                                                        .is_immediate = 0,
                                                        .is_16_mode = first_operand_index == 1,
                                                        .immediate = 0,
                                                        .displacement = displacements[displacement_index],
                                                        .opcode = encoding->opcode.bytes[0],
                                                        .reg1 = first_gpr,
                                                        .reg2 = second_gpr,
                                                        .sib_scale = 0,
                                                        .sib_index = 0b100,
                                                        .sib_base = (first_gpr & 0b111) == REGISTER_X86_64_SP ? first_gpr : 0,
                                                    };
                                                    u16 length = encode_instruction_batch(instruction_binary_buffer, &batch_encoding, 1);
                                                    String instruction_bytes = {
                                                        .pointer = instruction_binary_buffer,
                                                        .length = length,
                                                    };
                                                    CheckInstructionArguments check_args = {
                                                        .clang_path = clang_path,
                                                        .objdump_path = objdump_path,
                                                        .text = instruction_string,
                                                        .binary = instruction_bytes,
                                                        .error_buffer = error_buffer_slice,
                                                        // .check_text = !first_is_rm && second_is_rm,
                                                    };
                                                    u64 error_buffer_length = check_instruction(arena, check_args);
                                                    instance_index += 1;
                                                    let(first_failure, failure_count == 0);
                                                    failure_count = error_buffer_length != 0;
                                                    String error_string = { .pointer = error_buffer, .length = error_buffer_length };
                                                    if (error_buffer_length != 0)
                                                    {
                                                        print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", instance_index, instruction_string, error_string);
                                                    }
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
                                                for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                                {
                                                    String second_operand_string = second_rm_strings[second_gpr][displacement_index];
                                                    String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                                                    unused(instruction_string);
                                                }
                                            }
                                        }
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
                                        String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                                        InstructionEncoding batch_encoding = {
                                            .is_64_bit = first_operand_index == 3,
                                            .has_rex = 0,
                                            .scaled_index_register = 0,
                                            .is_reg1 = 1,
                                            .is_reg2 = 0,
                                            .is_indirect1 = 0,
                                            .is_indirect2 = 0,
                                            .is_immediate = 1 << second_operand_index,
                                            .is_16_mode = first_operand_index == 1,
                                            .immediate = immediate,
                                            .displacement = 0,
                                            .opcode = encoding->opcode.bytes[0],
                                            .reg1 = first_gpr,
                                            .reg2 = 0,
                                            .sib_scale = 0,
                                            .sib_index = 0,
                                            .sib_base = 0,
                                        };
                                        u16 length = encode_instruction_batch(instruction_binary_buffer, &batch_encoding, 1);
                                        String instruction_bytes = {
                                            .pointer = instruction_binary_buffer,
                                            .length = length,
                                        };
                                        CheckInstructionArguments check_args = {
                                            .clang_path = clang_path,
                                            .objdump_path = objdump_path,
                                            .text = instruction_string,
                                            .binary = instruction_bytes,
                                            .error_buffer = error_buffer_slice,
                                        };
                                        u64 error_buffer_length = check_instruction(arena, check_args);
                                        instance_index += 1;
                                        let(first_failure, failure_count == 0);
                                        failure_count += error_buffer_length != 0;
                                        String error_string = { .pointer = error_buffer, .length = error_buffer_length };
                                        if (error_buffer_length != 0)
                                        {
                                            print("{cstr}{u64}) {s}... [FAILED]\n{s}\n", first_failure ? "\n" : "", instance_index, instruction_string, error_string);
                                        }
                                    }

                                    if (first_is_rm)
                                    {
                                        for (GPR_x86_64 gpr = 0; gpr < X86_64_GPR_COUNT; gpr += 1)
                                        {
                                            for (u32 displacement_index = 0; displacement_index < array_length(displacements); displacement_index += 1)
                                            {
                                                String first_operand_string = first_rm_strings[gpr][displacement_index];
                                                String instruction_string = format_instruction2(instruction_text_buffer_slice, mnemonic_string, first_operand_string, second_operand_string);
                                                unused(instruction_string);
                                            }
                                        }
                                    }
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

            if (failure_count)
            {
                print("{s}... [FAILED] {u64}/{u64} failures\n", encoding_string, failure_count, instance_index);
            }
            else
            {
                print_string(strlit("[OK]\n"));
            }

            print_string(encoding_separator_string);
            print_string(strlit("\n"));
        }
    }

    return result;
}

#define batch_start(_mnemonic) Mnemonic_x86_64 batch_mnemonic = MNEMONIC_x86_64_ ## _mnemonic; u32 encoding_offset = encodings.length
#define encode(_opcode, _operands)\
    do{\
        Encoding encoding = {\
            .opcode = _opcode,\
            .operands = _operands,\
        };\
        *vb_add(&encodings, 1) = encoding;\
    } while (0)

#define batch_end() *vb_add(&batches, 1) = (Batch) { .mnemonic = batch_mnemonic, .encoding_offset = encoding_offset, .encoding_count = encodings.length - encoding_offset, }
#define ops(...) ((Operands){ .values = { __VA_ARGS__ }, .count = array_length(((OperandId[]){ __VA_ARGS__ })), })
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
    VirtualBuffer(Batch) batches = {};
    VirtualBuffer(Encoding) encodings = {};

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
        .batches = batches.pointer,
        .batch_count = batches.length,
        .encodings = encodings.pointer,
        .encoding_count = encodings.length,
    };
    return result;
}

int main(int argc, char** argv, char** envp)
{
    unused(argc);
    unused(argv);

    environment_pointer = envp;

    TestDataset dataset = construct_test_cases();
    Arena* arena = arena_initialize_default(MB(2));
    u8 result = encoding_test_instruction_batches(arena, dataset);
    return result;
}
