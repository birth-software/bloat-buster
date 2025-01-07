#include <std/base.h>
#include <std/os.h>

#include <std/base.c>
#include <std/os.c>

#if 0
#include <std/project.h>
#include <std/virtual_buffer.h>
#include <std/windowing.h>
#include <std/rendering.h>
#include <std/ui_core.h>
#include <std/ui_builder.h>

#include <std/os.c>
#include <std/virtual_buffer.c>
#include <std/windowing.c>
#include <std/rendering.c>
#include <std/ui_core.c>
#include <std/ui_builder.c>

#define default_font_height (24)
global_variable u32 proportional_font_height = default_font_height;
global_variable u32 monospace_font_height = default_font_height;

fn TextureIndex white_texture_create(Arena* arena, Renderer* renderer)
{
    u32 white_texture_width = 1024;
    u32 white_texture_height = white_texture_width;
    let(white_texture_buffer, arena_allocate(arena, u32, white_texture_width * white_texture_height));
    memset(white_texture_buffer, 0xff, white_texture_width * white_texture_height * sizeof(u32));

    let(white_texture, renderer_texture_create(renderer, (TextureMemory) {
        .pointer = white_texture_buffer,
        .width = white_texture_width,
        .height = white_texture_height,
        .depth = 1,
        .format = TEXTURE_FORMAT_R8G8B8A8_SRGB,
    }));

    return white_texture;
}

STRUCT(BBPanel)
{
    BBPanel* first;
    BBPanel* last;
    BBPanel* next;
    BBPanel* previous;
    BBPanel* parent;
    f32 parent_percentage;
    Axis2 split_axis;
};

STRUCT(BBWindow)
{
    WindowingInstance* handle;
    RenderWindow* render;
    BBWindow* previous;
    BBWindow* next;
    BBPanel* root_panel;
    UI_State* ui;
};

STRUCT(BBGUIState)
{
    Arena* arena;
    Timestamp last_frame_timestamp;
    BBWindow* first_window;
    BBWindow* last_window;
    Renderer* renderer;
    // TODO: should this not be thread local?
    WindowingEventQueue event_queue;
};
global_variable BBGUIState state;

fn void ui_top_bar()
{
    ui_push(pref_height, ui_em(1, 1));
    {
        ui_push(child_layout_axis, AXIS2_X);
        let(top_bar, ui_widget_make((UI_WidgetFlags) {
                }, strlit("top_bar")));
        ui_push(parent, top_bar);
        {
            ui_button(strlit("Button 1"));
            ui_button(strlit("Button 2"));
            ui_button(strlit("Button 3"));
        }
        ui_pop(parent);
        ui_pop(child_layout_axis);
    }
    ui_pop(pref_height);
}

STRUCT(UI_Node)
{
    String name;
    String type;
    String value;
    String namespace;
    String function;
};

fn void ui_node(UI_Node node)
{
    let(node_widget, ui_widget_make_format((UI_WidgetFlags) {
        .draw_background = 1,
        .draw_text = 1,
    }, "{s} : {s} = {s}##{s}{s}", node.name, node.type, node.value, node.function, node.namespace));
}

fn void app_update()
{
    let(frame_end, os_timestamp());
    windowing_poll_events(/* &state.event_queue */);
    let(frame_ms, os_resolve_timestamps(state.last_frame_timestamp, frame_end, TIME_UNIT_MILLISECONDS));
    state.last_frame_timestamp = frame_end;

    Renderer* renderer = state.renderer;

    BBWindow* window = state.first_window;
    while (likely(window))
    {
        let(previous, window->previous);
        let(next, window->next);

        let(render_window, window->render);
        renderer_window_frame_begin(renderer, render_window);

        ui_state_select(window->ui);

        if (likely(ui_build_begin(window->handle, frame_ms, &state.event_queue)))
        {
            ui_push(font_size, default_font_height);

            ui_top_bar();
            ui_push(child_layout_axis, AXIS2_X);
            let(workspace_widget, ui_widget_make_format((UI_WidgetFlags) {}, "workspace{u64}", window->handle));
            ui_push(parent, workspace_widget);
            {
                // Node visualizer
                ui_push(child_layout_axis, AXIS2_Y);
                let(node_visualizer_widget, ui_widget_make_format((UI_WidgetFlags) {
                    .draw_background = 1,
                }, "node_visualizer{u64}", window->handle));

                ui_push(parent, node_visualizer_widget);
                {
                    ui_node((UI_Node) {
                        .name = strlit("a"),
                        .type = strlit("s32"),
                        .value = strlit("1"),
                        .namespace = strlit("foo"),
                        .function = strlit("main"),
                    });
                    ui_node((UI_Node) {
                        .name = strlit("b"),
                        .type = strlit("s32"),
                        .value = strlit("2"),
                        .namespace = strlit("foo"),
                        .function = strlit("main"),
                    });
                }
                ui_pop(parent);
                ui_pop(child_layout_axis);

                // Side-panel stub
                ui_button(strlit("Options"));
            }
            ui_pop(parent);
            ui_pop(child_layout_axis);

            ui_build_end();

            ui_draw();

            ui_pop(font_size);

            renderer_window_frame_end(renderer, render_window);
        }
        else
        {
            if (previous)
            {
                previous->next = next;
            }

            if (next)
            {
                next->previous = previous;
            }

            if (state.first_window == window)
            {
                state.first_window = next;
            }

            if (state.last_window == window)
            {
                state.last_window = previous;
            }
        }

        window = next;
    }
}

fn void window_refresh_callback(WindowingInstance* window, void* context)
{
    unused(window);
    unused(context);
    app_update();
}

int main()
{
    state.arena = arena_initialize_default(MB(2));
    if (!windowing_initialize())
    {
        return 1;
    }

    state.renderer = rendering_initialize(state.arena);
    if (!state.renderer)
    {
        return 1;
    }

    WindowingInstantiate window_create_options = {
        .name = strlit("Bloat Buster"),
        .size = { .width = 1600, .height = 900 },
    };
    state.first_window = state.last_window = arena_allocate(state.arena, BBWindow, 1);
    state.first_window->handle = windowing_instantiate(window_create_options);

    state.first_window->render = rendering_initialize_window(state.renderer, state.first_window->handle);

    state.first_window->ui = ui_state_allocate(state.renderer, state.first_window->render);
    state.first_window->root_panel = arena_allocate(state.arena, BBPanel, 1);
    state.first_window->root_panel->parent_percentage = 1.0f;
    state.first_window->root_panel->split_axis = AXIS2_X;

#ifndef __APPLE__
    window_rect_texture_update_begin(state.first_window->render);

    let(white_texture, white_texture_create(state.arena, state.renderer));
    TextureAtlasCreate monospace_font_create = {
#ifdef _WIN32
        .font_path = strlit("C:/Users/David/Downloads/Fira_Sans/FiraSans-Regular.ttf"),
#elif defined(__linux__)
        .font_path = strlit("/usr/share/fonts/TTF/FiraSans-Regular.ttf"),
#elif defined(__APPLE__)
        .font_path = strlit("/Users/david/Library/Fonts/FiraSans-Regular.ttf"),
#else
        .font_path = strlit("WRONG_PATH"),
#endif
        .text_height = monospace_font_height,
    };
    let(monospace_font, font_texture_atlas_create(state.arena, state.renderer, monospace_font_create));
    let(proportional_font, monospace_font);

    window_queue_rect_texture_update(state.first_window->render, RECT_TEXTURE_SLOT_WHITE, white_texture);
    renderer_queue_font_update(state.renderer, state.first_window->render, RENDER_FONT_TYPE_MONOSPACE, monospace_font);
    renderer_queue_font_update(state.renderer, state.first_window->render, RENDER_FONT_TYPE_PROPORTIONAL, proportional_font);

    window_rect_texture_update_end(state.renderer, state.first_window->render);
#endif

    state.last_frame_timestamp = os_timestamp();

    while (state.first_window)
    {
        app_update();
    }

    return 0;
}
#else

global_variable const u8 operand_size_override_prefix = 0x66;
// global_variable const u8 address_size_override_prefix = 0x67;

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

fn u64 encode_instructions(u8* restrict output, InstructionEncoding* restrict encodings, u64 encoding_count)
{
    u8* restrict it = output;
    for (u64 i = 0; i < encoding_count; i += 1)
    {
        InstructionEncoding encoding = encodings[i];

        *it = operand_size_override_prefix;
        it += encoding.is_16_mode;

        u8 rex_base = 0x40;
        u8 rex_b = 0x01;
        u8 rex_x = 0x02;
        u8 rex_r = 0x04;
        u8 rex_w = 0x08;
        u8 byte_rex_b = rex_b * ((encoding.reg1 & 0b1000) != 0);
        u8 byte_rex_x = rex_x * encoding.scaled_index_register;
        u8 byte_rex_r = rex_r * ((encoding.reg2 & 0b1000) != 0);
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
    }

    u64 length = (u64)(it - output);
    return length;
}

STRUCT(EncodingTestCase)
{
    InstructionEncoding encoding;
    String expected;
    String text;
};

fn u8 encoding_test_all(EncodingTestCase* restrict test_cases, u64 test_case_count)
{
    u8 buffer[256];
    u8 result = 0;

    for (u64 i = 0; i < test_case_count; i += 1)
    {
        print("{s}... ", test_cases[i].text);
        u64 length = encode_instructions(buffer, &test_cases[i].encoding, 1);
        String expected = test_cases[i].expected;
        u8 error = length != expected.length;

        u64 error_byte = length;
        if (!error)
        {
            for (u64 i = 0; i < length; i += 1)
            {
                if (buffer[i] != expected.pointer[i])
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

            if (length != expected.length)
            {
                print("error: mismatch in the length of the instruction\n");
            }

            if (error_byte != length)
            {
                print("error: byte {u64} does not match. Expected: 0x{u32:x}. Produced: 0x{u32:x}\n", error_byte, (u32)expected.pointer[error_byte], (u32)buffer[error_byte]);
            }

            print("Expected {u64} bytes:\n", expected.length);

            for (u64 i = 0; i < expected.length; i += 1)
            {
                print("0x{u32:x} ", (u32)expected.pointer[i]);
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

    return result;
}

int main(int argc, char** argv, char** envp)
{
    unused(argc);
    unused(argv);
    unused(envp);

#define immediate8_literal  0x10
#define immediate16_literal 0x1000
#define immediate32_literal 0x10000000
#define immediate64_literal 0x1000000000000000

#define immediate8_string  "0x10"
#define immediate16_string "0x1000"
#define immediate32_string "0x10000000"
#define immediate64_string "0x1000000000000000"

#define immediate8_array  0x10,
#define immediate16_array 0x00, 0x10,
#define immediate32_array 0x00, 0x00, 0x00, 0x10,
#define immediate64_array 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,

#define stringify(x) #x

    EncodingTestCase test_cases[] = {
        {
            .encoding = {
                .opcode = 0x04,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x04, immediate8_array })),
            .text = strlit("add al, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x05,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x05, immediate16_array })),
            .text = strlit("add ax, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x05,
                .is_immediate32 = 1,
                .immediate32 = immediate32_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x05, immediate32_array })),
            .text = strlit("add eax, " immediate32_string),
        },
        {
            .encoding = {
                .opcode = 0x05,
                .is_immediate32 = 1,
                .immediate32 = immediate32_literal,
                .is_64_bit = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x48, 0x05, immediate32_array })),
            .text = strlit("add rax, " immediate32_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_AL,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc0, immediate8_array })),
            .text = strlit("add al, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_CL,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc1, immediate8_array })),
            .text = strlit("add cl, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_DL,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc2, immediate8_array })),
            .text = strlit("add dl, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_BL,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc3, immediate8_array })),
            .text = strlit("add bl, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_AH,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc4, immediate8_array })),
            .text = strlit("add ah, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_CH,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc5, immediate8_array })),
            .text = strlit("add ch, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_DH,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc6, immediate8_array })),
            .text = strlit("add dh, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_BH,
                .is_reg1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0xc7, immediate8_array })),
            .text = strlit("add bh, " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RAX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x00, immediate8_array })),
            .text = strlit("add byte ptr [rax], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RCX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x01, immediate8_array })),
            .text = strlit("add byte ptr [rcx], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RDX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x02, immediate8_array })),
            .text = strlit("add byte ptr [rdx], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RBX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x03, immediate8_array })),
            .text = strlit("add byte ptr [rbx], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RSP,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
                .sib_base = REGISTER_X86_64_RSP,
                .sib_index = 0b100,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x04, 0x24, immediate8_array })),
            .text = strlit("add byte ptr [rsp], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RBP,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x45, 0x00, immediate8_array })),
            .text = strlit("add byte ptr [rbp], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RSI,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x06, immediate8_array })),
            .text = strlit("add byte ptr [rsi], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_RDI,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x80, 0x07, immediate8_array })),
            .text = strlit("add byte ptr [rdi], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R8,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x00, immediate8_array })),
            .text = strlit("add byte ptr [r8], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R9,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x01, immediate8_array })),
            .text = strlit("add byte ptr [r9], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R10,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x02, immediate8_array })),
            .text = strlit("add byte ptr [r10], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R11,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x03, immediate8_array })),
            .text = strlit("add byte ptr [r11], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R12,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
                .sib_base = REGISTER_X86_64_R12,
                .sib_index = 0b100,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x04, 0x24, immediate8_array })),
            .text = strlit("add byte ptr [r12], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R13,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x45, 0x00, immediate8_array })),
            .text = strlit("add byte ptr [r13], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R14,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x06, immediate8_array })),
            .text = strlit("add byte ptr [r14], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x80,
                .reg1 = REGISTER_X86_64_R15,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate8 = 1,
                .immediate8 = immediate8_literal,
            },
            .expected = array_to_bytes(((u8[]){ 0x41, 0x80, 0x07, immediate8_array })),
            .text = strlit("add byte ptr [r15], " immediate8_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_AX,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc0, immediate16_array })),
            .text = strlit("add ax, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_CX,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc1, immediate16_array })),
            .text = strlit("add cx, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_DX,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc2, immediate16_array })),
            .text = strlit("add dx, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_BX,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc3, immediate16_array })),
            .text = strlit("add bx, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_SP,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc4, immediate16_array })),
            .text = strlit("add sp, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_BP,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc5, immediate16_array })),
            .text = strlit("add bp, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_SI,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc6, immediate16_array })),
            .text = strlit("add si, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_DI,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0xc7, immediate16_array })),
            .text = strlit("add di, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R8W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc0, immediate16_array })),
            .text = strlit("add r8w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R9W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc1, immediate16_array })),
            .text = strlit("add r9w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R10W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc2, immediate16_array })),
            .text = strlit("add r10w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R11W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc3, immediate16_array })),
            .text = strlit("add r11w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R12W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc4, immediate16_array })),
            .text = strlit("add r12w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R13W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc5, immediate16_array })),
            .text = strlit("add r13w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R14W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc6, immediate16_array })),
            .text = strlit("add r14w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R15W,
                .is_reg1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0xc7, immediate16_array })),
            .text = strlit("add r15w, " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RAX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x00, immediate16_array })),
            .text = strlit("add word ptr [rax], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RCX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x01, immediate16_array })),
            .text = strlit("add word ptr [rcx], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RDX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x02, immediate16_array })),
            .text = strlit("add word ptr [rdx], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RBX,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x03, immediate16_array })),
            .text = strlit("add word ptr [rbx], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RSP,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .sib_base = REGISTER_X86_64_RSP,
                .sib_index = 0b100,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x04, 0x24, immediate16_array })),
            .text = strlit("add word ptr [rsp], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RBP,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x45, 0x00, immediate16_array })),
            .text = strlit("add word ptr [rbp], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RSI,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x06, immediate16_array })),
            .text = strlit("add word ptr [rsi], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_RDI,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x81, 0x07, immediate16_array })),
            .text = strlit("add word ptr [rdi], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R8,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x00, immediate16_array })),
            .text = strlit("add word ptr [r8], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R9,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x01, immediate16_array })),
            .text = strlit("add word ptr [r9], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R10,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x02, immediate16_array })),
            .text = strlit("add word ptr [r10], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R11,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x03, immediate16_array })),
            .text = strlit("add word ptr [r11], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R12,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .sib_base = REGISTER_X86_64_R12,
                .sib_index = 0b100,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x04, 0x24, immediate16_array })),
            .text = strlit("add word ptr [r12], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R13,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x45, 0x00, immediate16_array })),
            .text = strlit("add word ptr [r13], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R14,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x06, immediate16_array })),
            .text = strlit("add word ptr [r14], " immediate16_string),
        },
        {
            .encoding = {
                .opcode = 0x81,
                .reg1 = REGISTER_X86_64_R15,
                .is_reg1 = 1,
                .is_indirect1 = 1,
                .is_immediate16 = 1,
                .immediate16 = immediate16_literal,
                .is_16_mode = 1,
            },
            .expected = array_to_bytes(((u8[]){ 0x66, 0x41, 0x81, 0x07, immediate16_array })),
            .text = strlit("add word ptr [r15], " immediate16_string),
        },
    };

    return encoding_test_all(test_cases, array_length(test_cases));
}
#endif
