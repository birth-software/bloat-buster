#pragma once

#include <std/base.h>
#include <std/window.h>
#include <std/os.h>
#include <std/render.h>

typedef enum UI_SizeKind : u8
{
    UI_SIZE_PIXEL_COUNT,
    UI_SIZE_PERCENTAGE,
    UI_SIZE_BY_CHILDREN,
    UI_SIZE_COUNT,
} UI_SizeKind;

STRUCT(UI_Size)
{
    UI_SizeKind kind;
    f32 value;
    f32 strictness;
};
static_assert(sizeof(UI_Size) == 12);
decl_vb(UI_Size);

STRUCT(UI_Key)
{
    u64 value;
};

STRUCT(UI_MousePosition)
{
    f64 x;
    f64 y;
};

typedef enum UI_WidgetFlagEnum : u64
{
    UI_WIDGET_FLAG_DISABLED                      = 1 << 0,
    UI_WIDGET_FLAG_MOUSE_CLICKABLE               = 1 << 1,
    UI_WIDGET_FLAG_KEYBOARD_PRESSABLE            = 1 << 2,
    UI_WIDGET_FLAG_DRAW_TEXT                     = 1 << 3,
    UI_WIDGET_FLAG_DRAW_BACKGROUND               = 1 << 4,
    UI_WIDGET_FLAG_OVERFLOW_X                    = 1 << 5,
    UI_WIDGET_FLAG_OVERFLOW_Y                    = 1 << 6,
    UI_WIDGET_FLAG_FLOATING_X                    = 1 << 7,
    UI_WIDGET_FLAG_FLOATING_Y                    = 1 << 8,
} UI_WidgetFlagEnum;

UNION(UI_WidgetFlags)
{
    struct
    {
        u64 disabled:1;
        u64 mouse_clickable:1;
        u64 keyboard_pressable:1;
        u64 draw_text:1;
        u64 draw_background:1;
        u64 overflow_x:1;
        u64 overflow_y:1;
        u64 floating_x:1;
        u64 floating_y:1;
    };
    u64 v;
};
static_assert(sizeof(UI_WidgetFlags) == sizeof(u64));

STRUCT(UI_Widget)
{
    // Random category I temporarily introduce
    String text;
    
    UI_Widget* hash_previous;
    UI_Widget* hash_next;

    UI_Widget* first;
    UI_Widget* last;
    UI_Widget* next;
    UI_Widget* previous;
    UI_Widget* parent;
    u64 child_count;

    UI_Key key;

    // Input parameters
    UI_Size pref_size[AXIS2_COUNT];
    Axis2 child_layout_axis;
    UI_WidgetFlags flags;

    // Data known after size determination happens
    float2 computed_size;
    float2 computed_relative_position;

    // Data known after layout computation happens
    F32Interval2 relative_rect;
    F32Interval2 rect;
    float2 relative_corner_delta[CORNER_COUNT];

    // Persistent data across frames
    u64 last_build_touched;
    float2 view_offset;
    float4 background_colors[4];
    float4 text_color;
};
decl_vbp(UI_Widget);

STRUCT(UI_WidgetSlot)
{
    UI_Widget* first;
    UI_Widget* last;
};
declare_slice(UI_WidgetSlot);

decl_vb(Axis2);
decl_vb(float4);

STRUCT(UI_StateStackAutoPops)
{
    u64 parent:1;
    u64 pref_width:1;
    u64 pref_height:1;
    u64 child_layout_axis:1;
    u64 text_color:1;
    u64 background_color:1;
    u64 font_size:1;
};
static_assert(sizeof(UI_StateStackAutoPops) % sizeof(u64) == 0);

STRUCT(UI_StateStackNulls)
{
    UI_Widget* parent;
    UI_Size pref_width;
    UI_Size pref_height;
    Axis2 child_layout_axis;
    float4 text_color;
    float4 background_color;
    f32 font_size;
};

STRUCT(UI_StateStacks)
{
    VirtualBufferP(UI_Widget) parent;
    VirtualBuffer(UI_Size) pref_width;
    VirtualBuffer(UI_Size) pref_height;
    VirtualBuffer(Axis2) child_layout_axis;
    VirtualBuffer(float4) text_color;
    VirtualBuffer(float4) background_color;
    VirtualBuffer(f32) font_size;
};

STRUCT(UI_State)
{
    Arena* arena;
    Arena* build_arenas[2];
    Renderer* renderer;
    RenderWindow* render_window;
    OSWindow os_window;
    u64 build_count;
    f64 frame_time;
    UI_Widget* root;
    UI_MousePosition mouse_position;
    Slice(UI_WidgetSlot) widget_table;
    UI_Widget* free_widget_list;
    u64 free_widget_count;
    OSEventMouseButtonEvent mouse_button_events[OS_EVENT_MOUSE_BUTTON_COUNT];
    u8 focused:1;

    UI_StateStacks stacks;
    UI_StateStackNulls stack_nulls;
    UI_StateStackAutoPops stack_autopops;
};

enum
{
    UI_SignalFlag_ClickedLeft = (1 << 0),
};

typedef u32 UI_SignalFlags;

STRUCT(UI_Signal)
{
    UI_Widget* widget;
    union
    {
        UI_SignalFlags flags;
        struct
        {
            u32 clicked_left:1;
            u32 reserved:31;
        };
    };
};

extern UI_State* ui_state;

#define ui_stack_autopop_set(field_name, value) ui_state->stack_autopops.field_name = (value)
#define ui_stack_push_impl(field_name, value, auto_pop_value) do \
{\
    *vb_add(&ui_state->stacks.field_name, 1) = (value);\
    ui_stack_autopop_set(field_name, auto_pop_value);\
} while (0)

fn u8* ui_pop_generic(VirtualBuffer(u8)* stack, u32 element_size)
{
    auto length = stack->length;

    assert(length > 0);
    auto next_length = length - 1;
    auto index = next_length;
    auto* result = &stack->pointer[index * element_size];
    stack->length = next_length;

    return result;
}

#define ui_push(field_name, value) ui_stack_push_impl(field_name, value, 0)
#define ui_push_next_only(field_name, value) ui_stack_push_impl(field_name, value, 1)
#define ui_pop(field_name) (typeof(ui_state->stacks.field_name.pointer)) ui_pop_generic((VirtualBuffer(u8)*)&ui_state->stacks.field_name, sizeof(*ui_state->stacks.field_name.pointer))
#define ui_top(field_name) (ui_state->stacks.field_name.length ? ui_state->stacks.field_name.pointer[ui_state->stacks.field_name.length - 1] : ui_state->stack_nulls.field_name)

EXPORT UI_State* ui_state_allocate(Renderer* renderer, RenderWindow* window);
EXPORT void ui_state_select(UI_State* state);
EXPORT u8 ui_build_begin(OSWindow window, f64 frame_time, OSEventQueue* event_queue);
EXPORT void ui_build_end();
EXPORT void ui_draw();
EXPORT UI_Signal ui_signal_from_widget(UI_Widget* widget);
EXPORT UI_State* ui_state_get();

EXPORT UI_Widget* ui_widget_make(UI_WidgetFlags flags, String string);
EXPORT UI_Widget* ui_widget_make_format(UI_WidgetFlags flags, const char* format, ...);
EXPORT UI_Size ui_pixels(u32 width, f32 strictness);
EXPORT UI_Size ui_percentage(f32 percentage, f32 strictness);
EXPORT UI_Size ui_em(f32 value, f32 strictness);
