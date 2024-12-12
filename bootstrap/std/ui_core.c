#include <std/ui_core.h>
#include <std/format.h>
#include <std/string.h>

global_variable UI_State* ui_state = 0;

void ui_state_select(UI_State* state)
{
    ui_state = state;
}

UI_State* ui_state_get()
{
    return ui_state;
}

fn UI_Key ui_key_null()
{
    UI_Key key = {};
    return key;
}

auto text_end_delimiter = strlit("##");
auto hash_start_delimiter = strlit("###");

fn String ui_text_from_key_string(String string)
{
    String result = string;
    auto index = string_first_ocurrence(string, text_end_delimiter);
    if (index < string.length)
    {
        result.length = index;
    }
    return result;
}

fn String ui_hash_from_key_string(String string)
{
    String result = string;
    auto index = string_first_ocurrence(string, hash_start_delimiter);
    if (index < string.length)
    {
        result = s_get_slice(u8, string, index, string.length);
    }

    return result;
}

u8 ui_build_begin(OSWindow window, f64 frame_time, OSEventQueue* event_queue)
{
    u8 open = 1;
    for (u32 generic_event_index = 0; generic_event_index < event_queue->descriptors.length; generic_event_index += 1)
    {
        auto event_descriptor = event_queue->descriptors.pointer[generic_event_index];
        u32 event_index = event_descriptor.index;

        switch (event_descriptor.type)
        {
        case OS_EVENT_TYPE_MOUSE_BUTTON:
            {
                auto button = event_queue->mouse_buttons.pointer[event_index];
                auto previous_button_event = ui_state->mouse_button_events[button.button];
                switch (button.event.action)
                {
                    case OS_EVENT_MOUSE_RELAX:
                        unreachable();
                    case OS_EVENT_MOUSE_RELEASE:
                        {
                            assert(previous_button_event.action == OS_EVENT_MOUSE_PRESS);
                        } break;
                    case OS_EVENT_MOUSE_PRESS:
                        {
                            assert(previous_button_event.action == OS_EVENT_MOUSE_RELAX);
                        } break;
                    case OS_EVENT_MOUSE_REPEAT:
                        {
                            unreachable();
                        } break;
                }

                ui_state->mouse_button_events[button.button] = button.event;
            } break;
        case OS_EVENT_TYPE_WINDOW_FOCUS:
            {
            } break;
        case OS_EVENT_TYPE_CURSOR_POSITION:
            {
                auto mouse_position = event_queue->cursor_positions.pointer[event_index];
                ui_state->mouse_position = (UI_MousePosition) {
                    .x = mouse_position.x,
                    .y = mouse_position.y,
                };
            } break;
        case OS_EVENT_TYPE_CURSOR_ENTER:
            {
                todo();
            } break;
        case OS_EVENT_TYPE_WINDOW_POSITION:
            {
                // event_queue->window_positions.pointer[event_index];
                // todo();
            } break;
        case OS_EVENT_TYPE_WINDOW_CLOSE:
            {
                open = 0;
            } break;
        }
    }

    auto framebuffer_size = os_window_framebuffer_size_get(window);

    ui_state->root = ui_widget_make(
        (UI_WidgetFlags) {},
        strlit(""),
        (UI_Rect) {
            .x0 = 0,
            .y0 = 0,
            .x1 = framebuffer_size.width,
            .y1 = framebuffer_size.height,
        }
    );

    return open;
}

void ui_build_end()
{
    // Clear release button presses
    for (u32 i = 0; i < array_length(ui_state->mouse_button_events); i += 1)
    {
        auto* event = &ui_state->mouse_button_events[i];
        if (event->action == OS_EVENT_MOUSE_RELEASE)
        {
            event->action = OS_EVENT_MOUSE_RELAX;
        }
    }
}

fn RenderRect render_rect(UI_Rect rect)
{
    return (RenderRect) {
        .x0 = rect.x0,
        .y0 = rect.y0,
        .x1 = rect.x1,
        .y1 = rect.y1,
    };
}

void ui_draw()
{
    UI_Widget* root = ui_state->root;

    UI_Widget* widget = root;
    RenderWindow* window = ui_state->render;
    Renderer* renderer = ui_state->renderer;

    while (1)
    {
        if (widget->flags.draw_background)
        {
            window_render_rect(window, (RectDraw) {
                .color = widget->background_color,
                .vertex = render_rect(widget->rect),
            });
        }

        if (widget->flags.draw_text)
        {
            window_render_text(renderer, window, widget->string, Color4(1, 1, 1, 1), RENDER_FONT_TYPE_PROPORTIONAL, widget->rect.x0, widget->rect.y0);
        }

        if (widget->first)
        {
            widget = widget->first;
        }
        else if (widget->next)
        {
            widget = widget->next;
        }
        else if (widget->parent == ui_state->root)
        {
            break;
        }
        else if (widget->parent)
        {
            widget = widget->parent;
        }
        else
        {
            unreachable();
        }
    }
}

UI_Widget* ui_widget_make(UI_WidgetFlags flags, String string, UI_Rect rect)
{
    auto* widget = arena_allocate(ui_state->arena, UI_Widget, 1);
    *widget = (UI_Widget)
    {
        .string = string,
        .flags = flags,
        .rect = rect,
        .background_color = Color4(0, 0, 0, 1),
        // TODO: modify
        .parent = ui_state->root,
    };

    auto* parent = widget->parent;
    if (parent)
    {
        auto* ptr = &parent->last;
        auto* previous_last = *ptr;
        if (previous_last)
        {
            previous_last->next = widget;
        }
        *ptr = widget;

        if (!parent->first)
        {
            parent->first = widget;
        }
        parent->last = widget;
    }
    
    return widget;
}

UI_Widget* ui_widget_make_format(UI_WidgetFlags flags, UI_Rect rect, const char* format, ...)
{
    va_list args;
    u8 buffer[4096];
    va_start(args, format);
    auto string = format_string_va((String)array_to_slice(buffer), format, args);
    va_end(args);

    auto* result = ui_widget_make(flags, string, rect);
    return result;
}

UI_Signal ui_signal_from_widget(UI_Widget* widget)
{
    UI_Rect rect = widget->rect;
    UI_Signal signal = {
        .clicked_left = (widget->flags.clickable & (ui_state->mouse_button_events[OS_EVENT_MOUSE_LEFT].action == OS_EVENT_MOUSE_RELEASE)) &
        (ui_state->mouse_position.x >= rect.x0 & ui_state->mouse_position.x <= rect.x1) &
        (ui_state->mouse_position.y >= rect.y0 & ui_state->mouse_position.y <= rect.y1),
    };
    return signal;
}
