// This UI is heavily inspired by the ideas of Casey Muratori and Ryan Fleury ideas on GUI programming, to whom I am deeply grateful.
// Here are some links which helped me achieve this build
// https://www.youtube.com/watch?v=Z1qyvQsjK5Y
// https://www.rfleury.com/p/ui-part-1-the-interaction-medium
// https://www.rfleury.com/p/ui-part-2-build-it-every-frame-immediate
// https://www.rfleury.com/p/ui-part-3-the-widget-building-language
// https://www.rfleury.com/p/ui-part-4-the-widget-is-a-lie-node
// https://www.rfleury.com/p/ui-part-5-visual-content
// https://www.rfleury.com/p/ui-part-6-rendering
// https://www.rfleury.com/p/ui-part-7-where-imgui-ends
// https://www.rfleury.com/p/ui-part-8-state-mutation-jank-and
// https://www.rfleury.com/p/ui-part-9-keyboard-and-gamepad-navigation
// https://www.rfleury.com/p/ui-bonus-1-simple-single-line-text
// https://www.rfleury.com/p/codebase-walkthrough-multi-window

#pragma once

global_variable UI_State* ui_state = 0;

fn void ui_autopop(UI_State* state)
{
    let(stack_end, (u32*)((u8*)&state->stacks + sizeof(state->stacks)));
    
    let(bitset_pointer, (u64*)&state->stack_autopops);
    u64 bitset_index = 0;
    for (let(stack_pointer, (u32*)&state->stacks); stack_pointer != stack_end; stack_pointer += sizeof(VirtualBuffer(u8)) / sizeof(u32))
    {
        let(bitset, *bitset_pointer);
        let(shift_value, 1 << bitset_index);
        let(autopop, (bitset & shift_value) != 0);
        let(mask, ~shift_value);
        *bitset_pointer = bitset & mask;
        let(length_pointer, stack_pointer + (offsetof(VirtualBuffer(u8), length) / sizeof(u32)));
        let(current_length, *length_pointer);
        assert(!autopop | current_length);
        *length_pointer -= autopop;

        u64 increment_bitset_element = (bitset_index > 0) & (bitset_index % 64 == 0);
        bitset_pointer += increment_bitset_element;
        bitset_index = increment_bitset_element ? 0 : bitset_index + 1;
    }
}

fn void ui_state_select(UI_State* state)
{
    ui_state = state;
}

fn UI_State* ui_state_get()
{
    return ui_state;
}

fn Arena* ui_build_arena()
{
    let(arena, ui_state->build_arenas[ui_state->build_count % array_length(ui_state->build_arenas)]);
    return arena;
}

fn UI_Key ui_key_null()
{
    UI_Key key = {};
    return key;
}

fn UI_State* ui_state_allocate(Renderer* renderer, RenderWindow* window)
{
    Arena* arena = arena_initialize(GB(8), MB(2), MB(2));
    UI_State* state = arena_allocate(arena, UI_State, 1);
    state->renderer = renderer;
    state->render_window = window;
    state->arena = arena;
    state->widget_table.length = 4096;
    state->widget_table.pointer = arena_allocate(arena, UI_WidgetSlot, state->widget_table.length);
    
    for (u64 i = 0; i < array_length(state->build_arenas); i += 1)
    {
        state->build_arenas[i] = arena_initialize(GB(8), MB(2), MB(2));
    }

    state->stack_nulls = (UI_StateStackNulls){
        .parent = 0,
        .child_layout_axis = AXIS2_COUNT,
        .pref_width = {},
        .pref_height = {},
    };

    let(stack_end, (u32*)((u8*)&state->stacks + sizeof(state->stacks)));
    
    for (let(stack_pointer, (u32*)&state->stacks); stack_pointer != stack_end; stack_pointer += sizeof(VirtualBuffer(u8)) / sizeof(u32))
    {
        let(length_pointer, stack_pointer + (offsetof(VirtualBuffer(u8), length) / sizeof(u32)));
        assert(*length_pointer == 0);
    }

    return state;
}

fn u64 ui_widget_index_from_key(UI_Key key)
{
    let(length, ui_state->widget_table.length);
    assert(is_power_of_two(length));
    return key.value & (length - 1);
}


fn String ui_text_from_key_string(String string)
{
    String result = string;
    String text_end_delimiter = strlit("##");
    let(index, string_first_occurrence(string, text_end_delimiter));
    if (index < string.length)
    {
        result.length = index;
    }
    return result;
}

fn String ui_hash_from_key_string(String string)
{
    String result = string;
    String hash_start_delimiter = strlit("###");
    let(index, string_first_occurrence(string, hash_start_delimiter));
    if (index < string.length)
    {
        result = s_get_slice(u8, string, index, string.length);
    }

    return result;
}

fn UI_Key ui_key_from_string(UI_Key seed, String string)
{
    UI_Key key = ui_key_null();

    if (string.length)
    {
        key = seed;

        for (u64 i = 0; i < string.length; i += 1)
        {
            key.value = ((key.value << 5) + key.value) + string.pointer[i];
        }
    }

    return key;
}

fn UI_Key ui_key_from_string_format(UI_Key seed, char* format, ...)
{
    u8 buffer[256];
    va_list args;
    va_start(args, format);
    let(string, format_string_va((String)array_to_slice(buffer), format, args));
    va_end(args);
    let(result, ui_key_from_string(seed, string));
    return result;
}

fn u8 ui_key_equal(UI_Key a, UI_Key b)
{
    return a.value == b.value;
}

fn UI_Widget* ui_widget_from_key(UI_Key key)
{
    UI_Widget* result = 0;

    if (!ui_key_equal(key, ui_key_null()))
    {
        let(index, ui_widget_index_from_key(key));
        for (UI_Widget* widget = ui_state->widget_table.pointer[index].first; widget; widget = widget->hash_next)
        {
            if (ui_key_equal(widget->key, key))
            {
                result = widget;
                break;
            }
        }
    }

    return result;
}

fn UI_Widget* ui_widget_make_from_key(UI_WidgetFlags flags, UI_Key key)
{
    let(widget, ui_widget_from_key(key));
    static let(count, 0);
    count += 1;

    if (widget)
    {
        if (widget->last_build_touched == ui_state->build_count)
        {
            key = ui_key_null();
            widget = 0;
        }
    }

    u8 first_frame = 0;
    if (!widget)
    {
        let(index, ui_widget_index_from_key(key));
        first_frame = 1;

        widget = arena_allocate(ui_state->arena, UI_Widget, 1);

        let(table_widget_slot, &ui_state->widget_table.pointer[index]);
        if (!table_widget_slot->last)
        {
            table_widget_slot->first = widget;
            table_widget_slot->last = widget;
        }
        else
        {
            table_widget_slot->last->hash_next = widget;
            widget->hash_previous = table_widget_slot->last;
            table_widget_slot->last = widget;
        }
    }

    let(parent, ui_top(parent));

    if (parent)
    {
        if (!parent->last)
        {
            parent->last = widget;
            parent->first = widget;
        }
        else
        {
            let(previous_last, parent->last);
            previous_last->next = widget;
            widget->previous = previous_last;
            parent->last = widget;
        }

        parent->child_count += 1;
        widget->parent = parent;
    }
    else
    {
        ui_state->root = widget;
    }

    widget->key = key;

    for (u64 i = 0; i < array_length(widget->background_colors); i += 1)
    {
        widget->background_colors[i] = ui_top(background_color);
    }
    widget->text_color = ui_top(text_color);
    widget->flags = flags;
    widget->first = 0;
    widget->last = 0;
    widget->last_build_touched = ui_state->build_count;
    widget->pref_size[AXIS2_X] = ui_top(pref_width);
    widget->pref_size[AXIS2_Y] = ui_top(pref_height);
    widget->child_layout_axis = ui_top(child_layout_axis);

    ui_autopop(ui_state);

    return widget;
}

fn UI_Widget* ui_widget_make(UI_WidgetFlags flags, String string)
{
    // TODO:
    let(seed, ui_key_null());

    let(hash_string, ui_hash_from_key_string(string));
    let(key, ui_key_from_string(seed, hash_string));

    let(widget, ui_widget_make_from_key(flags, key));

    if (flags.draw_text)
    {
        widget->text = ui_text_from_key_string(string);
    }

    return widget;
}

fn UI_Widget* ui_widget_make_format(UI_WidgetFlags flags, const char* format, ...)
{
    va_list args;
    u8 buffer[4096];
    va_start(args, format);
    let(string, format_string_va((String)array_to_slice(buffer), format, args));
    va_end(args);

    let(result, ui_widget_make(flags, string));
    return result;
}

fn UI_Signal ui_signal_from_widget(UI_Widget* widget)
{
    let(rect, widget->rect);
    let(mouse_position, ui_state->mouse_position);
    UI_Signal signal = {
        .clicked_left = 
            (widget->flags.mouse_clickable & (ui_state->mouse_button_events[WINDOWING_EVENT_MOUSE_LEFT].action == WINDOWING_EVENT_MOUSE_RELEASE)) &
            ((mouse_position.x >= rect.x0) & (mouse_position.x <= rect.x1)) &
            ((mouse_position.y >= rect.y0) & (mouse_position.y <= rect.y1)),
    };
    return signal;
}

fn void ui_stack_reset(UI_State* state)
{
    let(stack_end, (u32*)((u8*)&state->stacks + sizeof(state->stacks)));
    
    for (let(stack_pointer, (u32*)&state->stacks); stack_pointer != stack_end; stack_pointer += sizeof(VirtualBuffer(u8)) / sizeof(u32))
    {
        let(length_pointer, stack_pointer + (offsetof(VirtualBuffer(u8), length) / sizeof(u32)));
        *length_pointer = 0;
    }
}

fn UI_Size ui_pixels(u32 width, f32 strictness)
{
    return (UI_Size) {
        .kind = UI_SIZE_PIXEL_COUNT,
        .strictness = strictness,
        .value = (f32)width,
    };
}

fn UI_Size ui_percentage(f32 percentage, f32 strictness)
{
    return (UI_Size) {
        .kind = UI_SIZE_PERCENTAGE,
        .strictness = strictness,
        .value = percentage,
    };
}

fn UI_Size ui_em(f32 value, f32 strictness)
{
    let(font_size, ui_top(font_size));
    assert(font_size);
    return (UI_Size) {
        .kind = UI_SIZE_PIXEL_COUNT,
        .strictness = strictness,
        .value = value * font_size,
    };
}

fn u8 ui_build_begin(WindowingInstance* window, f64 frame_time, WindowingEventQueue* event_queue)
{
    ui_state->build_count += 1;
    let(build_arena, ui_build_arena());
    arena_reset(build_arena);
    ui_state->frame_time = frame_time;
    ui_state->window = window;

    ui_stack_reset(ui_state);

    u8 open = 1;

    let(mouse_button_count, 0);
    for (u32 generic_event_index = 0; open & (generic_event_index < event_queue->descriptors.length); generic_event_index += 1)
    {
        let(event_descriptor, event_queue->descriptors.pointer[generic_event_index]);
        u32 event_index = event_descriptor.index;

        switch (event_descriptor.type)
        {
        case WINDOWING_EVENT_TYPE_MOUSE_BUTTON:
            {
                let(button, event_queue->mouse_buttons.pointer[event_index]);
                let(previous_button_event, ui_state->mouse_button_events[button.button]);
                switch (button.event.action)
                {
                    case WINDOWING_EVENT_MOUSE_RELAX:
                        unreachable();
                    case WINDOWING_EVENT_MOUSE_RELEASE:
                        {
                            assert(previous_button_event.action == WINDOWING_EVENT_MOUSE_PRESS);
                        } break;
                    case WINDOWING_EVENT_MOUSE_PRESS:
                        {
                            // TODO: handle properly
                            assert(previous_button_event.action == WINDOWING_EVENT_MOUSE_RELAX || mouse_button_count);
                        } break;
                    case WINDOWING_EVENT_MOUSE_REPEAT:
                        {
                            unreachable();
                        } break;
                }

                ui_state->mouse_button_events[button.button] = button.event;
                mouse_button_count += 1;
            } break;
        case WINDOWING_EVENT_TYPE_WINDOW_FOCUS:
            {
            } break;
        case WINDOWING_EVENT_TYPE_CURSOR_POSITION:
            {
                let(mouse_position, event_queue->cursor_positions.pointer[event_index]);
                ui_state->mouse_position = (UI_MousePosition) {
                    .x = mouse_position.x,
                    .y = mouse_position.y,
                };
            } break;
        case WINDOWING_EVENT_TYPE_CURSOR_ENTER:
            {
                todo();
            } break;
        case WINDOWING_EVENT_TYPE_WINDOW_POSITION:
            {
                // event_queue->window_positions.pointer[event_index];
                // todo();
            } break;
        case WINDOWING_EVENT_TYPE_WINDOW_CLOSE:
            {
                open = 0;
            } break;
        }
    }

    if (open)
    {
        for (u64 i = 0; i < ui_state->widget_table.length; i += 1)
        {
            let(widget_table_element, &ui_state->widget_table.pointer[i]);
            for (UI_Widget* widget = widget_table_element->first, *next = 0; widget; widget = next)
            {
                next = widget->hash_next;

                if (ui_key_equal(widget->key, ui_key_null()) || widget->last_build_touched + 1 < ui_state->build_count)
                {
                    // Remove from the list
                    if (widget->hash_previous)
                    {
                        widget->hash_previous->hash_next = widget->hash_next;
                    }

                    if (widget->hash_next)
                    {
                        widget->hash_next->hash_previous = widget->hash_previous;
                    }

                    if (widget_table_element->first == widget)
                    {
                        widget_table_element->first = widget->hash_next;
                    }

                    if (widget_table_element->last == widget)
                    {
                        widget_table_element->last = widget->hash_previous;
                    }
                }
            }
        }

        let(framebuffer_size, windowing_get_instance_framebuffer_size(window));
        ui_push_next_only(pref_width, ui_pixels(framebuffer_size.width, 1.0f));
        ui_push_next_only(pref_height, ui_pixels(framebuffer_size.height, 1.0f));
        ui_push_next_only(child_layout_axis, AXIS2_Y);

        let(root, ui_widget_make_format((UI_WidgetFlags) {}, "window_root_{u64}", window));
        assert(!ui_state->stack_autopops.child_layout_axis);

        ui_push(parent, root);

        ui_push(font_size, 12);

        ui_push(text_color, VEC4(0.9, 0.9, 0.02, 1));
        ui_push(background_color, VEC4(0.1, 0.1, 0.1, 1));
        ui_push(pref_width, ui_percentage(1.0, 0.0));
        ui_push(pref_height, ui_percentage(1.0, 0.0));
        // ui_push(pref_height, ui_em(1.8, 0.0));
    }

    return open;
}

fn void ui_compute_independent_sizes(UI_Widget* widget)
{
    for (Axis2 axis = 0; axis < AXIS2_COUNT; axis += 1)
    {
        let(pref_size, widget->pref_size[axis]);
        switch (pref_size.kind)
        {
            default: break; case UI_SIZE_COUNT: unreachable();
            case UI_SIZE_PIXEL_COUNT:
                {
#if BB_HAS_NATIVE_FLOAT2
                    widget->computed_size[axis] = floorf(widget->pref_size[axis].value);
#else
                    widget->computed_size.v[axis] = floorf(widget->pref_size[axis].value);
#endif
                } break;
        }
    }

    for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
    {
        ui_compute_independent_sizes(child_widget);
    }
}

fn void ui_compute_upward_dependent_sizes(UI_Widget* widget)
{
    // TODO: optimize loop out if possible
    for (Axis2 axis = 0; axis < AXIS2_COUNT; axis += 1)
    {
        let(pref_size, widget->pref_size[axis]);
        switch (pref_size.kind)
        {
            default: break; case UI_SIZE_COUNT: unreachable();
            case UI_SIZE_PERCENTAGE:
            {
                for (UI_Widget* ancestor = widget->parent; ancestor; ancestor = ancestor->parent)
                {
                    if (ancestor->pref_size[axis].kind != UI_SIZE_BY_CHILDREN)
                    {
#if BB_HAS_NATIVE_FLOAT2
                        widget->computed_size[axis] = floorf(ancestor->computed_size[axis] * widget->pref_size[axis].value);
#else
                        widget->computed_size.v[axis] = floorf(ancestor->computed_size.v[axis] * widget->pref_size[axis].value);
#endif
                        break;
                    }
                }
            } break;
        }
    }

    for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
    {
        ui_compute_upward_dependent_sizes(child_widget);
    }
}

fn void ui_compute_downward_dependent_sizes(UI_Widget* widget)
{
    for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
    {
        ui_compute_downward_dependent_sizes(child_widget);
    }

    for (Axis2 axis = 0; axis < AXIS2_COUNT; axis += 1)
    {
        let(pref_size, widget->pref_size[axis]);
        switch (pref_size.kind)
        {
            default: break; case UI_SIZE_COUNT: unreachable();
            case UI_SIZE_BY_CHILDREN:
            {
                todo();
            } break;
        }
    }
}

fn void ui_resolve_conflicts(UI_Widget* widget)
{
    for (Axis2 axis = 0; axis < AXIS2_COUNT; axis += 1)
    {
#if BB_HAS_NATIVE_FLOAT2
        let(available_space, widget->computed_size[axis]);
#else
        let(available_space, widget->computed_size.v[axis]);
#endif
        f32 taken_space = 0;
        f32 total_fixup_budget = 0;

        if (!(widget->flags.v & (UI_WIDGET_FLAG_OVERFLOW_X << axis)))
        {
            for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
            {
                if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
                {
                    if (axis == widget->child_layout_axis)
                    {
#if BB_HAS_NATIVE_FLOAT2
                        taken_space += child_widget->computed_size[axis];
#else
                        taken_space += child_widget->computed_size.v[axis];
#endif
                    }
                    else
                    {
#if BB_HAS_NATIVE_FLOAT2
                        taken_space = MAX(taken_space, child_widget->computed_size[axis]);
#else
                        taken_space = MAX(taken_space, child_widget->computed_size.v[axis]);
#endif
                    }
#if BB_HAS_NATIVE_FLOAT2
                    let(fixup_budget_this_child, child_widget->computed_size[axis] * (1 - child_widget->pref_size[axis].strictness));
#else
                    let(fixup_budget_this_child, child_widget->computed_size.v[axis] * (1 - child_widget->pref_size[axis].strictness));
#endif
                    total_fixup_budget += fixup_budget_this_child;
                }
            }

            let(conflict, taken_space - available_space);

            if (conflict > 0 && total_fixup_budget > 0)
            {
                for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
                {
                    if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
                    {
#if BB_HAS_NATIVE_FLOAT2
                        let(fixup_budget_this_child, child_widget->computed_size[axis] * (1 - child_widget->pref_size[axis].strictness));
#else
                        let(fixup_budget_this_child, child_widget->computed_size.v[axis] * (1 - child_widget->pref_size[axis].strictness));
#endif
                        f32 fixup_size_this_child = 0;

                        if (axis == widget->child_layout_axis)
                        {
                            fixup_size_this_child = fixup_budget_this_child * (conflict / total_fixup_budget);
                        }
                        else
                        {
#if BB_HAS_NATIVE_FLOAT2
                            fixup_size_this_child = child_widget->computed_size[axis] - available_space;
#else
                            fixup_size_this_child = child_widget->computed_size.v[axis] - available_space;
#endif
                        }

                        fixup_size_this_child = CLAMP(0, fixup_size_this_child, fixup_budget_this_child);
#if BB_HAS_NATIVE_FLOAT2
                        child_widget->computed_size[axis] = floorf(child_widget->computed_size[axis] - fixup_size_this_child);
#else
                        child_widget->computed_size.v[axis] = floorf(child_widget->computed_size.v[axis] - fixup_size_this_child);
#endif
                    }
                }
            }
        }

        if (axis == widget->child_layout_axis)
        {
            f32 p = 0;

            for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
            {
                if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
                {
#if BB_HAS_NATIVE_FLOAT2
                    child_widget->computed_relative_position[axis] = p;
                    p += child_widget->computed_size[axis];
#else
                    child_widget->computed_relative_position.v[axis] = p;
                    p += child_widget->computed_size.v[axis];
#endif
                }
            }
        }
        else
        {
            for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
            {
                if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
                {
#if BB_HAS_NATIVE_FLOAT2
                    child_widget->computed_relative_position[axis] = 0;
#else
                    child_widget->computed_relative_position.v[axis] = 0;
#endif
                }
            }
        }

        for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
        {
            let(last_relative_rect, child_widget->relative_rect);
#if BB_HAS_NATIVE_FLOAT2
            child_widget->relative_rect.p0[axis] = child_widget->computed_relative_position[axis];
            child_widget->relative_rect.p1[axis] = child_widget->relative_rect.p0[axis] + child_widget->computed_size[axis];
#else
            child_widget->relative_rect.p0.v[axis] = child_widget->computed_relative_position.v[axis];
            child_widget->relative_rect.p1.v[axis] = child_widget->relative_rect.p0.v[axis] + child_widget->computed_size.v[axis];
#endif

            float2 last_corner_01 = { last_relative_rect.x0, last_relative_rect.y1 };
            float2 last_corner_10 = { last_relative_rect.x1, last_relative_rect.y0 };
            float2 this_corner_01 = { child_widget->relative_rect.x0, child_widget->relative_rect.y1 };
            float2 this_corner_10 = { child_widget->relative_rect.x1, child_widget->relative_rect.y0 };

#if BB_HAS_NATIVE_FLOAT2
            child_widget->relative_corner_delta[CORNER_00][axis] = child_widget->relative_rect.p0[axis] - last_relative_rect.p0[axis];
            child_widget->relative_corner_delta[CORNER_01][axis] = this_corner_01[axis] - last_corner_01[axis];
            child_widget->relative_corner_delta[CORNER_10][axis] = this_corner_10[axis] - last_corner_10[axis];
            child_widget->relative_corner_delta[CORNER_11][axis] = child_widget->relative_rect.p1[axis] - last_relative_rect.p1[axis];

            child_widget->rect.p0[axis] = widget->rect.p0[axis] + child_widget->relative_rect.p0[axis] - widget->view_offset[axis];
            child_widget->rect.p1[axis] = child_widget->rect.p0[axis] + child_widget->computed_size[axis];

            if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
            {
                child_widget->rect.p0[axis] = floorf(child_widget->rect.p0[axis]);
                child_widget->rect.p1[axis] = floorf(child_widget->rect.p1[axis]);
            }
#else
            child_widget->relative_corner_delta[CORNER_00].v[axis] = child_widget->relative_rect.p0.v[axis] - last_relative_rect.p0.v[axis];
            child_widget->relative_corner_delta[CORNER_01].v[axis] = this_corner_01.v[axis] - last_corner_01.v[axis];
            child_widget->relative_corner_delta[CORNER_10].v[axis] = this_corner_10.v[axis] - last_corner_10.v[axis];
            child_widget->relative_corner_delta[CORNER_11].v[axis] = child_widget->relative_rect.p1.v[axis] - last_relative_rect.p1.v[axis];

            child_widget->rect.p0.v[axis] = widget->rect.p0.v[axis] + child_widget->relative_rect.p0.v[axis] - widget->view_offset.v[axis];
            child_widget->rect.p1.v[axis] = child_widget->rect.p0.v[axis] + child_widget->computed_size.v[axis];

            if (!(child_widget->flags.v & (UI_WIDGET_FLAG_FLOATING_X << axis)))
            {
                child_widget->rect.p0.v[axis] = floorf(child_widget->rect.p0.v[axis]);
                child_widget->rect.p1.v[axis] = floorf(child_widget->rect.p1.v[axis]);
            }
#endif
        }

        for (UI_Widget* child_widget = widget->first; child_widget; child_widget = child_widget->next)
        {
            ui_resolve_conflicts(child_widget);
        }
    }
}

fn void ui_build_end()
{
    // Clear release button presses
    for (u32 i = 0; i < array_length(ui_state->mouse_button_events); i += 1)
    {
        let(event, &ui_state->mouse_button_events[i]);
        if (event->action == WINDOWING_EVENT_MOUSE_RELEASE)
        {
            event->action = WINDOWING_EVENT_MOUSE_RELAX;
        }
    }

    ui_pop(parent);

    ui_compute_independent_sizes(ui_state->root);
    ui_compute_upward_dependent_sizes(ui_state->root);
    ui_compute_downward_dependent_sizes(ui_state->root);
    ui_resolve_conflicts(ui_state->root);
}

STRUCT(WidgetIterator)
{
    UI_Widget* next;
    u32 push_count;
    u32 pop_count;
};

#define ui_widget_recurse_depth_first_preorder(widget) ui_widget_recurse_depth_first((widget), offset_of(UI_Widget, next), offset_of(UI_Widget, first))
#define ui_widget_recurse_depth_first_postorder(widget) ui_widget_recurse_depth_first((widget), offset_of(UI_Widget, previous), offset_of(UI_Widget, last))

fn WidgetIterator ui_widget_recurse_depth_first(UI_Widget* widget, u64 sibling_offset, u64 child_offset)
{
    WidgetIterator it = {};
    let(child, member_from_offset(widget, UI_Widget*, child_offset));
    if (child)
    {
        it.next = child;
        it.push_count += 1;
    }
    else
    {
        for (UI_Widget* w = widget; w; w = w->parent)
        {
            let(sibling, member_from_offset(w, UI_Widget*, sibling_offset));
            if (sibling)
            {
                it.next = sibling;
                break;
            }

            it.pop_count += 1;
        }
    }

    return it;
}

fn void ui_draw()
{
    UI_Widget* root = ui_state->root;

    UI_Widget* widget = root;
    RenderWindow* window = ui_state->render_window;
    Renderer* renderer = ui_state->renderer;

    while (widget)
    {
        if (widget->flags.draw_background)
        {
            window_render_rect(window, (RectDraw) {
                .colors = { widget->background_colors[0], widget->background_colors[1], widget->background_colors[2], widget->background_colors[3] },
                .vertex = widget->rect,
            });
        }

        if (widget->flags.draw_text)
        {
            window_render_text(renderer, window, widget->text, widget->text_color, RENDER_FONT_TYPE_PROPORTIONAL, widget->rect.x0, widget->rect.y0);
        }

        widget = ui_widget_recurse_depth_first_postorder(widget).next;
    }
}
