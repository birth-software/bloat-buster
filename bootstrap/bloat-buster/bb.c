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
int main(int argc, char** argv, char** envp)
{
    unused(argc);
    unused(argv);
    unused(envp);
    return 0;
}
#endif
