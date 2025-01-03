#include <std/base.h>
#include <std/project.h>
#include <std/os.h>
#include <std/virtual_buffer.h>
#include <std/windowing.h>
#include <std/rendering.h>
#include <std/ui_core.h>

#include <std/base.c>
#include <std/os.c>
#include <std/virtual_buffer.c>
#include <std/windowing.c>
#include <std/rendering.c>
#include <std/ui_core.c>

#define default_font_height (24)
auto proportional_font_height = default_font_height;
auto monospace_font_height = default_font_height;

fn TextureIndex white_texture_create(Arena* arena, Renderer* renderer)
{
    u32 white_texture_width = 1024;
    u32 white_texture_height = white_texture_width;
    auto* white_texture_buffer = arena_allocate(arena, u32, white_texture_width * white_texture_height);
    memset(white_texture_buffer, 0xff, white_texture_width * white_texture_height * sizeof(u32));

    auto white_texture = renderer_texture_create(renderer, (TextureMemory) {
        .pointer = white_texture_buffer,
        .width = white_texture_width,
        .height = white_texture_height,
        .depth = 1,
        .format = TEXTURE_FORMAT_R8G8B8A8_SRGB,
    });

    return white_texture;
}

int main()
{
    Arena* arena = arena_initialize_default(MB(2));
    if (!windowing_initialize())
    {
        return 1;
    }

    Renderer* renderer = rendering_initialize(arena);
    if (!renderer)
    {
        return 1;
    }

    WindowCreate window_create_options = {
        .name = strlit("Bloat Buster"),
        .size = { .width = 1600, .height = 900 },
    };
    WindowingInstance* window = windowing_instantiate(window_create_options);

    RenderWindow* render_window = rendering_initialize_window(renderer, window);

    window_rect_texture_update_begin(render_window);

    auto white_texture = white_texture_create(arena, renderer);
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
    auto monospace_font = font_texture_atlas_create(arena, renderer, monospace_font_create);
    auto proportional_font = monospace_font;

    window_queue_rect_texture_update(render_window, RECT_TEXTURE_SLOT_WHITE, white_texture);
    renderer_queue_font_update(renderer, render_window, RENDER_FONT_TYPE_MONOSPACE, monospace_font);
    renderer_queue_font_update(renderer, render_window, RENDER_FONT_TYPE_PROPORTIONAL, proportional_font);

    window_rect_texture_update_end(renderer, render_window);

    while (1)
    {
        windowing_poll_events();
    }

    return 0;
}
