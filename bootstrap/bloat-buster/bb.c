#include <std/base.h>
#include <std/project.h>
#include <std/os.h>
#include <std/virtual_buffer.h>
#include <std/windowing.h>
#include <std/rendering.h>

#include <std/base.c>
#include <std/os.c>
#include <std/virtual_buffer.c>
#include <std/windowing.c>
#include <std/rendering.c>

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

    while (1)
    {
        windowing_poll_events();
    }

    return 0;
}
