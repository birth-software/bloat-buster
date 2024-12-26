#include <std/window.h>

#ifndef __APPLE__
#include <volk.h>
#endif
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>

global_variable OSGraphicCallbacks callbacks;

// TODO: thread local
global_variable OSEventQueue* event_queue = 0;

fn void monitor_callback(GLFWmonitor* monitor, int event)
{
    unused(monitor);
    unused(event);
    todo();
}

fn void joystick_callback(int joystick_id, int event)
{
    unused(joystick_id);
    unused(event);
    todo();
}

fn void bitset_list_add(VirtualBuffer(OSEventBitset)* list, u32* counter, u64 value)
{
    auto event_index = *counter;
    if (unlikely(event_index % OS_EVENT_BITSET_SIZE == 0))
    {
        *vb_add(list, 1) = (OSEventBitset) {
            .value = 0,
        };
    }

    auto bitset_index = event_index / OS_EVENT_BITSET_SIZE;
    u64 bit_index = event_index % OS_EVENT_BITSET_SIZE;
    list->pointer[bitset_index].value |= (value << bit_index);
}

void os_graphics_init(OSGraphicsInitializationOptions options)
{
#ifdef __linux__
    int platform_hint = options.should_use_x11 ? GLFW_PLATFORM_X11 : GLFW_PLATFORM_WAYLAND;
    glfwInitHint(GLFW_PLATFORM, platform_hint);
#endif

    if (glfwInit() != GLFW_TRUE)
    {
        failed_execution();
    }

    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    // From GLFW documentation:
    // This is called when a monitor is connected to or disconnected from the system.
    glfwSetMonitorCallback(&monitor_callback);
    glfwSetJoystickCallback(&joystick_callback);

    callbacks = options.callback;
}

fn void glfw_window_drop_callback(GLFWwindow* window, int path_count, const char* paths[])
{
    void* context = glfwGetWindowUserPointer(window);
    auto* drop_callback = callbacks.window_drop;
    print("DROP\n");
    if (drop_callback)
    {
        drop_callback(window, context, (CStringSlice) { .pointer = (char**)paths, .length = path_count });
    }
}

fn void glfw_window_scroll_callback(GLFWwindow* window, double x, double y)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* scroll_callback = callbacks.window_scroll;
    print("SCROLL\n");
    if (scroll_callback)
    {
        scroll_callback(window, context, x, y);
    }
}

fn void glfw_window_cursor_enter_callback(GLFWwindow* window, int entered)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* cursor_enter_callback = callbacks.window_cursor_enter;
    print("CURSOR_ENTER: {u32}\n", entered);

    auto event_index = event_queue->cursor_enter_count;
    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .type = OS_EVENT_TYPE_WINDOW_FOCUS,
        .index = event_index,
    };

    bitset_list_add(&event_queue->cursor_enters, &event_queue->cursor_enter_count, entered);

    if (cursor_enter_callback)
    {
        cursor_enter_callback(window, context, entered);
    }
}

fn void glfw_window_cursor_position_callback(GLFWwindow* window, double x, double y)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* cursor_position_callback = callbacks.window_cursor_position;
    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .index = event_queue->cursor_positions.length,
        .type = OS_EVENT_TYPE_CURSOR_POSITION,
    };
    *vb_add(&event_queue->cursor_positions, 1) = (OSEventCursorPosition) {
        .x = x,
        .y = y,
    };

    if (cursor_position_callback)
    {
        cursor_position_callback(window, context, x, y);
    }
}

fn void glfw_window_mouse_button_callback(GLFWwindow* window, int button, int action, int mods)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* mouse_button_callback = callbacks.window_mouse_button;
    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .index = event_queue->mouse_buttons.length,
        .type = OS_EVENT_TYPE_MOUSE_BUTTON,
    };
    print("Button: {u32:x}. Action: {u32:x}. Mods: {u32:x}\n", button, action, mods);

    OSEventMouseButtonAction os_action;
    switch (action)
    {
        case GLFW_RELEASE: os_action = OS_EVENT_MOUSE_RELEASE; break;
        case GLFW_PRESS: os_action = OS_EVENT_MOUSE_PRESS; break;
        case GLFW_REPEAT: os_action = OS_EVENT_MOUSE_REPEAT; break;
        default: unreachable();
    }

    OSEventMouseButtonKind mouse_button = 0;
    switch (button)
    {
        case GLFW_MOUSE_BUTTON_1:
            mouse_button = OS_EVENT_MOUSE_BUTTON_1;
            break;
        case GLFW_MOUSE_BUTTON_2:
            mouse_button = OS_EVENT_MOUSE_BUTTON_2;
            break;
        case GLFW_MOUSE_BUTTON_3:
            mouse_button = OS_EVENT_MOUSE_BUTTON_3;
            break;
        case GLFW_MOUSE_BUTTON_4:
            mouse_button = OS_EVENT_MOUSE_BUTTON_4;
            break;
        case GLFW_MOUSE_BUTTON_5:
            mouse_button = OS_EVENT_MOUSE_BUTTON_5;
            break;
        case GLFW_MOUSE_BUTTON_6:
            mouse_button = OS_EVENT_MOUSE_BUTTON_6;
            break;
        case GLFW_MOUSE_BUTTON_7:
            mouse_button = OS_EVENT_MOUSE_BUTTON_7;
            break;
        case GLFW_MOUSE_BUTTON_8:
            mouse_button = OS_EVENT_MOUSE_BUTTON_8;
            break;
    }

    *vb_add(&event_queue->mouse_buttons, 1) = (OSEventMouseButton) {
        .button = mouse_button,
        .event = (OSEventMouseButtonEvent){
            .action = os_action,
            .mod_shift = !!(mods & GLFW_MOD_SHIFT),
            .mod_control = !!(mods & GLFW_MOD_CONTROL),
            .mod_alt = !!(mods & GLFW_MOD_ALT),
            .mod_super = !!(mods & GLFW_MOD_SUPER),
            .mod_caps_lock = !!(mods & GLFW_MOD_CAPS_LOCK),
            .mod_num_lock = !!(mods & GLFW_MOD_NUM_LOCK),
        },
    };

    if (mouse_button_callback)
    {
        mouse_button_callback(window, context, button, action, mods);
    }
}

fn void glfw_window_character_modifier_callback(GLFWwindow* window, unsigned int codepoint, int mods)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* character_modifier_callback = callbacks.window_character_modifier;
    // print("CHAR_MODIFIER. Codepoint: {u32}. Mods: {u32}\n", codepoint, mods);
    if (character_modifier_callback)
    {
        character_modifier_callback(window, context, codepoint, mods);
    }
}

fn void glfw_window_character_callback(GLFWwindow* window, unsigned int codepoint)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* character_callback = callbacks.window_character;
    // print("CHAR. Codepoint: {u32}\n", codepoint);
    if (character_callback)
    {
        character_callback(window, context, codepoint);
    }
}

fn void glfw_window_key_callback(GLFWwindow* window, int key, int scancode, int action, int mods)
{
    void* context = glfwGetWindowUserPointer(window);
    auto* key_callback = callbacks.window_key;
    print("Key: {u32}. Scancode: {u32}. Action: {u32}. Mods: {u32}\n", key, scancode, action, mods);
    if (key_callback)
    {
        key_callback(window, context, key, scancode, action, mods);
    }
}

fn void glfw_window_content_scale_callback(GLFWwindow* window, float x, float y)
{
    void* context = glfwGetWindowUserPointer(window);
    print("CONTENT_SCALE\n");
    auto* content_scale_callback = callbacks.window_content_scale;
    if (content_scale_callback)
    {
        content_scale_callback(window, context, x, y);
    }
}

fn void glfw_window_maximize_callback(GLFWwindow* window, int maximized)
{
    void* context = glfwGetWindowUserPointer(window);
    print("MAXIMIZE\n");
    auto* maximize_callback = callbacks.window_maximize;
    if (maximize_callback)
    {
        maximize_callback(window, context, maximized);
    }
}

fn void glfw_window_iconify_callback(GLFWwindow* window, int iconified)
{
    void* context = glfwGetWindowUserPointer(window);
    print("ICONIFY\n");
    auto* iconify_callback = callbacks.window_iconify;
    if (iconify_callback)
    {
        iconify_callback(window, context, iconified);
    }
}

fn void glfw_window_focus_callback(GLFWwindow* window, int focused)
{
    void* context = glfwGetWindowUserPointer(window);
    print("FOCUS\n");
    auto* focus_callback = callbacks.window_focus;
    auto event_index = event_queue->window_focuses_count;
    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .type = OS_EVENT_TYPE_WINDOW_FOCUS,
        .index = event_index,
    };

    bitset_list_add(&event_queue->window_focuses, &event_queue->window_focuses_count, focused);

    if (focus_callback)
    {
        focus_callback(window, context, focused);
    }
}

fn void glfw_window_close_callback(GLFWwindow* window)
{
    void* context = glfwGetWindowUserPointer(window);
    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .type = OS_EVENT_TYPE_WINDOW_CLOSE,
    };

    auto* close_callback = callbacks.window_close;
    if (close_callback)
    {
        close_callback(window, context);
    }
}

fn void glfw_window_position_callback(GLFWwindow* window, int x, int y)
{
    void* context = glfwGetWindowUserPointer(window);
    print("WINDOW_POSITION: {u32}x{u32}\n", x, y);
    auto* position_callback = callbacks.window_position;

    *vb_add(&event_queue->descriptors, 1) = (OSEventDescriptor) {
        .index = event_queue->window_positions.length,
        .type = OS_EVENT_TYPE_WINDOW_POSITION,
    };

    *vb_add(&event_queue->window_positions, 1) = (OSEventWindowPosition) {
        .x = x,
        .y = y,
    };

    if (position_callback)
    {
        position_callback(window, context, x, y);
    }
}

fn void glfw_window_size_callback(GLFWwindow* window, int width, int height)
{
    void* context = glfwGetWindowUserPointer(window);
    print("WINDOW_SIZE\n");
    auto* window_resize_callback = callbacks.window_resize;
    if (window_resize_callback)
    {
        window_resize_callback(window, context, width, height);
    }
}

fn void glfw_framebuffer_size_callback(GLFWwindow* window, int width, int height)
{
    void* context = glfwGetWindowUserPointer(window);
    print("FRAMEBUFFER_SIZE\n");
    auto* framebuffer_resize_callback = callbacks.framebuffer_resize;
    if (framebuffer_resize_callback)
    {
        framebuffer_resize_callback(window, context, width, height);
    }
}

fn void glfw_window_refresh_callback(GLFWwindow* w)
{
    void* context = glfwGetWindowUserPointer(w);
    print("REFRESH\n");
    auto refresh_callback = callbacks.window_refresh;
    if (refresh_callback)
    {
        refresh_callback(w, context);
    }
}

OSWindow os_window_create(OSWindowCreate create)
{
    // glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);

    GLFWmonitor* monitor = 0;
    GLFWwindow* share = 0;
    GLFWwindow* window = glfwCreateWindow(create.size.width, create.size.height, string_to_c(create.name), monitor, share);

    glfwSetWindowUserPointer(window, create.context);

    glfwSetWindowPosCallback(window, &glfw_window_position_callback);
    glfwSetWindowSizeCallback(window, &glfw_window_size_callback);
    glfwSetWindowCloseCallback(window, &glfw_window_close_callback);
    glfwSetWindowFocusCallback(window, &glfw_window_focus_callback);
    glfwSetWindowIconifyCallback(window, &glfw_window_iconify_callback); // Minimize callback
    glfwSetWindowMaximizeCallback(window, &glfw_window_maximize_callback);
    glfwSetFramebufferSizeCallback(window, &glfw_framebuffer_size_callback);
    glfwSetWindowRefreshCallback(window, &glfw_window_refresh_callback);
    glfwSetWindowContentScaleCallback(window, &glfw_window_content_scale_callback);
    glfwSetKeyCallback(window, &glfw_window_key_callback);
    glfwSetCharCallback(window, &glfw_window_character_callback);
    glfwSetCharModsCallback(window, &glfw_window_character_modifier_callback);
    glfwSetMouseButtonCallback(window, &glfw_window_mouse_button_callback);
    glfwSetCursorPosCallback(window, &glfw_window_cursor_position_callback);
    glfwSetCursorEnterCallback(window, &glfw_window_cursor_enter_callback);
    glfwSetScrollCallback(window, &glfw_window_scroll_callback);
    glfwSetDropCallback(window, &glfw_window_drop_callback);

    return window;
}

u8 os_window_should_close(OSWindow window)
{
    return glfwWindowShouldClose(window);
}

fn void os_event_queue_reset(OSEventQueue* queue)
{
    queue->descriptors.length = 0;
    queue->mouse_buttons.length = 0;
    queue->cursor_positions.length = 0;
}

fn u8 os_event_bitset_list(VirtualBuffer(OSEventBitset) bitset, u32 index)
{
    auto bitset_index = index / bitset.length;
    auto bit_index = index % bitset.length;
    return !!(bitset.pointer[bitset_index].value & bit_index);
}

u8 os_event_queue_get_window_focus(OSEventQueue* queue, u32 index)
{
    assert(index < queue->window_focuses.length);
    auto result = os_event_bitset_list(queue->window_focuses, index);
    return result;
}

void os_poll_events(OSEventQueue* queue)
{
    os_event_queue_reset(queue);
    event_queue = queue;
    assert(queue->descriptors.length == 0);
    glfwPollEvents();
}

OSWindowSize os_window_framebuffer_size_get(OSWindow window)
{
    int width;
    int height;
    glfwGetFramebufferSize(window, &width, &height);
    return (OSWindowSize)
    {
        .width = width,
        .height = height,
    };
}

OSCursorPosition os_window_cursor_position_get(OSWindow window)
{
    OSCursorPosition result;
    glfwGetCursorPos(window, &result.x, &result.y);
    return result;
}
