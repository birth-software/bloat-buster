#pragma once

#if BB_WINDOWING_BACKEND_X11
#include <std/x11_windowing.h>
#endif

#if BB_WINDOWING_BACKEND_WAYLAND
#include <std/wayland_windowing.h>
#endif

#if BB_WINDOWING_BACKEND_COCOA
#include <std/cocoa_windowing.h>
#endif

#if BB_WINDOWING_BACKEND_WIN32
#include <std/win32_windowing.h>
#endif

typedef enum WindowingEventType
{
    WINDOWING_EVENT_TYPE_MOUSE_BUTTON,
    WINDOWING_EVENT_TYPE_CURSOR_POSITION,
    WINDOWING_EVENT_TYPE_CURSOR_ENTER,
    WINDOWING_EVENT_TYPE_WINDOW_FOCUS,
    WINDOWING_EVENT_TYPE_WINDOW_POSITION,
    WINDOWING_EVENT_TYPE_WINDOW_CLOSE,
} WindowingEventType;

STRUCT(WindowingEventDescriptor)
{
    u32 index:24;
    WindowingEventType type:8;
};
static_assert(sizeof(WindowingEventDescriptor) == 4);
decl_vb(WindowingEventDescriptor);

ENUM_START(WindowingEventMouseButtonKind, u8)
{
    WINDOWING_EVENT_MOUSE_BUTTON_1 = 0,
    WINDOWING_EVENT_MOUSE_BUTTON_2 = 1,
    WINDOWING_EVENT_MOUSE_BUTTON_3 = 2,
    WINDOWING_EVENT_MOUSE_BUTTON_4 = 3,
    WINDOWING_EVENT_MOUSE_BUTTON_5 = 4,
    WINDOWING_EVENT_MOUSE_BUTTON_6 = 5,
    WINDOWING_EVENT_MOUSE_BUTTON_7 = 6,
    WINDOWING_EVENT_MOUSE_BUTTON_8 = 7,
    WINDOWING_EVENT_MOUSE_LEFT = WINDOWING_EVENT_MOUSE_BUTTON_1,
    WINDOWING_EVENT_MOUSE_RIGHT = WINDOWING_EVENT_MOUSE_BUTTON_2,
    WINDOWING_EVENT_MOUSE_MIDDLE = WINDOWING_EVENT_MOUSE_BUTTON_3,
}
ENUM_END(WindowingEventMouseButtonKind);
#define WINDOWING_EVENT_MOUSE_BUTTON_COUNT (WINDOWING_EVENT_MOUSE_BUTTON_8 + 1)

ENUM_START(WindowingEventMouseButtonAction, u8)
{
    WINDOWING_EVENT_MOUSE_RELAX = 0,
    WINDOWING_EVENT_MOUSE_RELEASE = 1,
    WINDOWING_EVENT_MOUSE_PRESS = 2,
    WINDOWING_EVENT_MOUSE_REPEAT = 3,
} ENUM_END(WindowingEventMouseButtonAction);

STRUCT(WindowingEventMouseButtonEvent)
{
    WindowingEventMouseButtonAction action:2;
    u8 mod_shift:1;
    u8 mod_control:1;
    u8 mod_alt:1;
    u8 mod_super:1;
    u8 mod_caps_lock:1;
    u8 mod_num_lock:1;
};

STRUCT(WindowingEventMouseButton)
{
    WindowingEventMouseButtonKind button:3;
    u8 reserved:5;
    WindowingEventMouseButtonEvent event;
};
static_assert(sizeof(WindowingEventMouseButton) == sizeof(u16));
decl_vb(WindowingEventMouseButton);

#define WINDOWING_EVENT_BITSET_SIZE (64)
STRUCT(WindowingEventBitset)
{
    u64 value;
};
decl_vb(WindowingEventBitset);

STRUCT(WindowingEventCursorPosition)
{
    f64 x;
    f64 y;
};
decl_vb(WindowingEventCursorPosition);

STRUCT(WindowingEventWindowPosition)
{
    u32 x;
    u32 y;
};
decl_vb(WindowingEventWindowPosition);

STRUCT(WindowingEventQueue)
{
    VirtualBuffer(WindowingEventDescriptor) descriptors;
    VirtualBuffer(WindowingEventMouseButton) mouse_buttons;
    VirtualBuffer(WindowingEventBitset) window_focuses;
    u32 window_focuses_count;
    u32 cursor_enter_count;
    VirtualBuffer(WindowingEventBitset) cursor_enters;
    VirtualBuffer(WindowingEventCursorPosition) cursor_positions;
    VirtualBuffer(WindowingEventWindowPosition) window_positions;
};

// typedef void OSFramebufferResize(OSWindow window, void* context, u32 width, u32 height);
// typedef void OSWindowResize(OSWindow window, void* context, u32 width, u32 height);
// typedef void OSWindowRefresh(OSWindow window, void* context);
// typedef void OSWindowPosition(OSWindow window, void* context, u32 x, u32 y);
// typedef void OSWindowClose(OSWindow window, void* context);
// typedef void OSWindowFocus(OSWindow window, void* context, u8 focused);
// typedef void OSWindowIconify(OSWindow window, void* context, u8 iconified);
// typedef void OSWindowMaximize(OSWindow window, void* context, u8 maximized);
// typedef void OSWindowContentScale(OSWindow window, void* context, f32 x, f32 y);
// typedef void OSWindowKey(OSWindow window, void* context, s32 key, s32 scancode, s32 action, s32 mods);
// typedef void OSWindowCharacter(OSWindow window, void* context, u32 codepoint);
// typedef void OSWindowCharacterModifier(OSWindow window, void* context, u32 codepoint, s32 mods);
// typedef void OSWindowMouseButton(OSWindow window, void* context, s32 button, s32 action, s32 mods);
// typedef void OSWindowCursorPosition(OSWindow window, void* context, f64 x, f64 y);
// typedef void OSWindowCursorEnter(OSWindow window, void* context, u8 entered);
// typedef void OSWindowScroll(OSWindow window, void* context, f64 x, f64 y);
// typedef void OSWindowDrop(OSWindow window, void* context, CStringSlice paths);

// STRUCT(OSWindowingCallbacks)
// {
//     // OSFramebufferResize* framebuffer_resize;
//     // OSWindowResize* window_resize;
//     // OSWindowRefresh* window_refresh;
//     // OSWindowPosition* window_position;
//     // OSWindowClose* window_close;
//     // OSWindowFocus* window_focus;
//     // OSWindowIconify* window_iconify;
//     // OSWindowMaximize* window_maximize;
//     // OSWindowContentScale* window_content_scale;
//     // OSWindowKey* window_key;
//     // OSWindowCharacter* window_character;
//     // OSWindowCharacterModifier* window_character_modifier;
//     // OSWindowMouseButton* window_mouse_button;
//     // OSWindowCursorPosition* window_cursor_position;
//     // OSWindowCursorEnter* window_cursor_enter;
//     // OSWindowScroll* window_scroll;
//     // OSWindowDrop* window_drop;
// };

// STRUCT(OSWindowCreate)
// {
//     String name;
//     OSWindowSize size;
//     void* context;
//     // OSWindowResize* resize_callback;
//     // OSWindowRefresh* refresh_callback;
// };

STRUCT(WindowingCursorPosition)
{
    f64 x;
    f64 y;
};

// NEW API START
STRUCT(WindowingOffset)
{
    u32 x;
    u32 y;
};

STRUCT(WindowingSize)
{
    u32 width;
    u32 height;
};

STRUCT(WindowingInstantiate)
{
    String name;
    WindowingOffset offset;
    WindowingSize size;
    void* context;
};

fn u8 windowing_initialize();
fn WindowingInstance* windowing_instantiate(WindowingInstantiate instantiate);
fn void windowing_poll_events();
fn WindowingSize windowing_get_instance_framebuffer_size(WindowingInstance* window);
// NEW API END


// fn OSWindow os_window_create(OSWindowCreate create);
// fn u8 os_window_should_close(OSWindow window);
// fn OSCursorPosition os_window_cursor_position_get(OSWindow window);
//
// fn u8 os_event_queue_get_window_focus(OSEventQueue* queue, u32 index);

#ifndef __APPLE__
global_variable WindowingConnection windowing_connection;
global_variable WindowingInstance windowing_instances[256];
#endif
