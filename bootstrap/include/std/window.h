#pragma once

#include <std/base.h>
#include <std/os.h>
#include <std/virtual_buffer.h>

typedef enum OSEventType
{
    OS_EVENT_TYPE_MOUSE_BUTTON,
    OS_EVENT_TYPE_CURSOR_POSITION,
    OS_EVENT_TYPE_CURSOR_ENTER,
    OS_EVENT_TYPE_WINDOW_FOCUS,
    OS_EVENT_TYPE_WINDOW_POSITION,
    OS_EVENT_TYPE_WINDOW_CLOSE,
} OSEventType;

STRUCT(OSEventDescriptor)
{
    u32 index:24;
    OSEventType type:8;
};
static_assert(sizeof(OSEventDescriptor) == 4);
decl_vb(OSEventDescriptor);

typedef enum OSEventMouseButtonKind : u8
{
    OS_EVENT_MOUSE_BUTTON_1 = 0,
    OS_EVENT_MOUSE_BUTTON_2 = 1,
    OS_EVENT_MOUSE_BUTTON_3 = 2,
    OS_EVENT_MOUSE_BUTTON_4 = 3,
    OS_EVENT_MOUSE_BUTTON_5 = 4,
    OS_EVENT_MOUSE_BUTTON_6 = 5,
    OS_EVENT_MOUSE_BUTTON_7 = 6,
    OS_EVENT_MOUSE_BUTTON_8 = 7,
    OS_EVENT_MOUSE_BUTTON_COUNT = 8,
    OS_EVENT_MOUSE_LEFT = OS_EVENT_MOUSE_BUTTON_1,
    OS_EVENT_MOUSE_RIGHT = OS_EVENT_MOUSE_BUTTON_2,
    OS_EVENT_MOUSE_MIDDLE = OS_EVENT_MOUSE_BUTTON_3,
} OSEventMouseButtonKind;

typedef enum OSEventMouseButtonAction : u8
{
    OS_EVENT_MOUSE_RELAX = 0,
    OS_EVENT_MOUSE_RELEASE = 1,
    OS_EVENT_MOUSE_PRESS = 2,
    OS_EVENT_MOUSE_REPEAT = 3,
} OSEventMouseButtonAction;

STRUCT(OSEventMouseButtonEvent)
{
    OSEventMouseButtonAction action:2;
    u8 mod_shift:1;
    u8 mod_control:1;
    u8 mod_alt:1;
    u8 mod_super:1;
    u8 mod_caps_lock:1;
    u8 mod_num_lock:1;
};

STRUCT(OSEventMouseButton)
{
    OSEventMouseButtonKind button:3;
    u8 reserved:5;
    OSEventMouseButtonEvent event;
};
static_assert(sizeof(OSEventMouseButton) == sizeof(u16));
decl_vb(OSEventMouseButton);

#define OS_EVENT_BITSET_SIZE (64)
STRUCT(OSEventBitset)
{
    u64 value;
};
decl_vb(OSEventBitset);

STRUCT(OSEventCursorPosition)
{
    f64 x;
    f64 y;
};
decl_vb(OSEventCursorPosition);

STRUCT(OSEventWindowPosition)
{
    u32 x;
    u32 y;
};
decl_vb(OSEventWindowPosition);

STRUCT(OSEventQueue)
{
    VirtualBuffer(OSEventDescriptor) descriptors;
    VirtualBuffer(OSEventMouseButton) mouse_buttons;
    VirtualBuffer(OSEventBitset) window_focuses;
    u32 window_focuses_count;
    u32 cursor_enter_count;
    VirtualBuffer(OSEventBitset) cursor_enters;
    VirtualBuffer(OSEventCursorPosition) cursor_positions;
    VirtualBuffer(OSEventWindowPosition) window_positions;
};

typedef void* OSWindow;

typedef void OSFramebufferResize(OSWindow window, void* context, u32 width, u32 height);
typedef void OSWindowResize(OSWindow window, void* context, u32 width, u32 height);
typedef void OSWindowRefresh(OSWindow window, void* context);
typedef void OSWindowPosition(OSWindow window, void* context, u32 x, u32 y);
typedef void OSWindowClose(OSWindow window, void* context);
typedef void OSWindowFocus(OSWindow window, void* context, u8 focused);
typedef void OSWindowIconify(OSWindow window, void* context, u8 iconified);
typedef void OSWindowMaximize(OSWindow window, void* context, u8 maximized);
typedef void OSWindowContentScale(OSWindow window, void* context, f32 x, f32 y);
typedef void OSWindowKey(OSWindow window, void* context, s32 key, s32 scancode, s32 action, s32 mods);
typedef void OSWindowCharacter(OSWindow window, void* context, u32 codepoint);
typedef void OSWindowCharacterModifier(OSWindow window, void* context, u32 codepoint, s32 mods);
typedef void OSWindowMouseButton(OSWindow window, void* context, s32 button, s32 action, s32 mods);
typedef void OSWindowCursorPosition(OSWindow window, void* context, f64 x, f64 y);
typedef void OSWindowCursorEnter(OSWindow window, void* context, u8 entered);
typedef void OSWindowScroll(OSWindow window, void* context, f64 x, f64 y);
typedef void OSWindowDrop(OSWindow window, void* context, CStringSlice paths);

STRUCT(OSWindowingCallbacks)
{
    OSFramebufferResize* framebuffer_resize;
    OSWindowResize* window_resize;
    OSWindowRefresh* window_refresh;
    OSWindowPosition* window_position;
    OSWindowClose* window_close;
    OSWindowFocus* window_focus;
    OSWindowIconify* window_iconify;
    OSWindowMaximize* window_maximize;
    OSWindowContentScale* window_content_scale;
    OSWindowKey* window_key;
    OSWindowCharacter* window_character;
    OSWindowCharacterModifier* window_character_modifier;
    OSWindowMouseButton* window_mouse_button;
    OSWindowCursorPosition* window_cursor_position;
    OSWindowCursorEnter* window_cursor_enter;
    OSWindowScroll* window_scroll;
    OSWindowDrop* window_drop;
};

STRUCT(OSWindowingInitializationOptions)
{
    OSWindowingCallbacks callback;
    u8 should_use_x11;
};

STRUCT(OSWindowSize)
{
    u32 width;
    u32 height;
};

STRUCT(OSWindowCreate)
{
    String name;
    OSWindowSize size;
    void* context;
    OSWindowResize* resize_callback;
    OSWindowRefresh* refresh_callback;
};

STRUCT(OSCursorPosition)
{
    f64 x;
    f64 y;
};

EXPORT void os_windowing_init(OSWindowingInitializationOptions options);
EXPORT OSWindow os_window_create(OSWindowCreate create);
EXPORT u8 os_window_should_close(OSWindow window);
EXPORT void os_poll_events(OSEventQueue* event_queue);
EXPORT OSCursorPosition os_window_cursor_position_get(OSWindow window);
EXPORT OSWindowSize os_window_framebuffer_size_get(OSWindow window);

EXPORT u8 os_event_queue_get_window_focus(OSEventQueue* queue, u32 index);

#ifdef __linux__
typedef unsigned long XID;
typedef struct _XDisplay Display;
typedef XID Window;

EXPORT Display* x11_display_get();
EXPORT Window x11_window_get(OSWindow window);
#endif

#ifdef _WIN32
EXPORT HANDLE win32_window_get(OSWindow window);
#endif

int window_create_surface(void* instance, OSWindow window, const void* allocator, void** surface);
