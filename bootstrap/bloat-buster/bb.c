#include <std/base.h>

#if _WIN32
#else
#include <dlfcn.h>
STRUCT(OSLibrary)
{
    void* handle;
};
#endif

fn OSLibrary os_library_load(const char* library_name);

#if _WIN32
#else
fn OSLibrary os_library_load(const char* library_name)
{
    OSLibrary library = {};
    library.handle = dlopen(library_name, RTLD_NOW | RTLD_LOCAL);
    return library;
}
#endif

#ifdef __linux__
#define WINDOWING_BACKEND_X11 1
#define RENDERING_BACKEND_VULKAN 1
#else
#define WINDOWING_BACKEND_X11 0
#define RENDERING_BACKEND_VULKAN 0
#endif

#ifdef __APPLE__
#define WINDOWING_BACKEND_COCOA 1
#define RENDERING_BACKEND_METAL 1
#endif

#if WINDOWING_BACKEND_X11
#include <xcb/xcb.h>

STRUCT(WindowingConnection)
{
    xcb_connection_t* handle;
    const xcb_setup_t* setup;
};

STRUCT(WindowingInstance)
{
    xcb_window_t handle;
};
#endif

#if WINDOWING_BACKEND_COCOA
#include <Cocoa/Cocoa.h>
#endif

#if RENDERING_BACKEND_METAL
#import <Metal/Metal.h>
#import <Metal/Metal.h>
#endif

#if RENDERING_BACKEND_METAL

// Code from Volk
#ifndef VK_NO_PROTOTYPES
#define VK_NO_PROTOTYPES
#endif

#ifndef VULKAN_H_
#if defined(VK_USE_PLATFORM_WIN32_KHR)
#include <vulkan/vk_platform.h>
#include <vulkan/vulkan_core.h>

/* When VK_USE_PLATFORM_WIN32_KHR is defined, instead of including vulkan.h directly, we include individual parts of the SDK
* This is necessary to avoid including <windows.h> which is very heavy - it takes 200ms to parse without WIN32_LEAN_AND_MEAN
* and 100ms to parse with it. vulkan_win32.h only needs a few symbols that are easy to redefine ourselves.
*/
typedef unsigned long DWORD;
typedef const wchar_t* LPCWSTR;
typedef void* HANDLE;
typedef struct HINSTANCE__* HINSTANCE;
typedef struct HWND__* HWND;
typedef struct HMONITOR__* HMONITOR;
typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;

#include <vulkan/vulkan_win32.h>

#ifdef VK_ENABLE_BETA_EXTENSIONS
#include <vulkan/vulkan_beta.h>
#endif
#else
#include <vulkan/vulkan.h>
#endif
#endif

global_variable WindowingConnection windowing_connection;
global_variable WindowingInstance windowing_instances[256];

STRUCT(WindowOffset)
{
    u32 x;
    u32 y;
};

STRUCT(WindowSize)
{
    u32 width;
    u32 height;
};

STRUCT(WindowCreate)
{
    String name;
    WindowOffset offset;
    WindowSize size;
    void* context;
};

fn u8 windowing_connect();
fn WindowingInstance* windowing_instantiate(WindowCreate create);
fn void windowing_poll_events();

#if WINDOWING_BACKEND_X11
global_variable xcb_window_t windowing_instance_handles[256];

typedef enum WindowingEvent : u32
{
    WINDOWING_EVENT_CLOSE,
    WINDOWING_EVENT_COUNT,
} WindowingEvent;

fn void x11_intern_atoms(u32 atom_count, String* names, xcb_intern_atom_cookie_t* cookies, xcb_intern_atom_reply_t** replies)
{
    xcb_connection_t* connection = windowing_connection.handle;

    for (u64 i = 0; i < atom_count; i += 1)
    {
        String atom_name = names[i];

        cookies[i] = xcb_intern_atom(connection, 0, atom_name.length, string_to_c(atom_name));
    }

    for (u64 i = 0; i < atom_count; i += 1)
    {
        replies[i] = xcb_intern_atom_reply(connection, cookies[i], 0);
    }
}

enum X11Atom
{
    X11_ATOM_WM_PROTOCOLS,
    X11_ATOM_WM_DELETE_WINDOW,
    X11_ATOM_COUNT,
};

global_variable String atom_names[X11_ATOM_COUNT] = {
    strlit("WM_PROTOCOLS"),
    strlit("WM_DELETE_WINDOW"),
};
global_variable xcb_intern_atom_reply_t* atom_replies[array_length(atom_names)];
global_variable xcb_intern_atom_cookie_t atom_cookies[array_length(atom_names)];

fn u8 windowing_initialize()
{
    u8 result = 0;

    windowing_connection.handle = xcb_connect(0, 0);
    if (windowing_connection.handle)
    {
        if (!xcb_connection_has_error(windowing_connection.handle))
        {
            windowing_connection.setup = xcb_get_setup(windowing_connection.handle);

            if (windowing_connection.setup)
            {
                x11_intern_atoms(array_length(atom_names), atom_names, atom_cookies, atom_replies);

                if (atom_replies[X11_ATOM_WM_PROTOCOLS])
                {
                    if (atom_replies[X11_ATOM_WM_DELETE_WINDOW])
                    {
                        result = 1;
                    }
                }
            }
        }
    }

    return result;
}

fn WindowingInstance* windowing_instantiate(WindowCreate create)
{
    xcb_connection_t* connection = windowing_connection.handle;
    xcb_screen_iterator_t iter = xcb_setup_roots_iterator(windowing_connection.setup);
    xcb_screen_t *screen = iter.data;

    /* Create a window */
    xcb_window_t window_handle = xcb_generate_id(connection);

    u32 i;
    for (i = 0; i < array_length(windowing_instance_handles); i += 1)
    {
        xcb_window_t* window_handle_pointer = &windowing_instance_handles[i];
        if (!*window_handle_pointer)
        {
            *window_handle_pointer = window_handle;
            break;
        }
    }

    WindowingInstance* window = &windowing_instances[i];
    window->handle = window_handle;

    uint32_t value_mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
    uint32_t value_list[] = {
        screen->black_pixel,
        XCB_EVENT_MASK_EXPOSURE | XCB_EVENT_MASK_KEY_PRESS | XCB_EVENT_MASK_STRUCTURE_NOTIFY
    };

    xcb_create_window(
        connection,                     /* Connection */
        XCB_COPY_FROM_PARENT,           /* Depth (same as parent) */
        window_handle,                         /* Window ID */
        screen->root,                   /* Parent window (root) */
        create.offset.x, create.offset.y,                       /* X, Y */
        create.size.width, create.size.height,
        10,                             /* Border width */
        XCB_WINDOW_CLASS_INPUT_OUTPUT,  /* Class */
        screen->root_visual,            /* Visual */
        value_mask,                     /* Value mask */
        value_list                      /* Value list */
    );

    xcb_change_property(connection, XCB_PROP_MODE_REPLACE, window_handle, atom_replies[X11_ATOM_WM_PROTOCOLS]->atom, XCB_ATOM_ATOM, 32, 1, &atom_replies[X11_ATOM_WM_DELETE_WINDOW]->atom);

    xcb_map_window(connection, window_handle);

    /* Flush requests to the X server */
    xcb_flush(connection);

    return window;
}

fn void windowing_poll_events()
{
    xcb_generic_event_t *event;
    xcb_connection_t* connection = windowing_connection.handle;

    while ((event = xcb_poll_for_event(connection)))
    {
        switch (event->response_type & ~0x80) {
            case XCB_EXPOSE:
                break;
            case XCB_KEY_PRESS:
                break;
            case XCB_CLIENT_MESSAGE:
                {
                    pointer_cast(xcb_client_message_event_t, client_message_event, event);
                    if (client_message_event->data.data32[0] == atom_replies[X11_ATOM_WM_DELETE_WINDOW]->atom)
                    {
                        xcb_window_t window_handle = client_message_event->window;
                        u32 i;
                        u32 window_handle_count = array_length(windowing_instance_handles);
                        for (i = 0; i < window_handle_count; i += 1)
                        {
                            xcb_window_t* window_handle_pointer = &windowing_instance_handles[i];
                            if (window_handle == *window_handle_pointer)
                            {
                                windowing_instances[i].handle = 0;
                                *window_handle_pointer = 0;
                                // TODO: For now do this
                                exit(0);
                                break;
                            }
                        }

                        if (i == window_handle_count)
                        {
                            exit(1);
                        }
                    }
                    else
                    {
                        trap();
                    }
                } break;
            case XCB_DESTROY_NOTIFY:
                trap();
            default:
                break;
        }
        free(event);
    }
}
#endif

#if WINDOWING_BACKEND_COCOA
@interface AppleApplicationDelegate : NSObject<NSApplicationDelegate>
@end
@interface AppleWindow : NSWindow
@end
@interface AppleWindowDelegate : NSObject<NSWindowDelegate>
@end

@implementation AppleApplicationDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)aNotification
{
    trap();
}

@end
@implementation AppleWindow
@end

fn u8 windowing_initialize()
{
    u8 result = 1;
    [NSApplication sharedApplication];
    AppleApplicationDelegate* application_delegate; 
    application_delegate = [[AppleApplicationDelegate alloc] init];
    NSApp.delegate = application_delegate;
    [NSApp run];

    return result;
}

fn OSWindow window_create(WindowCreate create)
{
}

fn void windowing_poll_events()
{
}
#endif

#if RENDERING_BACKEND_VULKAN
fn void rendering_initialize()
{
#ifdef _WIN32
#endif
    os_library_load
    vol
    vkGetInstanceProcAddr = (PFN_vkGetInstanceProcAddr)dlsym(module, "vkGetInstanceProcAddr");
}
#endif

int main()
{
    if (!windowing_initialize())
    {
        return 1;
    }

    WindowCreate window_create_options = {
        .name = strlit("Bloat Buster"),
        .size = { .width = 1600, .height = 900 },
    };
    windowing_instantiate(window_create_options);

    while (1)
    {
        windowing_poll_events();
    }

    return 0;
}
