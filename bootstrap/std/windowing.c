#if BB_WINDOWING_BACKEND_X11
#include <std/x11_windowing.c>
#endif

#if BB_WINDOWING_BACKEND_WAYLAND
#include <std/wayland_windowing.c>
#endif

#if BB_WINDOWING_BACKEND_COCOA
#include <std/cocoa_windowing.c>
#endif

#if BB_WINDOWING_BACKEND_WIN32
#include <std/win32_windowing.c>
#endif
