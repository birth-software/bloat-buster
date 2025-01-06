#pragma once

#ifndef BUILD_DIR
#define BUILD_DIR "cache"
#endif

typedef enum RenderingBackend
{
    RENDERING_BACKEND_NONE,
    RENDERING_BACKEND_METAL,
    RENDERING_BACKEND_VULKAN,
    RENDERING_BACKEND_DIRECTX12,
    RENDERING_BACKEND_COUNT,
} RenderingBackend;

typedef enum WindowingBackend
{
    WINDOWING_BACKEND_NONE,
    WINDOWING_BACKEND_WIN32,
    WINDOWING_BACKEND_X11,
    WINDOWING_BACKEND_WAYLAND,
    WINDOWING_BACKEND_COCOA,
    WINDOWING_BACKEND_COUNT,
} WindowingBackend;

fn u8 rendering_backend_is_valid(RenderingBackend rendering_backend)
{
    u8 valid = rendering_backend != RENDERING_BACKEND_COUNT;

    if (valid && rendering_backend != RENDERING_BACKEND_NONE)
    {
#ifdef __linux__
        valid = rendering_backend == RENDERING_BACKEND_VULKAN;
#elif __APPLE__
        valid = rendering_backend == RENDERING_BACKEND_METAL || rendering_backend == RENDERING_BACKEND_VULKAN;
#elif _WIN32
        valid = rendering_backend == RENDERING_BACKEND_DIRECTX12 || rendering_backend == RENDERING_BACKEND_VULKAN;
#endif
    }

    return valid;
}

fn u8 windowing_backend_is_valid(WindowingBackend windowing_backend)
{
    u8 valid = windowing_backend != WINDOWING_BACKEND_COUNT;

    if (valid && windowing_backend != WINDOWING_BACKEND_NONE)
    {
#ifdef __linux__
        valid = windowing_backend == WINDOWING_BACKEND_WAYLAND || windowing_backend == WINDOWING_BACKEND_X11;
#elif _WIN32
        valid = windowing_backend == WINDOWING_BACKEND_WIN32;
#elif __APPLE__
        valid = windowing_backend == WINDOWING_BACKEND_COCOA;
#endif
    }
    
    return valid;
}
