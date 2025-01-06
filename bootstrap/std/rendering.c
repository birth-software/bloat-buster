#pragma once

#include <std/font_provider.c>

#if BB_RENDERING_BACKEND_VULKAN
#include <std/vulkan_rendering.c>
#endif

#if BB_RENDERING_BACKEND_METAL
#include <std/metal_rendering.c>
#endif

#if BB_RENDERING_BACKEND_DIRECTX12
#include <std/directx12_rendering.c>
#endif
