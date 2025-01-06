#pragma once

#if BB_WINDOWING_BACKEND_X11
#define VK_USE_PLATFORM_XCB_KHR
#endif

#if BB_WINDOWING_BACKEND_COCOA
#define VK_USE_PLATFORM_METAL_EXT
#endif

#if BB_WINDOWING_BACKEND_WIN32
#define VK_USE_PLATFORM_WIN32_KHR
#endif

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

#define vulkan_function_pointer(n) PFN_ ## n n
#define vulkan_global_function_pointer(n) global_variable vulkan_function_pointer(n)
// INSTANCE FUNCTIONS START
// These functions require no instance
vulkan_global_function_pointer(vkGetInstanceProcAddr);
vulkan_global_function_pointer(vkEnumerateInstanceVersion);
vulkan_global_function_pointer(vkEnumerateInstanceLayerProperties);
vulkan_global_function_pointer(vkCreateInstance);

// These functions require an instance as a parameter
vulkan_global_function_pointer(vkGetDeviceProcAddr);
vulkan_global_function_pointer(vkCreateDebugUtilsMessengerEXT);
vulkan_global_function_pointer(vkEnumeratePhysicalDevices);
vulkan_global_function_pointer(vkGetPhysicalDeviceMemoryProperties);
vulkan_global_function_pointer(vkGetPhysicalDeviceProperties);
vulkan_global_function_pointer(vkGetPhysicalDeviceQueueFamilyProperties);
vulkan_global_function_pointer(vkGetPhysicalDeviceSurfaceCapabilitiesKHR);
vulkan_global_function_pointer(vkGetPhysicalDeviceSurfacePresentModesKHR);
vulkan_global_function_pointer(vkCreateDevice);

#if defined(VK_KHR_xcb_surface)
vulkan_global_function_pointer(vkCreateXcbSurfaceKHR);
#endif
#if defined(VK_KHR_win32_surface)
vulkan_global_function_pointer(vkCreateWin32SurfaceKHR);
#endif
#if defined(VK_EXT_metal_surface)
vulkan_global_function_pointer(vkCreateMetalSurfaceEXT);
#endif
// INSTANCE FUNCTIONS END

vulkan_global_function_pointer(vkCreateSwapchainKHR);
vulkan_global_function_pointer(vkCmdCopyBuffer2);
vulkan_global_function_pointer(vkAllocateMemory);
vulkan_global_function_pointer(vkCreateBuffer);
vulkan_global_function_pointer(vkGetBufferMemoryRequirements);
vulkan_global_function_pointer(vkBindBufferMemory);
vulkan_global_function_pointer(vkMapMemory);
vulkan_global_function_pointer(vkGetBufferDeviceAddress);
vulkan_global_function_pointer(vkResetFences);
vulkan_global_function_pointer(vkResetCommandBuffer);
vulkan_global_function_pointer(vkBeginCommandBuffer);
vulkan_global_function_pointer(vkEndCommandBuffer);
vulkan_global_function_pointer(vkQueueSubmit2);
vulkan_global_function_pointer(vkWaitForFences);
vulkan_global_function_pointer(vkCreateImage);
vulkan_global_function_pointer(vkGetImageMemoryRequirements);
vulkan_global_function_pointer(vkBindImageMemory);
vulkan_global_function_pointer(vkCreateImageView);
vulkan_global_function_pointer(vkCmdPipelineBarrier2);
vulkan_global_function_pointer(vkCmdBlitImage2);
vulkan_global_function_pointer(vkGetDeviceQueue);
vulkan_global_function_pointer(vkCreateCommandPool);
vulkan_global_function_pointer(vkAllocateCommandBuffers);
vulkan_global_function_pointer(vkCreateFence);
vulkan_global_function_pointer(vkCreateSampler);
vulkan_global_function_pointer(vkCreateShaderModule);
vulkan_global_function_pointer(vkCreateDescriptorSetLayout);
vulkan_global_function_pointer(vkCreatePipelineLayout);
vulkan_global_function_pointer(vkCreateGraphicsPipelines);
vulkan_global_function_pointer(vkDestroyImageView);
vulkan_global_function_pointer(vkDestroyImage);
vulkan_global_function_pointer(vkFreeMemory);
vulkan_global_function_pointer(vkDeviceWaitIdle);
vulkan_global_function_pointer(vkDestroySwapchainKHR);
vulkan_global_function_pointer(vkGetSwapchainImagesKHR);
vulkan_global_function_pointer(vkCreateDescriptorPool);
vulkan_global_function_pointer(vkAllocateDescriptorSets);
vulkan_global_function_pointer(vkCreateSemaphore);
vulkan_global_function_pointer(vkAcquireNextImageKHR);
vulkan_global_function_pointer(vkDestroyBuffer);
vulkan_global_function_pointer(vkUnmapMemory);
vulkan_global_function_pointer(vkCmdSetViewport);
vulkan_global_function_pointer(vkCmdSetScissor);
vulkan_global_function_pointer(vkCmdBeginRendering);
vulkan_global_function_pointer(vkCmdBindPipeline);
vulkan_global_function_pointer(vkCmdBindDescriptorSets);
vulkan_global_function_pointer(vkCmdBindIndexBuffer);
vulkan_global_function_pointer(vkCmdPushConstants);
vulkan_global_function_pointer(vkCmdDrawIndexed);
vulkan_global_function_pointer(vkCmdEndRendering);
vulkan_global_function_pointer(vkQueuePresentKHR);
vulkan_global_function_pointer(vkCmdCopyBufferToImage);
vulkan_global_function_pointer(vkUpdateDescriptorSets);
