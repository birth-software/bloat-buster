#include <std/render.h>
#include <std/shader_compilation.h>
#include <std/string.h>
#include <std/image_loader.h>
#include <std/virtual_buffer.h>

#include <volk.h>

#define MAX_SWAPCHAIN_IMAGE_COUNT (16)
#define MAX_FRAME_COUNT (2)
#define MAX_DESCRIPTOR_SET_COUNT (16)
#define MAX_PUSH_CONSTANT_RANGE_COUNT (16)
#define MAX_SHADER_MODULE_COUNT_PER_PIPELINE (16)
#define MAX_DESCRIPTOR_SET_LAYOUT_COUNT (16)
#define MAX_DESCRIPTOR_SET_LAYOUT_BINDING_COUNT (16)
#define MAX_TEXTURE_COUNT (16)
#define MAX_TEXTURE_UPDATE_COUNT (32)
#define MAX_DESCRIPTOR_SET_UPDATE_COUNT (16)
#define MAX_LOCAL_BUFFER_COPY_COUNT (16)

#define vkok(call) do {\
    VkResult _r_e_s_u_l_t_ = call; \
    if (unlikely(_r_e_s_u_l_t_ != VK_SUCCESS)) wrong_vulkan_result(_r_e_s_u_l_t_, strlit(#call), strlit(__FILE__), __LINE__); \
} while(0)

STRUCT(VulkanImageCreate)
{
    u32 width;
    u32 height;
    u32 mip_levels;
    VkFormat format;
    VkImageUsageFlags usage;
};

STRUCT(GPUMemory)
{
    VkDeviceMemory handle;
    u64 size;
};

STRUCT(VulkanImage)
{
    VkImage handle;
    VkImageView view;
    GPUMemory memory;
    VkFormat format;
};

STRUCT(GPUDrawPushConstants)
{
    u64 vertex_buffer;
    f32 width;
    f32 height;
};

STRUCT(DescriptorSetLayoutBindings)
{
    VkDescriptorSetLayoutBinding buffer[MAX_DESCRIPTOR_SET_LAYOUT_BINDING_COUNT];
    u32 count;
};

STRUCT(Pipeline)
{
    VkPipeline handle;
    VkPipelineLayout layout;
    u32 descriptor_set_count;
    u32 push_constant_range_count;
    DescriptorSetLayoutBindings descriptor_set_layout_bindings[MAX_DESCRIPTOR_SET_COUNT];
    VkDescriptorSetLayout descriptor_set_layouts[MAX_DESCRIPTOR_SET_COUNT];
    VkPushConstantRange push_constant_ranges[MAX_PUSH_CONSTANT_RANGE_COUNT];
};

STRUCT(RectPipeline)
{
    Pipeline pipeline;
};

STRUCT(ImmediateContext)
{
    VkDevice device;
    VkFence fence;
    VkCommandBuffer command_buffer;
    VkCommandPool command_pool;
    VkQueue queue;
};

STRUCT(VulkanBuffer)
{
    VkBuffer handle;
    GPUMemory memory;
    u64 address;
    VkDeviceSize size;
    BufferType type;
};

STRUCT(LocalBufferCopy)
{
    VulkanBuffer destination;
    VulkanBuffer source;
    Slice(LocalBufferCopyRegion) regions;
};
declare_slice(LocalBufferCopy);

STRUCT(VertexBuffer)
{
    VulkanBuffer gpu;
    VirtualBuffer(u8) cpu;
    u32 count;
};

STRUCT(IndexBuffer)
{
    VulkanBuffer gpu;
    VirtualBuffer(u32) cpu;
};

STRUCT(Renderer)
{
    VkInstance instance;
    VkAllocationCallbacks* allocator;
    VkPhysicalDevice physical_device;
    VkDevice device;
    VkQueue graphics_queue;
    u32 graphics_queue_family_index;
    VkSampler sampler;
    ImmediateContext immediate;
    VkPhysicalDeviceMemoryProperties memory_properties;
    Pipeline pipelines[BB_PIPELINE_COUNT];
    TextureAtlas fonts[RENDER_FONT_TYPE_COUNT];
};

STRUCT(PipelineInstantiation)
{
    VkWriteDescriptorSet descriptor_set_update;
    VkDescriptorSet descriptor_sets[MAX_DESCRIPTOR_SET_COUNT];
    VkDescriptorImageInfo texture_descriptors[MAX_TEXTURE_UPDATE_COUNT];
};

STRUCT(FramePipelineInstantiation)
{
    VertexBuffer vertex_buffer;
    IndexBuffer index_buffer;
    VulkanBuffer transient_buffer;
};

STRUCT(WindowFrame)
{
    VkCommandPool command_pool;
    VkCommandBuffer command_buffer;
    VkSemaphore swapchain_semaphore;
    VkSemaphore render_semaphore;
    VkFence render_fence;
    BBPipeline bound_pipeline;
    VkBuffer index_buffer;
    GPUDrawPushConstants push_constants;
    FramePipelineInstantiation pipeline_instantiations[BB_PIPELINE_COUNT];
};

STRUCT(RenderWindow)
{
    VkSwapchainKHR swapchain;
    VkSurfaceKHR surface;
    VkFormat swapchain_image_format;
    u32 width;
    u32 height;
    u32 last_width;
    u32 last_height;
    u32 frame_index;
    u32 swapchain_image_index;
    u32 swapchain_image_count;
    VulkanImage render_image;
    VkImage swapchain_images[MAX_SWAPCHAIN_IMAGE_COUNT];
    VkImageView swapchain_image_views[MAX_SWAPCHAIN_IMAGE_COUNT];
    WindowFrame frames[MAX_FRAME_COUNT];
    PipelineInstantiation pipeline_instantiations[BB_PIPELINE_COUNT];
};

STRUCT(VulkanTexture)
{
    VulkanImage image;
    VkSampler sampler;
};

STRUCT(VulkanCopyImage)
{
    VkImage handle;
    VkExtent2D extent;
};

STRUCT(VulkanCopyImageArgs)
{
    VulkanCopyImage source;
    VulkanCopyImage destination;
};


global_variable Renderer renderer_memory;
global_variable RenderWindow renderer_window_memory;
global_variable VulkanTexture textures[MAX_TEXTURE_COUNT];
global_variable u32 texture_count;

fn String vulkan_result_to_string(VkResult result)
{
    switch (result)
    {
        case_to_name(VK_, SUCCESS);
        case_to_name(VK_, NOT_READY);
        case_to_name(VK_, TIMEOUT);
        case_to_name(VK_, EVENT_SET);
        case_to_name(VK_, EVENT_RESET);
        case_to_name(VK_, INCOMPLETE);
        case_to_name(VK_, ERROR_OUT_OF_HOST_MEMORY);
        case_to_name(VK_, ERROR_OUT_OF_DEVICE_MEMORY);
        case_to_name(VK_, ERROR_INITIALIZATION_FAILED);
        case_to_name(VK_, ERROR_DEVICE_LOST);
        case_to_name(VK_, ERROR_MEMORY_MAP_FAILED);
        case_to_name(VK_, ERROR_LAYER_NOT_PRESENT);
        case_to_name(VK_, ERROR_EXTENSION_NOT_PRESENT);
        case_to_name(VK_, ERROR_FEATURE_NOT_PRESENT);
        case_to_name(VK_, ERROR_INCOMPATIBLE_DRIVER);
        case_to_name(VK_, ERROR_TOO_MANY_OBJECTS);
        case_to_name(VK_, ERROR_FORMAT_NOT_SUPPORTED);
        case_to_name(VK_, ERROR_FRAGMENTED_POOL);
        case_to_name(VK_, ERROR_UNKNOWN);
        case_to_name(VK_, ERROR_OUT_OF_POOL_MEMORY);
        case_to_name(VK_, ERROR_INVALID_EXTERNAL_HANDLE);
        case_to_name(VK_, ERROR_FRAGMENTATION);
        case_to_name(VK_, ERROR_INVALID_OPAQUE_CAPTURE_ADDRESS);
        case_to_name(VK_, PIPELINE_COMPILE_REQUIRED);
        case_to_name(VK_, ERROR_SURFACE_LOST_KHR);
        case_to_name(VK_, ERROR_NATIVE_WINDOW_IN_USE_KHR);
        case_to_name(VK_, SUBOPTIMAL_KHR);
        case_to_name(VK_, ERROR_OUT_OF_DATE_KHR);
        case_to_name(VK_, ERROR_INCOMPATIBLE_DISPLAY_KHR);
        case_to_name(VK_, ERROR_VALIDATION_FAILED_EXT);
        case_to_name(VK_, ERROR_INVALID_SHADER_NV);
        case_to_name(VK_, ERROR_IMAGE_USAGE_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_VIDEO_PICTURE_LAYOUT_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_VIDEO_PROFILE_OPERATION_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_VIDEO_PROFILE_FORMAT_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_VIDEO_PROFILE_CODEC_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_VIDEO_STD_VERSION_NOT_SUPPORTED_KHR);
        case_to_name(VK_, ERROR_INVALID_DRM_FORMAT_MODIFIER_PLANE_LAYOUT_EXT);
        case_to_name(VK_, ERROR_NOT_PERMITTED_KHR);
        case_to_name(VK_, ERROR_FULL_SCREEN_EXCLUSIVE_MODE_LOST_EXT);
        case_to_name(VK_, THREAD_IDLE_KHR);
        case_to_name(VK_, THREAD_DONE_KHR);
        case_to_name(VK_, OPERATION_DEFERRED_KHR);
        case_to_name(VK_, OPERATION_NOT_DEFERRED_KHR);
        case_to_name(VK_, ERROR_INVALID_VIDEO_STD_PARAMETERS_KHR);
        case_to_name(VK_, ERROR_COMPRESSION_EXHAUSTED_EXT);
        //case_to_name(VK_, INCOMPATIBLE_SHADER_BINARY_EXT);
        //case_to_name(VK_, PIPELINE_BINARY_MISSING_KHR);
        //case_to_name(VK_, ERROR_NOT_ENOUGH_SPACE_KHR);
        default: unreachable();
    }
}

[[noreturn]] [[gnu::cold]] fn void wrong_vulkan_result(VkResult result, String call_string, String file, int line)
{
    unused(result);
    unused(call_string);
    unused(file);
    unused(line);

    String result_name = vulkan_result_to_string(result);
    my_panic("Wrong Vulkan result {s} at \"{s}\" {s}:{u32}\n", result_name, call_string, file, line);
}

fn void buffer_copy_to_local_command(VkCommandBuffer command_buffer, Slice(LocalBufferCopy) copies)
{
    for (u64 i = 0; i < copies.length; i += 1)
    {
        auto copy = copies.pointer[i];
        auto* source_buffer = &copy.source;
        auto* destination_buffer = &copy.destination;

        VkBufferCopy2 buffer_copies[MAX_LOCAL_BUFFER_COPY_COUNT];

        for (u64 i = 0; i < copy.regions.length; i += 1)
        {
            auto copy_region = copy.regions.pointer[i];
            buffer_copies[i] = (VkBufferCopy2) {
                .sType = VK_STRUCTURE_TYPE_BUFFER_COPY_2,
                .pNext = 0,
                .srcOffset = copy_region.source_offset,
                .dstOffset = copy_region.destination_offset,
                .size = copy_region.size,
            };
        }

        VkCopyBufferInfo2 info = {
            .sType = VK_STRUCTURE_TYPE_COPY_BUFFER_INFO_2,
            .pNext = 0,
            .srcBuffer = source_buffer->handle,
            .dstBuffer = destination_buffer->handle,
            .regionCount = copy.regions.length,
            .pRegions = buffer_copies,
        };

        vkCmdCopyBuffer2(command_buffer, &info);
    }
}

void buffer_copy_to_host(VulkanBuffer buffer, Slice(HostBufferCopy) regions)
{
    assert(buffer.type == BUFFER_TYPE_STAGING);

    auto* buffer_pointer = (u8*)buffer.address;

    for (u64 i = 0; i < regions.length; i += 1)
    {
        auto region = regions.pointer[i];
        auto* destination = buffer_pointer + region.destination_offset;
        assert(destination + region.source.length <= (u8*)buffer.address + buffer.size);
#define USE_MEMCPY 1
#if USE_MEMCPY
        memcpy(destination, region.source.pointer, region.source.length);
#else
        for (u64 i = 0; i < region.source.length; i += 1)
        {
            destination[i] = region.source.pointer[i];
        }
#endif
    }
}

fn VkShaderStageFlags vulkan_shader_stage_from_path(String shader_source_path)
{
    VkShaderStageFlags shader_stage;
    if (string_ends_with(shader_source_path, strlit(".vert")))
    {
        shader_stage = VK_SHADER_STAGE_VERTEX_BIT;
    }
    else if (string_ends_with(shader_source_path, strlit(".frag")))
    {
        shader_stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    }
    else
    {
        failed_execution();
    }

    return shader_stage;
}

fn VkShaderStageFlags vulkan_shader_stage(ShaderStage shader_stage)
{
    VkShaderStageFlags result;

    switch (shader_stage)
    {
    case SHADER_STAGE_VERTEX:
        result = VK_SHADER_STAGE_VERTEX_BIT;
        break;
    case SHADER_STAGE_FRAGMENT:
        result = VK_SHADER_STAGE_FRAGMENT_BIT;
        break;
    }

    return result;
}

fn VkDescriptorType vulkan_descriptor_type(DescriptorType type)
{
    VkDescriptorType result;

    switch (type)
    {
        case DESCRIPTOR_TYPE_IMAGE_PLUS_SAMPLER:
            result = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
            break;
        case DESCRIPTOR_TYPE_COUNT:
            unreachable();
        }

    return result;
}

fn DescriptorType descriptor_type_from_vulkan(VkDescriptorType descriptor_type)
{
    DescriptorType result;

    switch (descriptor_type)
    {
        case VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
            result = DESCRIPTOR_TYPE_IMAGE_PLUS_SAMPLER;
            break;
        default: unreachable();
    }

    return result;
}

fn ShaderStage shader_stage_from_path(String shader_source_path)
{
    ShaderStage shader_stage;
    if (string_ends_with(shader_source_path, strlit(".vert")))
    {
        shader_stage = SHADER_STAGE_VERTEX;
    }
    else if (string_ends_with(shader_source_path, strlit(".frag")))
    {
        shader_stage = SHADER_STAGE_FRAGMENT;
    }
    else
    {
        failed_execution();
    }

    return shader_stage;
}

fn GPUMemory vk_allocate_memory(VkDevice device, const VkAllocationCallbacks* allocation_callbacks, VkPhysicalDeviceMemoryProperties memory_properties, VkMemoryRequirements memory_requirements, VkMemoryPropertyFlags flags, u8 use_device_address_bit)
{
    u32 memory_type_index;
    for (memory_type_index = 0; memory_type_index < memory_properties.memoryTypeCount; memory_type_index += 1)
    {
        auto memory_type = memory_properties.memoryTypes[memory_type_index];

        if ((memory_requirements.memoryTypeBits & (1 << memory_type_index)) != 0 && (memory_type.propertyFlags & flags) == flags)
        {
            break;
        }
    }

    if (memory_type_index == memory_properties.memoryTypeCount)
    {
        failed_execution();
    }

    VkMemoryAllocateInfo allocate_info = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .pNext = 0,
        .allocationSize = memory_requirements.size,
        .memoryTypeIndex = memory_type_index,
    };

    VkMemoryAllocateFlagsInfo flags_info = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO,
        .pNext = 0,
        .flags = VK_MEMORY_ALLOCATE_DEVICE_ADDRESS_BIT,
        .deviceMask = 1,
    };

    if (use_device_address_bit)
    {
        allocate_info.pNext = &flags_info;
    }

    VkDeviceMemory memory = 0;
    vkok(vkAllocateMemory(device, &allocate_info, allocation_callbacks, &memory));

    return (GPUMemory) { .handle = memory, .size = allocate_info.allocationSize };
}

fn VulkanBuffer vk_buffer_create(VkDevice device, const VkAllocationCallbacks* allocation_callbacks, VkPhysicalDeviceMemoryProperties physical_device_memory_properties, VkDeviceSize buffer_size, VkBufferUsageFlags usage_flags, VkMemoryPropertyFlags memory_flags)
{
    VulkanBuffer result = {
        .size = buffer_size,
    };

    VkBufferCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .size = buffer_size,
        .usage = usage_flags,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .queueFamilyIndexCount = 0,
        .pQueueFamilyIndices = 0,
    };
    vkok(vkCreateBuffer(device, &create_info, allocation_callbacks, &result.handle));

    VkMemoryRequirements memory_requirements;
    vkGetBufferMemoryRequirements(device, result.handle, &memory_requirements);

    u8 use_device_address_bit = !!(create_info.usage & VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT);
    result.memory = vk_allocate_memory(device, allocation_callbacks, physical_device_memory_properties, memory_requirements, memory_flags, use_device_address_bit);

    VkDeviceSize memory_offset = 0;
    vkok(vkBindBufferMemory(device, result.handle, result.memory.handle, memory_offset));

    u8 map_memory = !!(memory_flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT);
    assert(((map_memory | use_device_address_bit) == 0) | (map_memory == !use_device_address_bit));
    if (map_memory)
    {
        void* data = 0;
        VkDeviceSize offset = 0;
        VkMemoryMapFlags map_flags = 0;
        vkok(vkMapMemory(device, result.memory.handle, offset, memory_requirements.size, map_flags, &data));
        result.address = (u64)data;
    }

    if (use_device_address_bit)
    {
        VkBufferDeviceAddressInfo device_address_info = {
            .sType = VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO,
            .pNext = 0,
            .buffer = result.handle,
        };
        result.address = vkGetBufferDeviceAddress(device, &device_address_info);
    }

    return result;
}

fn VulkanBuffer buffer_create(Renderer* renderer, u64 size, BufferType type)
{
    u8 is_dst = (type == BUFFER_TYPE_VERTEX) | (type == BUFFER_TYPE_INDEX);
    u8 is_src = type == BUFFER_TYPE_STAGING;

    VkBufferUsageFlags usage = 
        (VK_BUFFER_USAGE_TRANSFER_DST_BIT * is_dst) |
        (VK_BUFFER_USAGE_TRANSFER_SRC_BIT * is_src) |
        ((VK_BUFFER_USAGE_SHADER_DEVICE_ADDRESS_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT) * (type == BUFFER_TYPE_VERTEX)) |
        (VK_BUFFER_USAGE_INDEX_BUFFER_BIT * (type == BUFFER_TYPE_INDEX));
    VkMemoryPropertyFlags memory_flags =
        (VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT * is_dst) |
        ((VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) * is_src);
    auto result = vk_buffer_create(renderer->device, renderer->allocator, renderer->memory_properties, size, usage, memory_flags);
    result.type = type;
    return result;
}

fn u8 vk_layer_is_supported(String layer_name)
{
    assert(layer_name.pointer[layer_name.length] == 0);

    VkLayerProperties layers[256];
    u32 layer_count;

    vkok(vkEnumerateInstanceLayerProperties(&layer_count, 0));

    if (layer_count > array_length(layers))
    {
        failed_execution();
    }

    vkok(vkEnumerateInstanceLayerProperties(&layer_count, layers));

    u8 supported = 0;
    for (u32 i = 0; i < layer_count; i += 1)
    {
        VkLayerProperties* properties = &layers[i];

        auto candidate_layer_name = cstr(properties->layerName);
        if (s_equal(candidate_layer_name, layer_name))
        {
            supported = 1;
            break;
        }
    }

    return supported;
}

#if BB_DEBUG

fn String message_severity_to_string(VkDebugUtilsMessageSeverityFlagBitsEXT message_severity)
{
    switch (message_severity)
    {
    case VK_DEBUG_UTILS_MESSAGE_SEVERITY_VERBOSE_BIT_EXT:
        return strlit("VERBOSE");
    case VK_DEBUG_UTILS_MESSAGE_SEVERITY_INFO_BIT_EXT:
        return strlit("INFO");
    case VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT:
        return strlit("WARNING");
    case VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT:
        return strlit("ERROR");
    case VK_DEBUG_UTILS_MESSAGE_SEVERITY_FLAG_BITS_MAX_ENUM_EXT:
        unreachable();
    }
}

fn String message_type_to_string(VkDebugUtilsMessageTypeFlagBitsEXT message_type)
{
    switch (message_type)
    {
    case VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT:
        return strlit("GENERAL");
    case VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT:
        return strlit("VALIDATION");
    case VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT:
        return strlit("PERFORMANCE");
    case VK_DEBUG_UTILS_MESSAGE_TYPE_DEVICE_ADDRESS_BINDING_BIT_EXT:
        return strlit("DEVICE_ADDRESS_BINDING");
    case VK_DEBUG_UTILS_MESSAGE_TYPE_FLAG_BITS_MAX_ENUM_EXT:
        unreachable();
    }
}

fn VkBool32 VKAPI_CALL debug_callback(VkDebugUtilsMessageSeverityFlagBitsEXT message_severity, VkDebugUtilsMessageTypeFlagsEXT message_type, const VkDebugUtilsMessengerCallbackDataEXT* callback_data, void* user_data)
{
    unused(user_data);

    if (callback_data->pMessage)
    {
        print("Validation message ({s}) ({s}) ({cstr}): {cstr}\n", message_severity_to_string(message_severity), message_type_to_string(message_type), callback_data->pMessageIdName ? callback_data->pMessageIdName : "ID_NONE", callback_data->pMessage);
    }

    if (message_severity & VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT)
    {
        failed_execution();
    }

    return VK_FALSE;
}

#endif

fn void immediate_start(ImmediateContext context)
{
    VkFence fences[] = { context.fence };
    VkCommandBufferResetFlags reset_flags = 0;

    vkok(vkResetFences(context.device, array_length(fences), fences));
    vkok(vkResetCommandBuffer(context.command_buffer, reset_flags));

    VkCommandBufferBeginInfo command_buffer_begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    vkok(vkBeginCommandBuffer(context.command_buffer, &command_buffer_begin_info));
}

fn void immediate_end(ImmediateContext context)
{
    VkFence fences[] = { context.fence };

    vkok(vkEndCommandBuffer(context.command_buffer));

    VkCommandBufferSubmitInfo command_buffer_submit_infos[] = {
        {
            .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_SUBMIT_INFO,
            .pNext = 0,
            .deviceMask = 0,
            .commandBuffer = context.command_buffer,
        }
    };

    VkSubmitFlags submit_flags = 0;

    VkSubmitInfo2 submit_info[] = {
        {
            .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO_2,
            .pNext = 0,
            .flags = submit_flags,
            .waitSemaphoreInfoCount = 0,
            .pWaitSemaphoreInfos = 0,
            .commandBufferInfoCount = array_length(command_buffer_submit_infos),
            .pCommandBufferInfos = command_buffer_submit_infos,
            .signalSemaphoreInfoCount = 0,
            .pSignalSemaphoreInfos = 0,
        }
    };

    vkok(vkQueueSubmit2(context.queue, array_length(submit_info), submit_info, context.fence));
    VkBool32 wait_all = 1;
    auto timeout = ~(u64)0;
    vkok(vkWaitForFences(context.device, array_length(fences), fences, wait_all, timeout));
}

fn VulkanImage vk_image_create(VkDevice device, const VkAllocationCallbacks* allocation_callbacks, VkPhysicalDeviceMemoryProperties memory_properties, VulkanImageCreate create)
{
    assert(create.width);
    assert(create.height);
    VulkanImage result = {};
    result.format = create.format;

    VkImageCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .imageType = VK_IMAGE_TYPE_2D,
        .format = create.format,
        .extent = {
            .width = create.width,
            .height = create.height,
            .depth = 1,
        },
        .mipLevels = create.mip_levels,
        .arrayLayers = 1,
        .samples = VK_SAMPLE_COUNT_1_BIT,
        .tiling = VK_IMAGE_TILING_OPTIMAL,
        .usage = create.usage,
        .sharingMode = 0,
        .queueFamilyIndexCount = 0,
        .pQueueFamilyIndices = 0,
        .initialLayout = 0,
    };
    vkok(vkCreateImage(device, &create_info, allocation_callbacks, &result.handle));

    VkMemoryRequirements memory_requirements;
    vkGetImageMemoryRequirements(device, result.handle, &memory_requirements);

    VkMemoryPropertyFlags flags = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    u8 use_device_address_bit = 0;
    result.memory = vk_allocate_memory(device, allocation_callbacks, memory_properties, memory_requirements, flags, use_device_address_bit);

    VkDeviceSize memory_offset = 0;
    vkok(vkBindImageMemory(device, result.handle, result.memory.handle, memory_offset));

    VkImageViewCreateInfo view_create_info = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
        .image = result.handle,
        .viewType = VK_IMAGE_VIEW_TYPE_2D,
        .format = create_info.format,
        .subresourceRange = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .baseMipLevel = 0,
            .levelCount = create.mip_levels,
            .baseArrayLayer = 0,
            .layerCount = 1,
        },
    };

    vkok(vkCreateImageView(device, &view_create_info, allocation_callbacks, &result.view));
    return result;
}

fn void vk_image_transition(VkCommandBuffer command_buffer, VkImage image, VkImageLayout old_layout, VkImageLayout new_layout)
{
    VkImageMemoryBarrier2 image_barrier = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER_2,
        .srcStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT,
        .srcAccessMask = VK_ACCESS_2_MEMORY_WRITE_BIT,
        .dstStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT,
        .dstAccessMask = VK_ACCESS_2_MEMORY_WRITE_BIT | VK_ACCESS_2_MEMORY_READ_BIT,
        .oldLayout = old_layout,
        .newLayout = new_layout,
        .image = image,
        .subresourceRange = {
            .aspectMask = (new_layout == VK_IMAGE_LAYOUT_DEPTH_ATTACHMENT_OPTIMAL) ? VK_IMAGE_ASPECT_DEPTH_BIT : VK_IMAGE_ASPECT_COLOR_BIT,
            .baseMipLevel = 0,
            .levelCount = VK_REMAINING_MIP_LEVELS,
            .baseArrayLayer = 0,
            .layerCount = VK_REMAINING_ARRAY_LAYERS,
        },
    };

    VkDependencyInfo dependency_info = {
        .sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO,
        .imageMemoryBarrierCount = 1,
        .pImageMemoryBarriers = &image_barrier,
    };

    vkCmdPipelineBarrier2(command_buffer, &dependency_info);
}

fn void vk_image_copy(VkCommandBuffer command_buffer, VulkanCopyImageArgs args)
{
    VkImageSubresourceLayers subresource_layers = {
        .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
        .mipLevel = 0,
        .baseArrayLayer = 0,
        .layerCount = 1,
    };
    VkImageBlit2 blit_regions[] = {
        {
            .sType = VK_STRUCTURE_TYPE_IMAGE_BLIT_2,
            .pNext = 0,
            .srcSubresource = subresource_layers,
            .srcOffsets = {
                [1] = {
                    .x = args.source.extent.width,
                    .y = args.source.extent.height,
                    .z = 1,
                },
            },
            .dstSubresource = subresource_layers,
            .dstOffsets = {
                [1] = {
                    .x = args.destination.extent.width,
                    .y = args.destination.extent.height,
                    .z = 1,
                },
            },
        },
    };

    VkBlitImageInfo2 blit_info = {
        .sType = VK_STRUCTURE_TYPE_BLIT_IMAGE_INFO_2,
        .pNext = 0,
        .srcImage = args.source.handle,
        .srcImageLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        .dstImage = args.destination.handle,
        .dstImageLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .regionCount = array_length(blit_regions),
        .pRegions = blit_regions,
        .filter = VK_FILTER_LINEAR,
    };

    vkCmdBlitImage2(command_buffer, &blit_info);
}


Renderer* renderer_initialize(Arena* arena)
{
    Renderer* renderer = &renderer_memory;
    vkok(volkInitialize());

    auto api_version = volkGetInstanceVersion();
    if (api_version < VK_API_VERSION_1_3)
    {
        failed_execution();
    }

    {
#if BB_DEBUG
        auto debug_layer = strlit("VK_LAYER_KHRONOS_validation");
        if (!vk_layer_is_supported(debug_layer))
        {
            failed_execution();
        }
        const char* layers[] =
        {
            string_to_c(debug_layer),
        };
        auto layer_count = array_length(layers);
#else
        const char** layers = 0;
        u32 layer_count = 0;
#endif

        const char* extensions[] = {
#if BB_DEBUG
            VK_EXT_DEBUG_UTILS_EXTENSION_NAME,
#endif
            VK_KHR_SURFACE_EXTENSION_NAME,
#ifdef VK_USE_PLATFORM_WIN32_KHR
            VK_KHR_WIN32_SURFACE_EXTENSION_NAME,
#endif
#ifdef VK_USE_PLATFORM_XLIB_KHR
            VK_KHR_XLIB_SURFACE_EXTENSION_NAME,
#endif 
#ifdef VK_USE_PLATFORM_XCB_KHR
            VK_KHR_XCB_SURFACE_EXTENSION_NAME,
#endif
#ifdef VK_USE_PLATFORM_WAYLAND_KHR
            VK_KHR_WAYLAND_SURFACE_EXTENSION_NAME,
#endif
#ifdef VK_USE_PLATFORM_METAL_EXT
            VK_EXT_METAL_SURFACE_EXTENSION_NAME,
            VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME,
#endif
        };

#if BB_DEBUG
        VkValidationFeatureEnableEXT enabled_validation_features[] =
        {
            VK_VALIDATION_FEATURE_ENABLE_DEBUG_PRINTF_EXT,
        };

        VkDebugUtilsMessengerCreateInfoEXT msg_ci = {
            .sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT,
            .pNext = 0,
            .messageSeverity = VK_DEBUG_UTILS_MESSAGE_SEVERITY_VERBOSE_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_SEVERITY_INFO_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT,
            .messageType = VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_TYPE_DEVICE_ADDRESS_BINDING_BIT_EXT,
            .pfnUserCallback = debug_callback,
            .pUserData = 0,
        };

        u8 enable_shader_debug_printf = BB_DEBUG;

        VkValidationFeaturesEXT validation_features = { 
            .sType = VK_STRUCTURE_TYPE_VALIDATION_FEATURES_EXT,
            .enabledValidationFeatureCount = array_length(enabled_validation_features),
            .pEnabledValidationFeatures = enabled_validation_features,
            .pNext = &msg_ci,
        };

#endif
        auto* pNext =
#if BB_DEBUG
        enable_shader_debug_printf ? (void*)&validation_features : (void*)&msg_ci;
#else
        (void*)0;
#endif
        VkApplicationInfo app_info = {
            .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
            .apiVersion = api_version,
        };
        VkInstanceCreateInfo ci = {
            .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
            .pNext = pNext,
#if __APPLE__
            .flags = VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR,
#else
            .flags = 0,
#endif
            .pApplicationInfo = &app_info,
            .ppEnabledLayerNames = layers,
            .enabledLayerCount = layer_count,
            .ppEnabledExtensionNames = extensions,
            .enabledExtensionCount = array_length(extensions),
        };

        vkok(vkCreateInstance(&ci, renderer->allocator, &renderer->instance));
        volkLoadInstance(renderer->instance);

#if BB_DEBUG
        VkDebugUtilsMessengerEXT messenger;
        vkok(vkCreateDebugUtilsMessengerEXT(renderer->instance, &msg_ci, renderer->allocator, &messenger));
#endif
    }

    {
        u32 physical_device_count;
        VkPhysicalDevice physical_devices[256];
        vkok(vkEnumeratePhysicalDevices(renderer->instance, &physical_device_count, 0));

        if (physical_device_count == 0)
        {
            failed_execution();
        }

        if (physical_device_count > array_length(physical_devices))
        {
            failed_execution();
        }

        vkok(vkEnumeratePhysicalDevices(renderer->instance, &physical_device_count, physical_devices));

        renderer->physical_device = physical_devices[0];
    }

    vkGetPhysicalDeviceMemoryProperties(renderer->physical_device, &renderer->memory_properties);

    u32 graphics_queue_family_index;
    {
        u32 present_queue_family_index;
        VkPhysicalDeviceProperties properties;
        vkGetPhysicalDeviceProperties(renderer->physical_device, &properties);

        u32 queue_count;
        vkGetPhysicalDeviceQueueFamilyProperties(renderer->physical_device, &queue_count, 0);

        VkQueueFamilyProperties queue_properties[64];
        if (queue_count > array_length(queue_properties))
        {
            failed_execution();
        }

        vkGetPhysicalDeviceQueueFamilyProperties(renderer->physical_device, &queue_count, queue_properties);

        for (graphics_queue_family_index = 0; graphics_queue_family_index < queue_count; graphics_queue_family_index += 1)
        {
            VkQueueFamilyProperties* properties = &queue_properties[graphics_queue_family_index];
            if (properties->queueFlags & VK_QUEUE_GRAPHICS_BIT)
            {
                break;
            }
        }

        if (graphics_queue_family_index == queue_count)
        {
            failed_execution();
        }

        present_queue_family_index = 0;

        // for (present_queue_family_index = 0; present_queue_family_index < queue_count; present_queue_family_index += 1)
        // {
        //     VkBool32 support;
        //     vkok(vkGetPhysicalDeviceSurfaceSupportKHR(physical_device, present_queue_family_index, surface, &support));
        //     if (support)
        //     {
        //         break;
        //     }
        // }

        if (present_queue_family_index == queue_count)
        {
            failed_execution();
        }

        if (present_queue_family_index != graphics_queue_family_index)
        {
            failed_execution();
        }

        f32 queue_priorities[] = { 1.0f };
        VkDeviceQueueCreateInfo queue_create_infos[] = {
            {
                .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                .queueFamilyIndex = graphics_queue_family_index,
                .queueCount = array_length(queue_priorities),
                .pQueuePriorities = queue_priorities,
            },
        };

        const char* extensions[] =
        {
            VK_KHR_SWAPCHAIN_EXTENSION_NAME,
#ifdef __APPLE__
            "VK_KHR_portability_subset",
            VK_KHR_DYNAMIC_RENDERING_EXTENSION_NAME,
#endif
        };

#ifdef __APPLE__
            VkPhysicalDeviceDynamicRenderingFeatures dynamic_rendering_features = {
                .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DYNAMIC_RENDERING_FEATURES,
                .pNext = 0,
                .dynamicRendering = VK_TRUE,
            };
#else
        VkPhysicalDeviceVulkan13Features features13 = {
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES,
            .dynamicRendering = 1,
            .synchronization2 = 1,
        };
#endif

        VkPhysicalDeviceVulkan12Features features12 = {
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES,
            .bufferDeviceAddress = 1,
            .descriptorIndexing = 1,
            .runtimeDescriptorArray = 1,
            .shaderSampledImageArrayNonUniformIndexing = 1,
#ifdef __APPLE__
            .pNext = &dynamic_rendering_features,
#else
            .pNext = &features13,
#endif
        };

        VkPhysicalDeviceFeatures2 features = {
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
            .features = {
            },
            .pNext = &features12,
        };

        VkDeviceCreateInfo ci = {
            .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
            .ppEnabledExtensionNames = extensions,
            .enabledExtensionCount = array_length(extensions),
            .pQueueCreateInfos = queue_create_infos,
            .queueCreateInfoCount = array_length(queue_create_infos),
            .pNext = &features,
        };

        vkok(vkCreateDevice(renderer->physical_device, &ci, renderer->allocator, &renderer->device));
    }

    vkGetDeviceQueue(renderer->device, graphics_queue_family_index, 0, &renderer->graphics_queue);

    renderer->immediate.device = renderer->device;
    renderer->immediate.queue = renderer->graphics_queue;

    VkCommandPoolCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        .queueFamilyIndex = graphics_queue_family_index,
    };
    vkok(vkCreateCommandPool(renderer->device, &create_info, renderer->allocator, &renderer->immediate.command_pool));

    VkCommandBufferAllocateInfo command_buffer_allocate_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = renderer->immediate.command_pool,
        .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount = 1,
    };

    vkok(vkAllocateCommandBuffers(renderer->device, &command_buffer_allocate_info, &renderer->immediate.command_buffer));
    VkFenceCreateInfo fence_create_info = {
        .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
        .flags = VK_FENCE_CREATE_SIGNALED_BIT,
    };
    vkok(vkCreateFence(renderer->device, &fence_create_info, renderer->allocator, &renderer->immediate.fence));

    {
        VkFilter sampler_filter = VK_FILTER_LINEAR;
        VkSamplerCreateInfo create_info = {
            .sType = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO,
            .pNext = 0,
            .flags = 0,
            .magFilter = sampler_filter,
            .minFilter = sampler_filter,
            .mipmapMode = 0,
            .addressModeU = 0,
            .addressModeV = 0,
            .addressModeW = 0,
            .mipLodBias = 0,
            .anisotropyEnable = 0,
            .maxAnisotropy = 0,
            .compareEnable = 0,
            .compareOp = 0,
            .minLod = 0,
            .maxLod = 0,
            .borderColor = 0,
            .unnormalizedCoordinates = 0,
        };

        vkok(vkCreateSampler(renderer->device, &create_info, renderer->allocator, &renderer->sampler));
    }

    String shader_source_paths[] = {
        strlit("bootstrap/std/shaders/rect.vert"),
        strlit("bootstrap/std/shaders/rect.frag"),
    };

    PipelineLayoutCreate pipeline_layouts[] = {
        (PipelineLayoutCreate) {
            .push_constant_ranges = array_to_slice(((PushConstantRange[]){
                (PushConstantRange) {
                    .offset = 0,
                    .size = sizeof(GPUDrawPushConstants),
                    .stage = SHADER_STAGE_VERTEX,
                },
            })),
            .descriptor_set_layouts = array_to_slice(((DescriptorSetLayoutCreate[]){
                (DescriptorSetLayoutCreate) {
                    .bindings = array_to_slice(((DescriptorSetLayoutBinding[]) {
                        {
                            .binding = 0,
                            .type = DESCRIPTOR_TYPE_IMAGE_PLUS_SAMPLER,
                            .stage = SHADER_STAGE_FRAGMENT,
                            .count = RECT_TEXTURE_SLOT_COUNT,
                        },
                    })),
                },
            })),
        },
    };
    PipelineCreate pipeline_create[] = {
        (PipelineCreate) {
            .shader_source_indices = array_to_slice(((u16[]){0, 1})),
            .layout_index = 0,
        },
    };
    auto create_data = (GraphicsPipelinesCreate) {
        .layouts = array_to_slice(pipeline_layouts),
        .pipelines = array_to_slice(pipeline_create),
        .shader_sources = array_to_slice(shader_source_paths),
    };
    auto graphics_pipeline_count = create_data.pipelines.length;
    assert(graphics_pipeline_count);
    auto pipeline_layout_count = create_data.layouts.length;
    assert(pipeline_layout_count);
    assert(pipeline_layout_count <= graphics_pipeline_count);
    auto shader_count = create_data.shader_sources.length;

    VkPipeline pipeline_handles[BB_PIPELINE_COUNT];
    VkPipelineShaderStageCreateInfo shader_create_infos[MAX_SHADER_MODULE_COUNT_PER_PIPELINE];
    VkGraphicsPipelineCreateInfo graphics_pipeline_create_infos[BB_PIPELINE_COUNT];

    VkPipelineVertexInputStateCreateInfo vertex_input_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .vertexBindingDescriptionCount = 0,
        .pVertexBindingDescriptions = 0,
        .vertexAttributeDescriptionCount = 0,
        .pVertexAttributeDescriptions = 0,
    };

    VkPipelineInputAssemblyStateCreateInfo input_assembly_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST,
        .primitiveRestartEnable = VK_FALSE,
    };

    VkPipelineViewportStateCreateInfo viewport_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
        .pNext = 0,
        .viewportCount = 1,
        .scissorCount = 1,
    };

    VkPipelineRasterizationStateCreateInfo rasterization_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .depthClampEnable = 0,
        .rasterizerDiscardEnable = 0,
        .polygonMode = VK_POLYGON_MODE_FILL,
        .cullMode = VK_CULL_MODE_NONE,
        .frontFace = VK_FRONT_FACE_CLOCKWISE,
        .depthBiasEnable = 0,
        .depthBiasConstantFactor = 0,
        .depthBiasClamp = 0,
        .depthBiasSlopeFactor = 0,
        .lineWidth = 1.0f,
    };

    VkPipelineMultisampleStateCreateInfo multisample_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .rasterizationSamples = VK_SAMPLE_COUNT_1_BIT,
        .sampleShadingEnable = 0,
        .minSampleShading = 1.0f,
        .pSampleMask = 0,
        .alphaToCoverageEnable = 0,
        .alphaToOneEnable = 0,
    };

    VkPipelineDepthStencilStateCreateInfo depth_stencil_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .depthTestEnable = 0,
        .depthWriteEnable = 0,
        .depthCompareOp = VK_COMPARE_OP_NEVER,
        .depthBoundsTestEnable = 0,
        .stencilTestEnable = 0,
        .front = {},
        .back = {},
        .minDepthBounds = 0.0f,
        .maxDepthBounds = 1.0f,
    };

    VkPipelineColorBlendAttachmentState attachments[] = {
        {
            .blendEnable = 1,
            .srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA,
            .dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA,
            .colorBlendOp = VK_BLEND_OP_ADD,
            .srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE,
            .dstAlphaBlendFactor = VK_BLEND_FACTOR_ZERO,
            .alphaBlendOp = VK_BLEND_OP_ADD,
            .colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT,
        },
    };

    VkPipelineColorBlendStateCreateInfo color_blend_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .logicOpEnable = VK_FALSE,
        .logicOp = VK_LOGIC_OP_COPY,
        .attachmentCount = array_length(attachments),
        .pAttachments = attachments,
        .blendConstants = {},
    };

    VkDynamicState states[] = { VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR };

    VkPipelineDynamicStateCreateInfo dynamic_state_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO,
        .pNext = 0,
        .flags = 0,
        .dynamicStateCount = array_length(states),
        .pDynamicStates = states,
    };

    // TODO: abstract away
    VkFormat common_image_format = VK_FORMAT_B8G8R8A8_UNORM;
    VkFormat color_attachment_formats[] = {
        common_image_format,
    };

    VkPipelineRenderingCreateInfo rendering_create_info = {
        .sType = VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO,
        .pNext = 0,
        .viewMask = 0,
        .colorAttachmentCount = array_length(color_attachment_formats),
        .pColorAttachmentFormats = color_attachment_formats,
        .depthAttachmentFormat = 0,
        .stencilAttachmentFormat = 0,
    };

    auto* shader_modules = arena_allocate(arena, VkShaderModule, shader_count);

    for (u64 i = 0; i < shader_count; i += 1)
    {
        String shader_source_path = create_data.shader_sources.pointer[i];

        ShaderStage shader_stage = shader_stage_from_path(shader_source_path);

        auto binary = compile_shader(arena, shader_source_path, shader_stage);

        VkShaderModuleCreateInfo create_info = {
            .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
            .codeSize = binary.length,
            .pCode = (u32*)binary.pointer,
        };

        vkok(vkCreateShaderModule(renderer->device, &create_info, renderer->allocator, &shader_modules[i]));
    }

    for (u64 pipeline_index = 0; pipeline_index < pipeline_layout_count; pipeline_index += 1)
    {
        auto create = create_data.layouts.pointer[pipeline_index];
        auto descriptor_set_layout_count = create.descriptor_set_layouts.length;
        auto push_constant_range_count = create.push_constant_ranges.length;
        auto* pipeline = &renderer->pipelines[pipeline_index];
        pipeline->descriptor_set_count = descriptor_set_layout_count;
        pipeline->push_constant_range_count = push_constant_range_count;

        if (descriptor_set_layout_count > MAX_DESCRIPTOR_SET_LAYOUT_COUNT)
        {
            failed_execution();
        }

        // u16 descriptor_type_counter[DESCRIPTOR_TYPE_COUNT] = {};

        for (u64 descriptor_set_layout_index = 0; descriptor_set_layout_index < descriptor_set_layout_count; descriptor_set_layout_index += 1)
        {
            auto set_layout_create = create.descriptor_set_layouts.pointer[descriptor_set_layout_index];
            auto binding_count = set_layout_create.bindings.length;
            auto* descriptor_set_layout_bindings = &pipeline->descriptor_set_layout_bindings[descriptor_set_layout_index];
            descriptor_set_layout_bindings->count = binding_count;

            for (u64 binding_index = 0; binding_index < binding_count; binding_index += 1)
            {
                auto binding_descriptor = set_layout_create.bindings.pointer[binding_index];

                VkDescriptorType descriptor_type = vulkan_descriptor_type(binding_descriptor.type);

                VkShaderStageFlags shader_stage = vulkan_shader_stage(binding_descriptor.stage);

                descriptor_set_layout_bindings->buffer[binding_index] = (VkDescriptorSetLayoutBinding) {
                    .binding = binding_descriptor.binding,
                    .descriptorType = descriptor_type,
                    .descriptorCount = binding_descriptor.count,
                    .stageFlags = shader_stage,
                    .pImmutableSamplers = 0,
                };
            }

            VkDescriptorSetLayoutCreateInfo create_info = {
                .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
                .pNext = 0,
                .flags = 0,
                .bindingCount = binding_count,
                .pBindings = descriptor_set_layout_bindings->buffer,
            };

            vkok(vkCreateDescriptorSetLayout(renderer->device, &create_info, renderer->allocator, &pipeline->descriptor_set_layouts[descriptor_set_layout_index]));
        }

        if (push_constant_range_count > MAX_PUSH_CONSTANT_RANGE_COUNT)
        {
            failed_execution();
        }

        for (u64 push_constant_index = 0; push_constant_index < push_constant_range_count; push_constant_index += 1)
        {
            auto push_constant_descriptor = create.push_constant_ranges.pointer[push_constant_index];
            pipeline->push_constant_ranges[push_constant_index] = (VkPushConstantRange) {
                .stageFlags = vulkan_shader_stage(push_constant_descriptor.stage),
                .offset = push_constant_descriptor.offset,
                .size = push_constant_descriptor.size,
            };
        }

        VkPipelineLayoutCreateInfo create_info = {
            .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
            .pNext = 0,
            .flags = 0,
            .setLayoutCount = descriptor_set_layout_count,
            .pSetLayouts = pipeline->descriptor_set_layouts,
            .pushConstantRangeCount = push_constant_range_count,
            .pPushConstantRanges = pipeline->push_constant_ranges,
        };

        vkok(vkCreatePipelineLayout(renderer->device, &create_info, renderer->allocator, &pipeline->layout));
    }

    for (u64 i = 0; i < graphics_pipeline_count; i += 1)
    {
        auto create = create_data.pipelines.pointer[i];
        auto pipeline_shader_count = create.shader_source_indices.length;
        if (pipeline_shader_count > MAX_SHADER_MODULE_COUNT_PER_PIPELINE)
        {
            failed_execution();
        }

        for (u64 i = 0; i < pipeline_shader_count; i += 1)
        {
            auto shader_index = create.shader_source_indices.pointer[i];
            auto shader_source_path = create_data.shader_sources.pointer[shader_index];

            shader_create_infos[i] = (VkPipelineShaderStageCreateInfo) {
                .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
                .pNext = 0,
                .flags = 0,
                .stage = vulkan_shader_stage_from_path(shader_source_path),
                .module = shader_modules[i],
                .pName = "main",
                .pSpecializationInfo = 0,
            };
        }

        graphics_pipeline_create_infos[i] = (VkGraphicsPipelineCreateInfo)
        {
            .sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
            .pNext = &rendering_create_info,
            .flags = 0,
            .stageCount = shader_count,
            .pStages = shader_create_infos,
            .pVertexInputState = &vertex_input_state_create_info,
            .pInputAssemblyState = &input_assembly_state_create_info,
            .pTessellationState = 0,
            .pViewportState = &viewport_state_create_info,
            .pRasterizationState = &rasterization_state_create_info,
            .pMultisampleState = &multisample_state_create_info,
            .pDepthStencilState = &depth_stencil_state_create_info,
            .pColorBlendState = &color_blend_state_create_info,
            .pDynamicState = &dynamic_state_create_info,
            .layout = renderer->pipelines[i].layout,
            .renderPass = 0,
            .subpass = 0,
            .basePipelineHandle = 0,
            .basePipelineIndex = 0,
        };
    }

    VkPipelineCache pipeline_cache = 0;
    vkok(vkCreateGraphicsPipelines(renderer->device, pipeline_cache, graphics_pipeline_count, graphics_pipeline_create_infos, renderer->allocator, pipeline_handles));

    for (u32 i = 0; i < graphics_pipeline_count; i += 1)
    {
        renderer->pipelines[i].handle = pipeline_handles[i];
    }

    return renderer;
}

fn void destroy_image(Renderer* renderer, VulkanImage image)
{
    vkDestroyImageView(renderer->device, image.view, renderer->allocator);
    vkDestroyImage(renderer->device, image.handle, renderer->allocator);
    vkFreeMemory(renderer->device, image.memory.handle, renderer->allocator);
}

fn void swapchain_recreate(Renderer* renderer, RenderWindow* window)
{
    VkSurfaceCapabilitiesKHR surface_capabilities;
    vkok(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(renderer->physical_device, window->surface, &surface_capabilities));

    VkSwapchainKHR old_swapchain = window->swapchain;
    VkImageView old_swapchain_image_views[MAX_SWAPCHAIN_IMAGE_COUNT];

    if (old_swapchain)
    {
        vkok(vkDeviceWaitIdle(renderer->device));
        for (u32 i = 0; i < window->swapchain_image_count; i += 1)
        {
            old_swapchain_image_views[i] = window->swapchain_image_views[i];
        }
    }

    u32 queue_family_indices[] = { renderer->graphics_queue_family_index };
    VkImageUsageFlags swapchain_image_usage_flags = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    window->swapchain_image_format = VK_FORMAT_B8G8R8A8_UNORM;
    window->last_width = window->width;
    window->last_height = window->height;
    window->width = surface_capabilities.currentExtent.width;
    window->height = surface_capabilities.currentExtent.height;

    VkPresentModeKHR preferred_present_mode = VK_PRESENT_MODE_IMMEDIATE_KHR;
    VkPresentModeKHR present_modes[16];
    u32 present_mode_count = array_length(present_modes);
    vkok(vkGetPhysicalDeviceSurfacePresentModesKHR(renderer->physical_device, window->surface, &present_mode_count, present_modes));

    for (u32 i = 0; i < present_mode_count; i += 1)
    {
        if (present_modes[i] == VK_PRESENT_MODE_MAILBOX_KHR)
        {
            preferred_present_mode = VK_PRESENT_MODE_MAILBOX_KHR;
            break;
        }
    }

    VkSwapchainCreateInfoKHR swapchain_create_info = {
        .sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR,
        .pNext = 0,
        .flags = 0,
        .surface = window->surface,
        .minImageCount = surface_capabilities.minImageCount,
        .imageFormat = window->swapchain_image_format,
        .imageColorSpace = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR,
        .imageExtent = surface_capabilities.currentExtent,
        .imageArrayLayers = 1,
        .imageUsage = swapchain_image_usage_flags,
        .imageSharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .queueFamilyIndexCount = array_length(queue_family_indices),
        .pQueueFamilyIndices = queue_family_indices,
        .preTransform = surface_capabilities.currentTransform,
        .compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
        .presentMode = preferred_present_mode,
        .clipped = 0,
        .oldSwapchain = window->swapchain,
    };

    vkok(vkCreateSwapchainKHR(renderer->device, &swapchain_create_info, renderer->allocator, &window->swapchain));

    assert(window->swapchain != old_swapchain);

    if (old_swapchain)
    {
        for (u32 i = 0; i < window->swapchain_image_count; i += 1)
        {
            vkDestroyImageView(renderer->device, old_swapchain_image_views[i], renderer->allocator);
        }

        vkDestroySwapchainKHR(renderer->device, old_swapchain, renderer->allocator);

        destroy_image(renderer, window->render_image);
    }

    {
        vkok(vkGetSwapchainImagesKHR(renderer->device, window->swapchain, &window->swapchain_image_count, 0));

        if (window->swapchain_image_count == 0)
        {
            failed_execution();
        }

        if (window->swapchain_image_count > array_length(window->swapchain_images))
        {
            failed_execution();
        }

        vkok(vkGetSwapchainImagesKHR(renderer->device, window->swapchain, &window->swapchain_image_count, window->swapchain_images));
        
        // VkImageViewUsageCreateInfo image_view_usage_create_info = {
        //     .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_USAGE_CREATE_INFO,
        //     .pNext = 0,
        //     .usage = swapchain_create_info.imageUsage,
        // };

        for (u32 i = 0; i < window->swapchain_image_count; i += 1)
        {
            VkImageViewCreateInfo create_info = {
                .sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
                // .pNext = &image_view_usage_create_info,
                .flags = 0,
                .image = window->swapchain_images[i],
                .viewType = VK_IMAGE_VIEW_TYPE_2D,
                .format = swapchain_create_info.imageFormat,
                .components = {
                    .r = VK_COMPONENT_SWIZZLE_IDENTITY,
                    .g = VK_COMPONENT_SWIZZLE_IDENTITY,
                    .b = VK_COMPONENT_SWIZZLE_IDENTITY,
                    .a = VK_COMPONENT_SWIZZLE_IDENTITY,
                },
                .subresourceRange = {
                    .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
                    .baseMipLevel = 0,
                    .levelCount = 1,
                    .baseArrayLayer = 0,
                    .layerCount = 1,
                },
            };

            vkok(vkCreateImageView(renderer->device, &create_info, renderer->allocator, &window->swapchain_image_views[i]));
        }
    }

    window->render_image = vk_image_create(renderer->device, renderer->allocator, renderer->memory_properties, (VulkanImageCreate) {
        .width = surface_capabilities.currentExtent.width,
        .height = surface_capabilities.currentExtent.height,
        .mip_levels = 1,
        .format = window->swapchain_image_format,
        .usage = VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_STORAGE_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
    });
}

typedef void GLFWwindow;
extern VkResult glfwCreateWindowSurface(VkInstance instance, GLFWwindow* window, const VkAllocationCallbacks* allocator, VkSurfaceKHR* surface);

RenderWindow* renderer_window_initialize(Renderer* renderer, OSWindow window)
{
    RenderWindow* result = &renderer_window_memory;
    vkok(glfwCreateWindowSurface(renderer->instance, window, renderer->allocator, &result->surface));

    swapchain_recreate(renderer, result);

    for (u64 frame_index = 0; frame_index < MAX_FRAME_COUNT; frame_index += 1)
    {
        for (u64 pipeline_index = 0; pipeline_index < BB_PIPELINE_COUNT; pipeline_index += 1)
        {
            result->frames[frame_index].pipeline_instantiations[pipeline_index].vertex_buffer.gpu.type = BUFFER_TYPE_VERTEX;
            result->frames[frame_index].pipeline_instantiations[pipeline_index].index_buffer.gpu.type = BUFFER_TYPE_INDEX;
            result->frames[frame_index].pipeline_instantiations[pipeline_index].transient_buffer.type = BUFFER_TYPE_STAGING;
        }
    }

    for (u64 pipeline_index = 0; pipeline_index < BB_PIPELINE_COUNT; pipeline_index += 1)
    {
        auto* pipeline_descriptor = &renderer->pipelines[pipeline_index];
        auto* pipeline_instantiation = &result->pipeline_instantiations[pipeline_index];

        u16 descriptor_type_counter[DESCRIPTOR_TYPE_COUNT] = {};

        for (u64 descriptor_index = 0; descriptor_index < pipeline_descriptor->descriptor_set_count; descriptor_index += 1)
        {
            auto* descriptor_set_layout_bindings = &pipeline_descriptor->descriptor_set_layout_bindings[descriptor_index];

            for (u64 binding_index = 0; binding_index < descriptor_set_layout_bindings->count; binding_index += 1)
            {
                auto* binding_descriptor = &descriptor_set_layout_bindings->buffer[binding_index];
                auto descriptor_type = descriptor_type_from_vulkan(binding_descriptor->descriptorType);
                auto* counter_ptr = &descriptor_type_counter[descriptor_type];
                auto old_counter = *counter_ptr;
                *counter_ptr = old_counter + binding_descriptor->descriptorCount;
            }
        }

        VkDescriptorPoolSize pool_sizes[DESCRIPTOR_TYPE_COUNT];
        u32 pool_size_count = 0;

        for (DescriptorType i = 0; i < DESCRIPTOR_TYPE_COUNT; i += 1)
        {
            auto count = descriptor_type_counter[i];
            if (count)
            {
                auto* pool_size = &pool_sizes[pool_size_count];
                pool_size_count += 1;

                *pool_size = (VkDescriptorPoolSize) {
                    .type = vulkan_descriptor_type(i),
                        .descriptorCount = count,
                };
            }
        }

        VkDescriptorPoolCreateInfo create_info = {
            .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
            .pNext = 0,
            .flags = 0,
            .maxSets = pipeline_descriptor->descriptor_set_count,
            .poolSizeCount = pool_size_count,
            .pPoolSizes = pool_sizes,
        };

        VkDescriptorPool descriptor_pool;
        vkok(vkCreateDescriptorPool(renderer->device, &create_info, renderer->allocator, &descriptor_pool));

        VkDescriptorSetAllocateInfo allocate_info = {
            .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
            .pNext = 0,
            .descriptorPool = descriptor_pool,
            .descriptorSetCount = pipeline_descriptor->descriptor_set_count,
            .pSetLayouts = pipeline_descriptor->descriptor_set_layouts,
        };

        vkok(vkAllocateDescriptorSets(renderer->device, &allocate_info, pipeline_instantiation->descriptor_sets));
    }

    for (u32 i = 0; i < MAX_FRAME_COUNT; i += 1)
    {
        VkCommandPoolCreateInfo command_pool_create_info = {
            .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
            .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
            .queueFamilyIndex = renderer->graphics_queue_family_index,
        };

        VkFenceCreateInfo fence_create_info = {
            .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
            .flags = VK_FENCE_CREATE_SIGNALED_BIT,
        };

        VkSemaphoreCreateInfo semaphore_create_info = {
            .sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO,
            .flags = 0,
        };

        WindowFrame* frame = &result->frames[i];
        vkok(vkCreateCommandPool(renderer->device, &command_pool_create_info, renderer->allocator, &frame->command_pool));

        VkCommandBufferAllocateInfo command_buffer_allocate_info = {
            .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
            .commandPool = frame->command_pool,
            .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
            .commandBufferCount = 1,
        };

        vkok(vkAllocateCommandBuffers(renderer->device, &command_buffer_allocate_info, &frame->command_buffer));
        vkok(vkCreateFence(renderer->device, &fence_create_info, renderer->allocator, &frame->render_fence));
        vkok(vkCreateSemaphore(renderer->device, &semaphore_create_info, renderer->allocator, &frame->render_semaphore));
        vkok(vkCreateSemaphore(renderer->device, &semaphore_create_info, renderer->allocator, &frame->swapchain_semaphore));
        frame->bound_pipeline = BB_PIPELINE_COUNT;
    }

    return result;
}

fn WindowFrame* window_frame(RenderWindow* window)
{
    return &window->frames[window->frame_index % MAX_FRAME_COUNT];
}

void renderer_window_frame_begin(Renderer* renderer, RenderWindow* window)
{
    auto* frame = window_frame(window);
    auto timeout = ~(u64)0;

    u32 fence_count = 1;
    VkBool32 wait_all = 1;
    vkok(vkWaitForFences(renderer->device, fence_count, &frame->render_fence, wait_all, timeout));
    VkFence image_fence = 0;
    VkResult next_image_result = vkAcquireNextImageKHR(renderer->device, window->swapchain, timeout, frame->swapchain_semaphore, image_fence, &window->swapchain_image_index);
    if (next_image_result == VK_ERROR_OUT_OF_DATE_KHR)
    {
        swapchain_recreate(renderer, window);
    }
    else if (next_image_result != VK_SUCCESS && next_image_result != VK_SUBOPTIMAL_KHR)
    {
        vkok(next_image_result);
    }

    vkok(vkResetFences(renderer->device, fence_count, &frame->render_fence));

    VkCommandBufferResetFlags reset_flags = 0;
    vkok(vkResetCommandBuffer(frame->command_buffer, reset_flags));

    // Reset frame data
    for (u32 i = 0; i < array_length(window->pipeline_instantiations); i += 1)
    {
        auto* pipeline_instantiation = &frame->pipeline_instantiations[i];
        pipeline_instantiation->vertex_buffer.cpu.length = 0;
        pipeline_instantiation->vertex_buffer.count = 0;
        pipeline_instantiation->index_buffer.cpu.length = 0;
    }
}

void buffer_destroy(Renderer* renderer, VulkanBuffer buffer)
{
    if (buffer.handle)
    {
        vkDestroyBuffer(renderer->device, buffer.handle, renderer->allocator);
    }

    if (buffer.memory.handle)
    {
        if (buffer.type == BUFFER_TYPE_STAGING)
        {
            vkUnmapMemory(renderer->device, buffer.memory.handle);
        }

        vkFreeMemory(renderer->device, buffer.memory.handle, renderer->allocator);
    }
}

fn void buffer_ensure_capacity(Renderer* renderer, VulkanBuffer* buffer, u64 needed_size)
{
    if (unlikely(needed_size > buffer->memory.size))
    {
        buffer_destroy(renderer, *buffer);
        *buffer = buffer_create(renderer, needed_size, buffer->type);
    }
}

void renderer_window_frame_end(Renderer* renderer, RenderWindow* window)
{
    auto* frame = window_frame(window);

    VkCommandBufferBeginInfo command_buffer_begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    vkok(vkBeginCommandBuffer(frame->command_buffer, &command_buffer_begin_info));

    for (u32 i = 0; i < BB_PIPELINE_COUNT; i += 1)
    {
        auto* frame_pipeline_instantiation = &frame->pipeline_instantiations[i];

        if (likely(frame_pipeline_instantiation->vertex_buffer.cpu.length))
        {
            auto new_vertex_buffer_size = frame_pipeline_instantiation->vertex_buffer.cpu.length * sizeof(*frame_pipeline_instantiation->vertex_buffer.cpu.pointer);
            auto new_index_buffer_size = frame_pipeline_instantiation->index_buffer.cpu.length * sizeof(*frame_pipeline_instantiation->index_buffer.cpu.pointer);
            auto new_transient_buffer_size = new_vertex_buffer_size + new_index_buffer_size;

            buffer_ensure_capacity(renderer, &frame_pipeline_instantiation->transient_buffer, new_transient_buffer_size);
            buffer_ensure_capacity(renderer, &frame_pipeline_instantiation->vertex_buffer.gpu, new_vertex_buffer_size);
            buffer_ensure_capacity(renderer, &frame_pipeline_instantiation->index_buffer.gpu, new_index_buffer_size);

            buffer_copy_to_host(frame_pipeline_instantiation->transient_buffer, (Slice(HostBufferCopy)) array_to_slice(((HostBufferCopy[]) {
                (HostBufferCopy) {
                    .source = (String) {
                        .pointer = (u8*)frame_pipeline_instantiation->vertex_buffer.cpu.pointer,
                        .length = new_vertex_buffer_size,
                    },
                    .destination_offset = 0,
                },
                (HostBufferCopy) {
                    .source = (String) {
                        .pointer = (u8*)frame_pipeline_instantiation->index_buffer.cpu.pointer,
                        .length = new_index_buffer_size,
                    },
                    .destination_offset = new_vertex_buffer_size,
                },
            })));

            buffer_copy_to_local_command(frame->command_buffer, (Slice(LocalBufferCopy)) array_to_slice(((LocalBufferCopy[]) {
                {
                    .destination = frame_pipeline_instantiation->vertex_buffer.gpu,
                    .source = frame_pipeline_instantiation->transient_buffer,
                    .regions = array_to_slice(((LocalBufferCopyRegion[]) {
                        {
                            .source_offset = 0,
                            .destination_offset = 0,
                            .size = new_vertex_buffer_size,
                        },
                    })),
                },
                {
                    .destination = frame_pipeline_instantiation->index_buffer.gpu,
                    .source = frame_pipeline_instantiation->transient_buffer,
                    .regions = array_to_slice(((LocalBufferCopyRegion[]) {
                        {
                            .source_offset = new_vertex_buffer_size,
                            .destination_offset = 0,
                            .size = new_index_buffer_size,
                        },
                    })),
                },
            })));
        }
    }
    
    vk_image_transition(frame->command_buffer, window->render_image.handle, VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);

    VkViewport viewports[] = {
        {
            .x = 0,
            .y = 0,
            .width = window->width,
            .height = window->height,
            .minDepth = 0.0f,
            .maxDepth = 1.0f,
        }
    };

    u32 first_viewport = 0;
    vkCmdSetViewport(frame->command_buffer, first_viewport, array_length(viewports), viewports);

    VkRect2D scissors[] = {
        {
            .offset = {
                .x = 0,
                .y = 0,
            },
            .extent = {
                .width = window->width,
                .height = window->height,
            },
        }
    };

    u32 first_scissor = 0;
    vkCmdSetScissor(frame->command_buffer, first_scissor, array_length(scissors), scissors);

    VkRenderingAttachmentInfo color_attachments[] = {
        {
            .sType = VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO,
            .imageView = window->render_image.view,
            .imageLayout = VK_IMAGE_LAYOUT_ATTACHMENT_OPTIMAL,
            .loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR,
            .storeOp = VK_ATTACHMENT_STORE_OP_STORE,
            .clearValue = { .color = { .float32 = { 255.0f, 0.0f, 255.0f, 1.0f } } },
        },
    };

    VkRenderingInfo rendering_info = {
        .sType = VK_STRUCTURE_TYPE_RENDERING_INFO,
        .renderArea = {
            .extent = {
                .width = window->width,
                .height = window->height,
            },
        },
        .layerCount = 1,
        .colorAttachmentCount = array_length(color_attachments),
        .pColorAttachments = color_attachments,
    };

    vkCmdBeginRendering(frame->command_buffer, &rendering_info);

    for (u32 i = 0; i < BB_PIPELINE_COUNT; i += 1)
    {
        auto* pipeline = &renderer->pipelines[i];
        auto* pipeline_instantiation = &window->pipeline_instantiations[i];
        auto* frame_pipeline_instantiation = &frame->pipeline_instantiations[i];

        if (likely(frame_pipeline_instantiation->vertex_buffer.cpu.length))
        {
            // Bind pipeline and descriptor sets
            {
                vkCmdBindPipeline(frame->command_buffer, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline->handle);
                // print("Binding pipeline: 0x{u64}\n", pipeline->handle);
                u32 dynamic_offset_count = 0;
                u32* dynamic_offsets = 0;
                u32 first_set = 0;
                vkCmdBindDescriptorSets(frame->command_buffer, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline->layout, first_set, pipeline->descriptor_set_count, pipeline_instantiation->descriptor_sets, dynamic_offset_count, dynamic_offsets);
                // print("Binding descriptor sets: 0x{u64}\n", pipeline_instantiation->descriptor_sets);
                frame->bound_pipeline = i;
            }

            // Bind index buffer
            {
                vkCmdBindIndexBuffer(frame->command_buffer, frame_pipeline_instantiation->index_buffer.gpu.handle, 0, VK_INDEX_TYPE_UINT32);
                frame->index_buffer = frame_pipeline_instantiation->index_buffer.gpu.handle;
                // print("Binding descriptor sets: 0x{u64}\n", frame->index_buffer);
            }

            // Send vertex buffer and screen dimensions to the shader
            auto push_constants = (GPUDrawPushConstants)
            {
                .vertex_buffer = frame_pipeline_instantiation->vertex_buffer.gpu.address,
                .width = window->width,
                .height = window->height,
            };

            {
                auto push_constant_range = pipeline->push_constant_ranges[0];
                vkCmdPushConstants(frame->command_buffer, pipeline->layout, push_constant_range.stageFlags, push_constant_range.offset, push_constant_range.size, &push_constants);
                frame->push_constants = push_constants;
            }

            vkCmdDrawIndexed(frame->command_buffer, frame_pipeline_instantiation->index_buffer.cpu.length, 1, 0, 0, 0);
        }
    }

    vkCmdEndRendering(frame->command_buffer);

    vk_image_transition(frame->command_buffer, window->render_image.handle, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);

    VkImage swapchain_image = window->swapchain_images[window->swapchain_image_index];
    vk_image_transition(frame->command_buffer, swapchain_image, VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);

    vk_image_copy(frame->command_buffer, (VulkanCopyImageArgs) {
        .source = {
            .handle = window->render_image.handle,
            .extent = {
                .width = window->width,
                .height = window->height,
            },
        },
        .destination = {
            .handle = swapchain_image,
            .extent = {
                .width = window->width,
                .height = window->height,
            },
        },
    });

    vk_image_transition(frame->command_buffer, swapchain_image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR);

    vkok(vkEndCommandBuffer(frame->command_buffer));

    VkCommandBufferSubmitInfo command_buffer_submit_info[] = {
        {
            .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_SUBMIT_INFO,
            .commandBuffer = frame->command_buffer,
            .deviceMask = 0,
        },
    };

    VkSemaphoreSubmitInfo wait_semaphore_submit_info[] = {
        {
            .sType = VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO,
            .semaphore = frame->swapchain_semaphore,
            .stageMask = VK_PIPELINE_STAGE_2_COLOR_ATTACHMENT_OUTPUT_BIT,
            .deviceIndex = 0,
            .value = 1,
        },
    };

    VkSemaphoreSubmitInfo signal_semaphore_submit_info[] = {
        {
            .sType = VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO,
            .semaphore = frame->render_semaphore,
            .stageMask = VK_PIPELINE_STAGE_2_ALL_GRAPHICS_BIT,
            .deviceIndex = 0,
            .value = 1,
        },
    };

    VkSubmitInfo2 submit_info[] = {
        {
            .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO_2,
            .flags = 0,
            .waitSemaphoreInfoCount = array_length(wait_semaphore_submit_info),
            .pWaitSemaphoreInfos = wait_semaphore_submit_info,
            .signalSemaphoreInfoCount = array_length(signal_semaphore_submit_info),
            .pSignalSemaphoreInfos = signal_semaphore_submit_info,
            .commandBufferInfoCount = array_length(command_buffer_submit_info),
            .pCommandBufferInfos = command_buffer_submit_info,
        },
    };

    vkok(vkQueueSubmit2(renderer->graphics_queue, array_length(submit_info), submit_info, frame->render_fence));

    const VkSwapchainKHR swapchains[] = { window->swapchain };
    const u32 swapchain_image_indices[] = { window->swapchain_image_index };
    const VkSemaphore wait_semaphores[] = { frame->render_semaphore };
    VkResult results[array_length(swapchains)];

    VkPresentInfoKHR present_info = {
        .sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
        .waitSemaphoreCount = array_length(wait_semaphores),
        .pWaitSemaphores = wait_semaphores,
        .swapchainCount = array_length(swapchains),
        .pSwapchains = swapchains,
        .pImageIndices = swapchain_image_indices,
        .pResults = results,
    };

    VkResult present_result = vkQueuePresentKHR(renderer->graphics_queue, &present_info);

    if (present_result == VK_SUCCESS)
    {
        for (u32 i = 0; i < array_length(results); i += 1)
        {
            vkok(results[i]);
        }
    }
    else if (present_result == VK_ERROR_OUT_OF_DATE_KHR || present_result == VK_SUBOPTIMAL_KHR)
    {
        swapchain_recreate(renderer, window);
    }
    else
    {
        vkok(present_result);
    }

    window->frame_index += 1;
}

fn VkFormat vk_texture_format(TextureFormat format)
{
    VkFormat result;
    switch (format)
    {
    case TEXTURE_FORMAT_R8_UNORM:
        result = VK_FORMAT_R8_UNORM;
        break;
    case TEXTURE_FORMAT_R8G8B8A8_SRGB:
        result = VK_FORMAT_R8G8B8A8_SRGB;
        break;
    }

    return result;
}

fn u32 format_channel_count(TextureFormat format)
{
    switch (format)
    {
    case TEXTURE_FORMAT_R8_UNORM:
        return 1;
    case TEXTURE_FORMAT_R8G8B8A8_SRGB:
        return 4;
    }
}

TextureIndex renderer_texture_create(Renderer* renderer, TextureMemory texture_memory)
{
    assert(texture_memory.depth == 1);

    auto texture_index = texture_count;
    texture_count += 1;
    auto* texture = &textures[texture_index];
    texture->image = vk_image_create(renderer->device, renderer->allocator, renderer->memory_properties, (VulkanImageCreate) {
        .width = texture_memory.width,
        .height = texture_memory.height,
        .mip_levels = 1,
        .format = vk_texture_format(texture_memory.format),
        .usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
    });
    texture->sampler = renderer->sampler;

    auto image_size = (u64)texture_memory.depth * texture_memory.width * texture_memory.height * format_channel_count(texture_memory.format);
    VkBufferUsageFlags buffer_usage_flags = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    VkMemoryPropertyFlags buffer_memory_flags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    auto transfer_buffer = vk_buffer_create(renderer->device, renderer->allocator, renderer->memory_properties, image_size, buffer_usage_flags, buffer_memory_flags);
    memcpy((void*)transfer_buffer.address, texture_memory.pointer, image_size);

    immediate_start(renderer->immediate);

    vk_image_transition(renderer->immediate.command_buffer, texture->image.handle, VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);

    VkBufferImageCopy copy_regions[] = {
        {
            .bufferOffset = 0,
            .bufferRowLength = 0,
            .bufferImageHeight = 0,
            .imageSubresource = {
                .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
                .mipLevel = 0,
                .baseArrayLayer = 0,
                .layerCount = 1,
            },
            .imageOffset = {
                .x = 0,
                .y = 0,
                .z = 0,
            },
            .imageExtent = {
                .width = texture_memory.width,
                .height = texture_memory.height,
                .depth = texture_memory.depth,
            },
        }
    };

    vkCmdCopyBufferToImage(renderer->immediate.command_buffer, transfer_buffer.handle, texture->image.handle, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, array_length(copy_regions), copy_regions);

    vk_image_transition(renderer->immediate.command_buffer, texture->image.handle, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);

    immediate_end(renderer->immediate);

    return (TextureIndex) { .value = texture_index };
}

void window_draw_indexed(RenderWindow* window, u32 index_count, u32 instance_count, u32 first_index, s32 vertex_offset, u32 first_instance)
{
    auto* frame = window_frame(window);
    vkCmdDrawIndexed(frame->command_buffer, index_count, instance_count, first_index, vertex_offset, first_instance);
}

fn void window_texture_update_begin(RenderWindow* window, BBPipeline pipeline_index, u32 descriptor_count)
{
    auto* pipeline_instantiation = &window->pipeline_instantiations[pipeline_index];
    assert(descriptor_count <= array_length(pipeline_instantiation->texture_descriptors));

    pipeline_instantiation->descriptor_set_update = (VkWriteDescriptorSet) {
        .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
        .pNext = 0,
        .dstSet = pipeline_instantiation->descriptor_sets[0],
        .dstBinding = 0,
        .dstArrayElement = 0,
        .descriptorCount = descriptor_count,
        .descriptorType = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER,
        .pImageInfo = pipeline_instantiation->texture_descriptors,
        .pBufferInfo = 0,
        .pTexelBufferView = 0,
    };
}

void window_rect_texture_update_begin(RenderWindow* window)
{
    window_texture_update_begin(window, BB_PIPELINE_RECT, RECT_TEXTURE_SLOT_COUNT);
}

fn void window_queue_pipeline_texture_update(RenderWindow* window, BBPipeline pipeline_index, u32 resource_slot, TextureIndex texture_index)
{
    auto* pipeline_instantiation = &window->pipeline_instantiations[pipeline_index];
    VkDescriptorImageInfo* descriptor_image = &pipeline_instantiation->texture_descriptors[resource_slot];
    VulkanTexture* texture = &textures[texture_index.value];
    *descriptor_image = (VkDescriptorImageInfo) {
        .sampler = texture->sampler,
        .imageView = texture->image.view,
        .imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL, // TODO: specify
    };
}

void window_queue_rect_texture_update(RenderWindow* window, RectTextureSlot slot, TextureIndex texture_index)
{
    window_queue_pipeline_texture_update(window, BB_PIPELINE_RECT, slot, texture_index);
}

void renderer_queue_font_update(Renderer* renderer, RenderWindow* window, RenderFontType type, TextureAtlas atlas)
{
    static_assert(RECT_TEXTURE_SLOT_MONOSPACE_FONT < RECT_TEXTURE_SLOT_PROPORTIONAL_FONT);
    auto slot = RECT_TEXTURE_SLOT_MONOSPACE_FONT + type;
    window_queue_rect_texture_update(window, slot, atlas.texture);
    renderer->fonts[type] = atlas;
}

fn void window_texture_update_end(Renderer* renderer, RenderWindow* window, BBPipeline pipeline_index)
{
    auto* pipeline_instantiation = &window->pipeline_instantiations[pipeline_index];
    u32 descriptor_copy_count = 0;
    VkCopyDescriptorSet* descriptor_copies = 0;
    VkWriteDescriptorSet descriptor_set_writes[] = {
        pipeline_instantiation->descriptor_set_update,
    };
    vkUpdateDescriptorSets(renderer->device, array_length(descriptor_set_writes), descriptor_set_writes, descriptor_copy_count, descriptor_copies);
}

void window_rect_texture_update_end(Renderer* renderer, RenderWindow* window)
{
    window_texture_update_end(renderer, window, BB_PIPELINE_RECT);
}

u32 window_pipeline_add_vertices(RenderWindow* window, BBPipeline pipeline_index, String vertex_memory, u32 vertex_count)
{
    auto* frame = window_frame(window);
    auto* vertex_buffer = &frame->pipeline_instantiations[pipeline_index].vertex_buffer;
    vb_copy_string(&vertex_buffer->cpu, vertex_memory);
    auto vertex_offset = vertex_buffer->count;
    vertex_buffer->count = vertex_offset + vertex_count;
    return vertex_offset;
}

void window_pipeline_add_indices(RenderWindow* window, BBPipeline pipeline_index, Slice(u32) indices)
{
    auto* frame = window_frame(window);
    auto* index_pointer = vb_add(&frame->pipeline_instantiations[pipeline_index].index_buffer.cpu, indices.length);
    memcpy(index_pointer, indices.pointer, indices.length * sizeof(*indices.pointer));
}

void window_render_rect(RenderWindow* window, RectDraw draw)
{
    auto p0 = draw.vertex.p0;
    auto uv0 = draw.texture.p0;
    if (draw.texture.p1.x != 0)
    {
        assert(draw.texture.p1.x - draw.texture.p0.x == draw.vertex.p1.x - draw.vertex.p0.x);
        assert(draw.texture.p1.y - draw.texture.p0.y == draw.vertex.p1.y - draw.vertex.p0.y);
    }

    auto corner_radius = 5.0f;

    auto extent = draw.vertex.p1 - p0;
    RectVertex vertices[] = {
        (RectVertex) {
            .p0 = p0,
            .uv0 = uv0,
            .extent = extent,
            .texture_index = draw.texture_index,
            .colors = { draw.colors[0], draw.colors[1], draw.colors[2], draw.colors[3] },
            .softness = 1.0,
            .corner_radius = corner_radius,
        },
        (RectVertex) {
            .p0 = p0,
            .uv0 = uv0,
            .extent = extent,
            .texture_index = draw.texture_index,
            .colors = { draw.colors[0], draw.colors[1], draw.colors[2], draw.colors[3] },
            .softness = 1.0,
            .corner_radius = corner_radius,
        },
        (RectVertex) {
            .p0 = p0,
            .uv0 = uv0,
            .extent = extent,
            .texture_index = draw.texture_index,
            .colors = { draw.colors[0], draw.colors[1], draw.colors[2], draw.colors[3] },
            .softness = 1.0,
            .corner_radius = corner_radius,
        },
        (RectVertex) {
            .p0 = p0,
            .uv0 = uv0,
            .extent = extent,
            .texture_index = draw.texture_index,
            .colors = { draw.colors[0], draw.colors[1], draw.colors[2], draw.colors[3] },
            .softness = 1.0,
            .corner_radius = corner_radius,
        },
    };

    auto vertex_offset = window_pipeline_add_vertices(window, BB_PIPELINE_RECT, (String)array_to_bytes(vertices), array_length(vertices));

    u32 indices[] = {
        vertex_offset + 0,
        vertex_offset + 1,
        vertex_offset + 2,
        vertex_offset + 1,
        vertex_offset + 3,
        vertex_offset + 2,
    };

    window_pipeline_add_indices(window, BB_PIPELINE_RECT, (Slice(u32))array_to_slice(indices));
}

// TODO: support gradient
void window_render_text(Renderer* renderer, RenderWindow* window, String string, float4 color, RenderFontType font_type, u32 x_offset, u32 y_offset)
{
    auto* texture_atlas = &renderer->fonts[font_type];
    auto height = texture_atlas->ascent - texture_atlas->descent;
    auto texture_index = texture_atlas->texture.value;

    for (u64 i = 0; i < string.length; i += 1)
    {
        auto ch = string.pointer[i];
        auto* character = &texture_atlas->characters[ch];

        auto uv_x = character->x;
        auto uv_y = character->y;

        auto char_width = character->width;
        auto char_height = character->height;

        auto pos_x = x_offset;
        auto pos_y = y_offset + character->y_offset + height + texture_atlas->descent; // Offset of the height to render the character from the bottom (y + height) up (y)
        vec2 p0 = { pos_x, pos_y };
        vec2 uv0 = { uv_x, uv_y };
        vec2 extent = { char_width, char_height };
        // print("P0: ({u32}, {u32}). P1: ({u32}, {u32})\n", (u32)p0.x, (u32)p0.y, (u32)p1.x, (u32)p1.y);

        RectVertex vertices[] = {
            (RectVertex) {
                .p0 = p0,
                .uv0 = uv0,
                .extent = extent,
                .texture_index = texture_index,
                .colors = { color, color, color, color },
                .softness = 1.0,
            },
            (RectVertex) {
                .p0 = p0,
                .uv0 = uv0,
                .extent = extent,
                .texture_index = texture_index,
                .colors = { color, color, color, color },
                .softness = 1.0,
            },
            (RectVertex) {
                .p0 = p0,
                .uv0 = uv0,
                .extent = extent,
                .texture_index = texture_index,
                .colors = { color, color, color, color },
                .softness = 1.0,
            },
            (RectVertex) {
                .p0 = p0,
                .uv0 = uv0,
                .extent = extent,
                .colors = { color, color, color, color },
                .texture_index = texture_index,
                .softness = 1.0,
            },
        };

        auto vertex_offset = window_pipeline_add_vertices(window, BB_PIPELINE_RECT, (String)array_to_bytes(vertices), array_length(vertices));

        u32 indices[] = {
            vertex_offset + 0,
            vertex_offset + 1,
            vertex_offset + 2,
            vertex_offset + 1,
            vertex_offset + 3,
            vertex_offset + 2,
        };

        window_pipeline_add_indices(window, BB_PIPELINE_RECT, (Slice(u32))array_to_slice(indices));

        auto kerning = (texture_atlas->kerning_tables + ch * 256)[string.pointer[i + 1]];
        x_offset += character->advance + kerning;
    }
}

uint2 renderer_font_compute_string_rect(Renderer* renderer, RenderFontType type, String string)
{
    auto* texture_atlas = &renderer->fonts[type];
    auto result = texture_atlas_compute_string_rect(string, texture_atlas);
    return result;
}
