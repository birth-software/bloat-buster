#pragma once

#if BB_RENDERING_BACKEND_VULKAN
#include <std/vulkan_rendering.h>
#endif

#if BB_RENDERING_BACKEND_METAL
#include <std/metal_rendering.h>
#endif

#if BB_RENDERING_BACKEND_DIRECTX12
#include <std/directx12_rendering.h>
#endif

typedef float float2 __attribute__((ext_vector_type(2)));
typedef float float3 __attribute__((ext_vector_type(3)));
typedef float float4 __attribute__((ext_vector_type(4)));
typedef float2 vec2;
typedef float3 vec3;
typedef float4 vec4;

typedef u32 uint2 __attribute__((ext_vector_type(2)));
typedef u32 uint3 __attribute__((ext_vector_type(3)));
typedef u32 uint4 __attribute__((ext_vector_type(4)));

UNION(F32Interval2)
{
    struct
    {
        vec2 min;
        vec2 max;
    };
    struct
    {
        float2 p0;
        float2 p1;
    };
    struct
    {
        f32 x0;
        f32 y0;
        f32 x1;
        f32 y1;
    };
    float2 v[2];
};
static_assert(sizeof(F32Interval2) == 4 * sizeof(f32));

typedef struct Renderer Renderer;
typedef struct RenderWindow RenderWindow;
typedef struct Pipeline Pipeline;

STRUCT(RectDraw)
{
    F32Interval2 vertex;
    F32Interval2 texture;
    vec4 colors[4];
    u32 texture_index;
};

#include "../std/shaders/rect.inc"
typedef struct RectVertex RectVertex;
decl_vb(RectVertex);

typedef enum BBPipeline
{
    BB_PIPELINE_RECT,
    BB_PIPELINE_COUNT,
} BBPipeline;

typedef enum RenderFontType
{
    RENDER_FONT_TYPE_MONOSPACE,
    RENDER_FONT_TYPE_PROPORTIONAL,
    RENDER_FONT_TYPE_COUNT,
} RenderFontType;

typedef enum RectTextureSlot
{
    RECT_TEXTURE_SLOT_WHITE,
    RECT_TEXTURE_SLOT_MONOSPACE_FONT,
    RECT_TEXTURE_SLOT_PROPORTIONAL_FONT,
    RECT_TEXTURE_SLOT_COUNT
} RectTextureSlot;

typedef enum IndexType : u8
{
    INDEX_TYPE_U32,
} IndexType;

typedef enum TextureFormat : u8
{
    TEXTURE_FORMAT_R8_UNORM,
    TEXTURE_FORMAT_R8G8B8A8_SRGB,
} TextureFormat;

STRUCT(TextureMemory)
{
    void* pointer;
    u32 width;
    u32 height;
    u32 depth;
    TextureFormat format;
};

typedef enum ShaderStage : u8
{
    SHADER_STAGE_VERTEX,
    SHADER_STAGE_FRAGMENT,
} ShaderStage;

STRUCT(PipelineCreate)
{
    Slice(u16) shader_source_indices;
    u16 layout_index;
};
declare_slice(PipelineCreate);

STRUCT(PushConstantRange)
{
    u16 offset;
    u16 size;
    ShaderStage stage;
};
declare_slice(PushConstantRange);

typedef enum DescriptorType : u8
{
    DESCRIPTOR_TYPE_IMAGE_PLUS_SAMPLER,
    DESCRIPTOR_TYPE_COUNT,
} DescriptorType;

STRUCT(DescriptorSetLayoutBinding)
{
    u8 binding;
    DescriptorType type;
    ShaderStage stage;
    u8 count;
};
declare_slice(DescriptorSetLayoutBinding);

STRUCT(DescriptorSetLayoutCreate)
{
    Slice(DescriptorSetLayoutBinding) bindings;
};
declare_slice(DescriptorSetLayoutCreate);

STRUCT(PipelineLayoutCreate)
{
    Slice(PushConstantRange) push_constant_ranges;
    Slice(DescriptorSetLayoutCreate) descriptor_set_layouts;
};
declare_slice(PipelineLayoutCreate);

STRUCT(GraphicsPipelinesCreate)
{
    Slice(String) shader_binaries;
    Slice(PipelineLayoutCreate) layouts;
    Slice(PipelineCreate) pipelines;
};

STRUCT(PipelineIndex)
{
    u32 value;
};

STRUCT(PipelineLayoutIndex)
{
    u32 value;
};

STRUCT(DescriptorSetIndex)
{
    u32 value;
};

typedef enum BufferType : u8
{
    BUFFER_TYPE_VERTEX,
    BUFFER_TYPE_INDEX,
    BUFFER_TYPE_STAGING,
} BufferType;

STRUCT(HostBufferCopy)
{
    String source;
    u64 destination_offset;
};
declare_slice(HostBufferCopy);

STRUCT(LocalBufferCopyRegion)
{
    u64 source_offset;
    u64 destination_offset;
    u64 size;
};
declare_slice(LocalBufferCopyRegion);

#include <std/font_provider.h>

fn Renderer* rendering_initialize(Arena* arena);
fn RenderWindow* rendering_initialize_window(Renderer* renderer, WindowingInstance* window);
fn PipelineIndex renderer_graphics_pipelines_create(Renderer* renderer, Arena* arena, GraphicsPipelinesCreate create_data);
fn PipelineLayoutIndex renderer_pipeline_get_layout(PipelineIndex pipeline);
fn void renderer_window_frame_begin(Renderer* renderer, RenderWindow* window);
fn void renderer_window_frame_end(Renderer* renderer, RenderWindow* window);
fn TextureIndex renderer_texture_create(Renderer* renderer, TextureMemory texture_memory);
fn uint2 renderer_font_compute_string_rect(Renderer* renderer, RenderFontType type, String string);
fn void window_command_begin(RenderWindow* window);
fn void window_command_end(RenderWindow* window);
fn void window_render_begin(RenderWindow* window);
fn void window_render_end(RenderWindow* window);

fn void window_draw_indexed(RenderWindow* window, u32 index_count, u32 instance_count, u32 first_index, s32 vertex_offset, u32 first_instance);

fn void window_rect_texture_update_begin(RenderWindow* window);
fn void renderer_queue_font_update(Renderer* renderer, RenderWindow* window, RenderFontType type, TextureAtlas atlas);
fn void window_queue_rect_texture_update(RenderWindow* window, RectTextureSlot slot, TextureIndex texture_index);
fn void window_rect_texture_update_end(Renderer* renderer, RenderWindow* window);

fn u32 window_pipeline_add_vertices(RenderWindow* window, BBPipeline pipeline_index, String vertex_memory, u32 vertex_count);
fn void window_pipeline_add_indices(RenderWindow* window, BBPipeline pipeline_index, Slice(u32) indices);
fn void window_render_rect(RenderWindow* window, RectDraw draw);
fn void window_render_text(Renderer* renderer, RenderWindow* window, String string, float4 color, RenderFontType font_type, u32 x_offset, u32 y_offset);
