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

#ifdef __clang__
#define BB_HAS_NATIVE_FLOAT2 1
#define BB_HAS_NATIVE_FLOAT3 1
#define BB_HAS_NATIVE_FLOAT4 1
#define BB_HAS_NATIVE_UINT2 1
#define BB_HAS_NATIVE_UINT3 1
#define BB_HAS_NATIVE_UINT4 1
#else
#define BB_HAS_NATIVE_FLOAT2 0
#define BB_HAS_NATIVE_FLOAT3 0
#define BB_HAS_NATIVE_FLOAT4 0
#define BB_HAS_NATIVE_UINT2 0
#define BB_HAS_NATIVE_UINT3 0
#define BB_HAS_NATIVE_UINT4 0
#endif

#if BB_HAS_NATIVE_FLOAT2
declare_vector_type(float, 2, float2);
#else
UNION(float2)
{
    struct
    {
        float x, y;
    };
    float v[2];
};
#endif

#if BB_HAS_NATIVE_FLOAT3
declare_vector_type(float, 3, float3);
#else
UNION(float3)
{
    struct
    {
        float x, y, z;
    };
    float v[3];
};
#endif

#if BB_HAS_NATIVE_FLOAT4
declare_vector_type(float, 4, float4);
#else
UNION(float4)
{
    struct
    {
        float x, y, z, w;
    };
    float v[4];
};
#endif

#if BB_HAS_NATIVE_UINT2
declare_vector_type(uint, 2, uint2);
#else
UNION(uint2)
{
    struct
    {
        uint x, y;
    };
    uint v[2];
};
#endif

#if BB_HAS_NATIVE_UINT3
declare_vector_type(uint, 3, uint3);
#else
UNION(uint3)
{
    struct
    {
        uint x, y, z;
    };
    uint v[3];
};
#endif

#if BB_HAS_NATIVE_UINT4
declare_vector_type(uint, 4, uint4);
#else
UNION(uint4)
{
    struct
    {
        uint x, y, z, w;
    };
    uint v[4];
};
#endif

typedef float2 vec2;
typedef float3 vec3;
typedef float4 vec4;

#if BB_HAS_NATIVE_FLOAT2
#define VEC2(_x, y) ((vec2){_x, _y})
#else
#define VEC2(_x, _y) ((vec2){ .x = _x, .y = _y})
#endif

#if BB_HAS_NATIVE_FLOAT3
#define VEC3(_x, _y, _z) ((vec3){_x, _y, _z})
#else
#define VEC3(_x, _y, _z) ((vec3){ .x = _x, .y = _y, .z = _z})
#endif

#if BB_HAS_NATIVE_FLOAT4
#define VEC4(_x, _y, _z, _w) ((vec4){_x, _y, _z, _w})
#else
#define VEC4(_x, _y, _z, _w) ((vec4){ .x = _x, .y = _y, .z = _z, .w = _w})
#endif

fn float2 float2_add(float2 a, float2 b)
{
#if BB_HAS_NATIVE_FLOAT2
    return a + b;
#else
    float2 result;
    result.x = a.x + b.x;
    result.y = a.y + b.y;
    return result;
#endif
}

fn float2 float2_sub(float2 a, float2 b)
{
#if BB_HAS_NATIVE_FLOAT2
    return a - b;
#else
    float2 result;
    result.x = a.x - b.x;
    result.y = a.y - b.y;
    return result;
#endif
}

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

typedef enum TextureFormat
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

ENUM(ShaderStage, u8, 
    SHADER_STAGE_VERTEX,
    SHADER_STAGE_FRAGMENT,
);

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

ENUM(DescriptorType, u8, 
    DESCRIPTOR_TYPE_IMAGE_PLUS_SAMPLER,
    DESCRIPTOR_TYPE_COUNT,
);

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

ENUM(BufferType, u8, 
    BUFFER_TYPE_VERTEX,
    BUFFER_TYPE_INDEX,
    BUFFER_TYPE_STAGING,
);

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
fn void renderer_window_frame_begin(Renderer* renderer, RenderWindow* window);
fn void renderer_window_frame_end(Renderer* renderer, RenderWindow* window);
fn TextureIndex renderer_texture_create(Renderer* renderer, TextureMemory texture_memory);

fn void window_rect_texture_update_begin(RenderWindow* window);
fn void renderer_queue_font_update(Renderer* renderer, RenderWindow* window, RenderFontType type, TextureAtlas atlas);
fn void window_queue_rect_texture_update(RenderWindow* window, RectTextureSlot slot, TextureIndex texture_index);
fn void window_rect_texture_update_end(Renderer* renderer, RenderWindow* window);

fn void window_render_rect(RenderWindow* window, RectDraw draw);
fn void window_render_text(Renderer* renderer, RenderWindow* window, String string, float4 color, RenderFontType font_type, u32 x_offset, u32 y_offset);
