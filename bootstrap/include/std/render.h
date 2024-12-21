#pragma once


#include <std/base.h>

typedef struct Renderer Renderer;

#include <std/window.h>
#include <std/font_provider.h>

typedef struct RenderWindow RenderWindow;
typedef struct Pipeline Pipeline;

STRUCT(RenderRect)
{
    u32 x0;
    u32 y0;
    u32 x1;
    u32 y1;
};

STRUCT(RectColors)
{
    F32Vec4 v[4];
};

STRUCT(RectDraw)
{
    RenderRect vertex;
    RenderRect texture;
    RectColors colors;
    u32 texture_index;
};

STRUCT(RectVertex)
{
    f32 x;
    f32 y;
    f32 uv_x;
    f32 uv_y;
    RectColors colors;
    u32 texture_index;
    u32 reserved[3];
};
decl_vb(RectVertex);

#define Color4(r, g, b, a) ((F32Vec4){ .v = { r, g, b, a } })

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
    Slice(String) shader_sources;
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

EXPORT Renderer* renderer_initialize(Arena* arena);
EXPORT RenderWindow* renderer_window_initialize(Renderer* renderer, OSWindow window);
EXPORT PipelineIndex renderer_graphics_pipelines_create(Renderer* renderer, Arena* arena, GraphicsPipelinesCreate create_data);
EXPORT PipelineLayoutIndex renderer_pipeline_get_layout(PipelineIndex pipeline);
EXPORT void renderer_window_frame_begin(Renderer* renderer, RenderWindow* window);
EXPORT void renderer_window_frame_end(Renderer* renderer, RenderWindow* window);
EXPORT TextureIndex renderer_texture_create(Renderer* renderer, TextureMemory texture_memory);
EXPORT U32Vec2 renderer_font_compute_string_rect(Renderer* renderer, RenderFontType type, String string);
EXPORT void window_command_begin(RenderWindow* window);
EXPORT void window_command_end(RenderWindow* window);
EXPORT void window_render_begin(RenderWindow* window);
EXPORT void window_render_end(RenderWindow* window);

EXPORT void window_draw_indexed(RenderWindow* window, u32 index_count, u32 instance_count, u32 first_index, s32 vertex_offset, u32 first_instance);

EXPORT void window_rect_texture_update_begin(RenderWindow* window);
EXPORT void renderer_queue_font_update(Renderer* renderer, RenderWindow* window, RenderFontType type, TextureAtlas atlas);
EXPORT void window_queue_rect_texture_update(RenderWindow* window, RectTextureSlot slot, TextureIndex texture_index);
EXPORT void window_rect_texture_update_end(Renderer* renderer, RenderWindow* window);

EXPORT u32 window_pipeline_add_vertices(RenderWindow* window, BBPipeline pipeline_index, String vertex_memory, u32 vertex_count);
EXPORT void window_pipeline_add_indices(RenderWindow* window, BBPipeline pipeline_index, Slice(u32) indices);
EXPORT void window_render_rect(RenderWindow* window, RectDraw draw);
EXPORT void window_render_text(Renderer* renderer, RenderWindow* window, String string, Color color, RenderFontType font_type, u32 x_offset, u32 y_offset);
