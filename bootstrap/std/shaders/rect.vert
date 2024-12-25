#version 450
#extension GL_EXT_buffer_reference : require
#extension GL_EXT_debug_printf : require
#extension GL_GOOGLE_include_directive : require

#include "rect.inc"

layout (location = 0) out uint texture_index;
layout (location = 1) out RectFragmentShaderInput outputs;

layout(buffer_reference, std430) readonly buffer VertexBuffer{ 
   RectVertex vertices[];
};

layout(push_constant) uniform constants
{
    VertexBuffer vertex_buffer;
    float width;
    float height;
} PushConstants;

const vec2 vertices[] = {
    { -1, -1 },
    { +1, -1 },
    { -1, +1 },
    { +1, +1 },
};

void main() 
{
    RectVertex v = PushConstants.vertex_buffer.vertices[gl_VertexIndex];
    uint vertex_id = gl_VertexIndex % 4;
    float width = PushConstants.width;
    float height = PushConstants.height;

    vec2 extent = v.extent;

    vec2 p0 = v.p0;
    vec2 p1 = p0 + extent;
    vec2 position_center = (p1 + p0) / 2;
    vec2 half_size = (p1 - p0) / 2;
    vec2 position = vertices[vertex_id] * half_size + position_center;
    //debugPrintfEXT("Vertex index: (%u). P0: (%f, %f). P1: (%f, %f). Center: (%f, %f). Half size: (%f, %f). Position: (%f, %f)\n", gl_VertexIndex, p0.x, p0.y, p1.x, p1.y, center.x, center.y, half_size.x, half_size.y, position.x, position.y);

    gl_Position = vec4(2 * position.x / width - 1, 2 * position.y / height - 1, 0, 1);

    vec2 uv0 = v.uv0;
    vec2 uv1 = uv0 + extent;
    vec2 texture_center = (uv1 + uv0) / 2;
    vec2 uv = vertices[vertex_id] * half_size + texture_center;

    texture_index = v.texture_index;
    
    outputs.color = v.colors[vertex_id];
    outputs.uv = uv;
    outputs.position = position;
    outputs.center = position_center;
    outputs.half_size = half_size;
    outputs.corner_radius = v.corner_radius;
    outputs.softness = v.softness;
}
