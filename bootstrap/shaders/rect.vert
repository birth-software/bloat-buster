#version 450
#extension GL_EXT_buffer_reference : require
#extension GL_EXT_debug_printf : require
#extension GL_GOOGLE_include_directive : require

#include "rect.h"

layout (location = 0) out uint texture_index;
layout (location = 1) out FragmentShaderInput outputs;

struct Vertex {
    float x;
    float y;
    float uv_x;
    float uv_y;
    vec4 colors[4];
    uint texture_index;
    uint r[3];
}; 

layout(buffer_reference, std430) readonly buffer VertexBuffer{ 
   Vertex vertices[];
};

//push constants block
layout(push_constant) uniform constants
{
    VertexBuffer vertex_buffer;
    float width;
    float height;
} PushConstants;

void main() 
{
    Vertex v = PushConstants.vertex_buffer.vertices[gl_VertexIndex];
    float width = PushConstants.width;
    float height = PushConstants.height;

    gl_Position = vec4(2 * v.x / width - 1, 2 * v.y / height - 1, 0, 1);

    outputs.uv = vec2(v.uv_x, v.uv_y);
    outputs.color = v.colors[gl_VertexIndex % 4];
    texture_index = v.texture_index;

    //debugPrintfEXT("Vertex index: (%u)\n", gl_VertexIndex);
    //debugPrintfEXT("UV: (%f, %f)\n", v.uv_x, v.uv_y);
}
