#version 450
#extension GL_EXT_buffer_reference : require
#extension GL_EXT_debug_printf : require

layout (location = 0) out vec4 out_color;
layout (location = 1) out vec2 out_uv;
layout (location = 2) out uint out_texture_index;

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

    //output data
    gl_Position = vec4(2 * v.x / width - 1, 2 * v.y / height - 1, 0, 1);
    out_uv = vec2(v.uv_x, v.uv_y);
    out_color = v.colors[gl_VertexIndex % 4];
    out_texture_index = v.texture_index;
    //debugPrintfEXT("Vertex index: (%u)\n", gl_VertexIndex);
    //debugPrintfEXT("UV: (%f, %f)\n", v.uv_x, v.uv_y);
}
