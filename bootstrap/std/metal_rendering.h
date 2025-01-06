#pragma once

#import <Metal/Metal.h>

STRUCT(Renderer)
{
    id<MTLDevice> device;
    id<MTLCommandQueue> command_queue;
    id<MTLRenderPipelineState> pipeline_state;
};

STRUCT(RenderWindow)
{
    CAMetalLayer* layer;
};

