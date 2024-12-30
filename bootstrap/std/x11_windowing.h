#pragma once

#include <xcb/xcb.h>

STRUCT(WindowingConnection)
{
    xcb_connection_t* handle;
    const xcb_setup_t* setup;
};

STRUCT(WindowingInstance)
{
    xcb_window_t handle;
};

fn xcb_connection_t* xcb_connection_get();
fn xcb_window_t xcb_window_from_windowing_instance(WindowingInstance* instance);
