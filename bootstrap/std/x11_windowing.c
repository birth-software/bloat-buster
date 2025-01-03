#pragma once

global_variable xcb_window_t windowing_instance_handles[256];

typedef enum WindowingEvent : u32
{
    WINDOWING_EVENT_CLOSE,
    WINDOWING_EVENT_COUNT,
} WindowingEvent;

fn xcb_connection_t* xcb_connection_get()
{
    return windowing_connection.handle;
}

fn xcb_window_t xcb_window_from_windowing_instance(WindowingInstance* instance)
{
    return instance->handle;
}

fn void x11_intern_atoms(u32 atom_count, String* names, xcb_intern_atom_cookie_t* cookies, xcb_intern_atom_reply_t** replies)
{
    xcb_connection_t* connection = windowing_connection.handle;

    for (u64 i = 0; i < atom_count; i += 1)
    {
        String atom_name = names[i];

        cookies[i] = xcb_intern_atom(connection, 0, atom_name.length, string_to_c(atom_name));
    }

    for (u64 i = 0; i < atom_count; i += 1)
    {
        replies[i] = xcb_intern_atom_reply(connection, cookies[i], 0);
    }
}

typedef enum X11Atom
{
    X11_ATOM_WM_PROTOCOLS,
    X11_ATOM_WM_DELETE_WINDOW,
    X11_ATOM_COUNT,
} X11Atom;

global_variable String atom_names[X11_ATOM_COUNT] = {
    strlit("WM_PROTOCOLS"),
    strlit("WM_DELETE_WINDOW"),
};
global_variable xcb_intern_atom_reply_t* atom_replies[array_length(atom_names)];
global_variable xcb_intern_atom_cookie_t atom_cookies[array_length(atom_names)];

fn u8 windowing_initialize()
{
    u8 result = 0;

    windowing_connection.handle = xcb_connect(0, 0);
    if (windowing_connection.handle)
    {
        if (!xcb_connection_has_error(windowing_connection.handle))
        {
            windowing_connection.setup = xcb_get_setup(windowing_connection.handle);

            if (windowing_connection.setup)
            {
                x11_intern_atoms(array_length(atom_names), atom_names, atom_cookies, atom_replies);

                if (atom_replies[X11_ATOM_WM_PROTOCOLS])
                {
                    if (atom_replies[X11_ATOM_WM_DELETE_WINDOW])
                    {
                        result = 1;
                    }
                }
            }
        }
    }

    return result;
}

fn WindowingInstance* windowing_instantiate(WindowingInstantiate create)
{
    xcb_connection_t* connection = windowing_connection.handle;
    xcb_screen_iterator_t iter = xcb_setup_roots_iterator(windowing_connection.setup);
    xcb_screen_t *screen = iter.data;

    /* Create a window */
    xcb_window_t window_handle = xcb_generate_id(connection);

    u32 i;
    for (i = 0; i < array_length(windowing_instance_handles); i += 1)
    {
        xcb_window_t* window_handle_pointer = &windowing_instance_handles[i];
        if (!*window_handle_pointer)
        {
            *window_handle_pointer = window_handle;
            break;
        }
    }

    WindowingInstance* window = &windowing_instances[i];
    window->handle = window_handle;

    u32 value_mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
    u32 value_list[] = {
        screen->black_pixel,
        XCB_EVENT_MASK_EXPOSURE | XCB_EVENT_MASK_KEY_PRESS | XCB_EVENT_MASK_STRUCTURE_NOTIFY
    };

    xcb_create_window(
        connection,                     /* Connection */
        XCB_COPY_FROM_PARENT,           /* Depth (same as parent) */
        window_handle,                         /* Window ID */
        screen->root,                   /* Parent window (root) */
        create.offset.x, create.offset.y,                       /* X, Y */
        create.size.width, create.size.height,
        10,                             /* Border width */
        XCB_WINDOW_CLASS_INPUT_OUTPUT,  /* Class */
        screen->root_visual,            /* Visual */
        value_mask,                     /* Value mask */
        value_list                      /* Value list */
    );

    xcb_change_property(connection, XCB_PROP_MODE_REPLACE, window_handle, atom_replies[X11_ATOM_WM_PROTOCOLS]->atom, XCB_ATOM_ATOM, 32, 1, &atom_replies[X11_ATOM_WM_DELETE_WINDOW]->atom);

    xcb_map_window(connection, window_handle);

    /* Flush requests to the X server */
    xcb_flush(connection);

    return window;
}

fn void windowing_poll_events()
{
    xcb_generic_event_t *event;
    xcb_connection_t* connection = windowing_connection.handle;

    while ((event = xcb_poll_for_event(connection)))
    {
        switch (event->response_type & ~0x80) {
            case XCB_EXPOSE:
                break;
            case XCB_KEY_PRESS:
                break;
            case XCB_CLIENT_MESSAGE:
                {
                    let_pointer_cast(xcb_client_message_event_t, client_message_event, event);
                    if (client_message_event->data.data32[0] == atom_replies[X11_ATOM_WM_DELETE_WINDOW]->atom)
                    {
                        xcb_window_t window_handle = client_message_event->window;
                        u32 i;
                        u32 window_handle_count = array_length(windowing_instance_handles);
                        for (i = 0; i < window_handle_count; i += 1)
                        {
                            xcb_window_t* window_handle_pointer = &windowing_instance_handles[i];
                            if (window_handle == *window_handle_pointer)
                            {
                                windowing_instances[i].handle = 0;
                                *window_handle_pointer = 0;
                                // TODO: For now do this
                                os_exit(0);
                                break;
                            }
                        }

                        if (i == window_handle_count)
                        {
                            os_exit(1);
                        }
                    }
                    else
                    {
                        trap();
                    }
                } break;
            case XCB_DESTROY_NOTIFY:
                trap();
            default:
                break;
        }
        os_free(event);
    }
}

fn WindowingSize windowing_get_instance_framebuffer_size(WindowingInstance* instance)
{
    WindowingSize result = {};
    xcb_connection_t* connection = windowing_connection.handle;
    xcb_window_t window = instance->handle;
    xcb_get_geometry_cookie_t cookie = xcb_get_geometry(connection, window);
    xcb_get_geometry_reply_t* reply = xcb_get_geometry_reply(connection, cookie, 0);
    result.width = reply->width;
    result.height = reply->height;
    os_free(reply);
    return result;
}
