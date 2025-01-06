#pragma once

#pragma comment(lib, "user32")

fn LRESULT window_callback(HWND window, UINT message, WPARAM w_parameter, LPARAM l_parameter)
{
    return DefWindowProcW(window, message, w_parameter, l_parameter);
}

fn u8 windowing_initialize()
{
    HINSTANCE instance = GetModuleHandleW(0);
    windowing_connection.instance = instance;
    WNDCLASSEXW window_class = {
        .cbSize = sizeof(window_class),
        .lpfnWndProc = window_callback,
        .hInstance = instance,
        .lpszClassName = L"window",
        .hCursor = LoadCursorA(0, IDC_ARROW),
        .hIcon = LoadIcon(instance, MAKEINTRESOURCE(1)),
        .style = CS_VREDRAW|CS_HREDRAW,
    };
    RegisterClassExW(&window_class);
    windowing_connection.window_class = window_class;
    return 1;
}

fn WindowingInstance* windowing_instantiate(WindowingInstantiate instantiate)
{
    // TODO:
    WindowingInstance* window = &windowing_instances[0];
    window->handle = CreateWindowExW(WS_EX_APPWINDOW, L"window", L"Bloat Buster", WS_OVERLAPPEDWINDOW | WS_SIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, instantiate.size.width, instantiate.size.height, 0, 0, windowing_connection.instance, 0);
    ShowWindow(window->handle, SW_SHOW);
    return window;
}

fn WindowingSize windowing_get_instance_framebuffer_size(WindowingInstance* instance)
{
    RECT area;
    GetClientRect(instance->handle, &area);
    WindowingSize size = {
        .width = area.right,
        .height = area.bottom,
    };

    return size;
}

fn void windowing_poll_events()
{
    MSG msg;
    HWND handle;

    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
