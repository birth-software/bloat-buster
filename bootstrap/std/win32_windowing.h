#pragma once

STRUCT(WindowingConnection)
{
    HINSTANCE instance;
    WNDCLASSEXW window_class;
};

STRUCT(WindowingInstance)
{
    HWND handle;
};

