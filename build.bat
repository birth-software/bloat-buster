@echo off
setlocal enableextensions

if not defined BB_CI (
    set BB_CI=0
)

if not defined BB_BUILD_TYPE (
    set BB_BUILD_TYPE=debug
)

set BUILD_DIR=cache
mkdir %BUILD_DIR% > NUL 2>&1
set BUILD_OUT=cache\build.exe

if "%BB_CI%" == "0" (
    %VK_SDK_PATH%\Bin\glslangValidator.exe -V bootstrap\std\shaders\rect.vert -o cache\rect.vert.spv --quiet || exit /b 1
    %VK_SDK_PATH%\Bin\glslangValidator.exe -V bootstrap\std\shaders\rect.frag -o cache\rect.frag.spv --quiet || exit /b 1
)


cl /Zi /Y- /Gm- /std:clatest /diagnostics:caret -FC /nologo build.c /Fd%BUILD_DIR%\ /Fo%BUILD_DIR%\ /Fe%BUILD_OUT% -Ibootstrap -DBB_TIMETRACE=0 -DBB_BUILD_TYPE=\"%BB_BUILD_TYPE%\" -DBB_CI=%BB_CI% /link /INCREMENTAL:NO || exit /b 1
%BUILD_OUT%
