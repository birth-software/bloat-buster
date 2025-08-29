cmake_minimum_required(VERSION 4.0)
project(bb)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
option(CMAKE_COMPILE_WARNING_AS_ERROR "Compile warnings as errors" ON)
add_compile_options(-march=native -masm=intel -funsigned-char -fwrapv -ferror-limit=1 -Wno-unused-function)
include_directories(BEFORE src)

add_executable(bb
    src/lib.c
    src/lexer.c
    src/parser.c
    src/analysis.c
    src/abi_system_v.c
    src/compiler.c
    src/main.c
)

if(UNIX AND NOT APPLE)
    find_library(URING_LIB uring REQUIRED)
    target_link_libraries(bb PRIVATE ${URING_LIB})
endif()
