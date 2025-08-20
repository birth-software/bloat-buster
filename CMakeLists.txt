cmake_minimum_required(VERSION 4.0)
project(bb)

set (CMAKE_CXX_STANDARD 23)
set (CMAKE_C_STANDARD 23)
set(CMAKE_BUILD_TYPE Debug)
set(BUILD_SHARED_LIBS OFF)
add_compile_options(-march=native -masm=intel -static)
add_link_options(-static)
include_directories(BEFORE src)

add_executable(bb
    src/lib.c
    src/lexer.cpp
    src/parser.c
    src/compiler.c
    src/main.c
)

if(UNIX AND NOT APPLE)
    find_library(URING_LIB uring REQUIRED)
    target_link_libraries(bb PRIVATE ${URING_LIB})
endif()
