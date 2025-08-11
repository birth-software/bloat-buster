cmake_minimum_required(VERSION 4.0)
project(bb)

set(CMAKE_BUILD_TYPE Debug)

add_executable(bb
    src/lib.c
    src/lexer.c
    src/parser.c
    src/compiler.c
    src/main.c
)

add_compile_options(-march native)
include_directories(BEFORE src)
find_library(URING_LIB uring REQUIRED)
target_link_libraries(bb PRIVATE ${URING_LIB})
