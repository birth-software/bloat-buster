cmake_minimum_required(VERSION 4.0)
project(bb)

set(CMAKE_BUILD_TYPE Release)
add_compile_options(-march=native -masm=intel)
include_directories(BEFORE src)

add_executable(bb
    src/lib.c
    src/lexer.c
    src/parser.c
    src/compiler.c
    src/main.c
)

if(UNIX AND NOT APPLE)
    find_library(URING_LIB uring REQUIRED)
    target_link_libraries(bb PRIVATE ${URING_LIB})
endif()
