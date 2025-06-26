cmake_minimum_required(VERSION 3.15)
include(CMakePrintHelpers)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
project(bb)

find_package(LLVM REQUIRED CONFIG)
find_package(LLD REQUIRED CONFIG)

add_executable(bb
    src/lib.cpp
    src/entry_point.cpp
    src/compiler.cpp
    src/parser.cpp
    src/emitter.cpp
)

add_library(c_abi tests/c_abi.c)

include_directories(src)
add_compile_definitions(
  $<$<CONFIG:Debug>:BB_DEBUG=1>
  $<$<NOT:$<CONFIG:Debug>>:BB_DEBUG=0>
)

find_library(llvm_bindings NAMES libllvm_bindings.dylib libllvm_bindings.lib libllvm_bindings.a libllvm_bindingsELF.dll.a libllvm_bindingsELF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_COMMON NAMES liblldCommon.dylib lldCommon.lib lldCommon.a liblldCommon.dll.a liblldCommon.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_ELF NAMES liblldELF.dylib lldELF.lib lldELF.a liblldELF.dll.a liblldELF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_COFF NAMES liblldCOFF.dylib lldCOFF.lib lldCOFF.a liblldCOFF.dll.a liblldCOFF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_MACHO NAMES liblldMachO.dylib lldMachO.lib lldMachO.a liblldMachO.dll.a liblldMachO.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_MINGW NAMES liblldMinGW.dylib lldMinGW.lib lldMinGW.a liblldMinGW.dll.a liblldMinGW.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(LLD_WASM NAMES liblldWasm.dylib lldWasm.lib lldWasm.a liblldWasm.dll.a liblldWasm.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)

target_link_libraries(bb PUBLIC
    ${LLVM_AVAILABLE_LIBS}
    ${LLD_COMMON}
    ${LLD_COFF}
    ${LLD_ELF}
    ${LLD_MACHO}
    ${LLD_MINGW}
    ${LLD_WASM}
    ${llvm_bindings}
)

add_compile_options(-Wall -Wextra -pedantic -Wpedantic -Werror -Wno-c99-extensions -Wno-unused-function -Wno-missing-designated-field-initializers -fno-signed-char -fwrapv -fno-strict-aliasing)
add_compile_definitions(CMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}")
add_compile_definitions(BB_CI=${BB_CI})

# add_compile_options(-fsanitize=address)
# add_link_options(-fsanitize=address)
