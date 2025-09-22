cmake_minimum_required(VERSION 3.31)
project(bb)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug STRING "Build type" FORCE)
endif()
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_COLOR_DIAGNOSTICS ON)
option(CMAKE_COMPILE_WARNING_AS_ERROR "Compile warnings as errors" ON)
option(USE_LLVM "Build with LLVM support" ON)
option(USE_SANITIZER "Build with sanitizer support" OFF)

add_compile_options(-march=native -funsigned-char -fwrapv -ferror-limit=1 -Wno-unused-function)

if (CMAKE_C_COMPILER_TARGET MATCHES "^(x86_64|AMD64)$")
    add_compile_options(-masm=intel)
endif()

include_directories(BEFORE src)
add_compile_definitions(
  $<$<CONFIG:Debug>:BB_DEBUG=1>
  $<$<NOT:$<CONFIG:Debug>>:BB_DEBUG=0>
)

if (NOT "${XC_SDK_PATH}" STREQUAL "")
    add_compile_definitions(XC_SDK_PATH="${XC_SDK_PATH}")
endif()

if (USE_LLVM)
    add_compile_definitions(BB_USE_LLVM=1)
else()
    add_compile_definitions(BB_USE_LLVM=0)
endif()

add_compile_options(-Wno-pragma-once-outside-header)

# Optional LLVM support
if(USE_LLVM)
    find_package(LLVM REQUIRED CONFIG)
    find_package(LLD REQUIRED CONFIG)

    message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

    include_directories(${LLVM_INCLUDE_DIRS})
    add_definitions(${LLVM_DEFINITIONS})

    find_library(lld_bindings NAMES liblld_bindings.dylib lld_bindings.lib liblld_bindings.a liblld_bindingsELF.dll.a liblld_bindingsELF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_COMMON NAMES liblldCommon.dylib lldCommon.lib lldCommon.a liblldCommon.dll.a liblldCommon.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_ELF NAMES liblldELF.dylib lldELF.lib lldELF.a liblldELF.dll.a liblldELF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_COFF NAMES liblldCOFF.dylib lldCOFF.lib lldCOFF.a liblldCOFF.dll.a liblldCOFF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_MACHO NAMES liblldMachO.dylib lldMachO.lib lldMachO.a liblldMachO.dll.a liblldMachO.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_MINGW NAMES liblldMinGW.dylib lldMinGW.lib lldMinGW.a liblldMinGW.dll.a liblldMinGW.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
    find_library(LLD_WASM NAMES liblldWasm.dylib lldWasm.lib lldWasm.a liblldWasm.dll.a liblldWasm.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)

    add_compile_definitions(CMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}")
    add_compile_definitions(BB_CI=${BB_CI})
endif()

if (USE_SANITIZER)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

set (PROJECT_DIR src)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    set(UNITY_BUILD ON)
else()
    set(UNITY_BUILD OFF)
endif()

message(STATUS "UNITY_BUILD: ${UNITY_BUILD}")

if (UNITY_BUILD)
    add_compile_definitions(UNITY_BUILD=1)
    add_executable(bb
        ${PROJECT_DIR}/compiler.c
    )
else()
    add_compile_definitions(UNITY_BUILD=0)
    add_executable(bb
        ${PROJECT_DIR}/lib.c
        ${PROJECT_DIR}/lexer.c
        ${PROJECT_DIR}/parser.c
        ${PROJECT_DIR}/analysis.c
        ${PROJECT_DIR}/abi.c
        ${PROJECT_DIR}/abi_system_v.c
        ${PROJECT_DIR}/abi_win64.c
        ${PROJECT_DIR}/abi_aarch64.c
        ${PROJECT_DIR}/llvm_common.c
        ${PROJECT_DIR}/llvm_generate.c
        ${PROJECT_DIR}/llvm_optimize.c
        ${PROJECT_DIR}/llvm_emit.c
        ${PROJECT_DIR}/llvm_link.c
        ${PROJECT_DIR}/compiler.c
    )
endif()

if (USE_LLVM)
    target_link_libraries(bb PUBLIC
        ${LLVM_AVAILABLE_LIBS}
        ${LLD_COMMON}
        ${LLD_COFF}
        ${LLD_ELF}
        ${LLD_MACHO}
        ${LLD_MINGW}
        ${LLD_WASM}
        ${lld_bindings}
    )
endif()
