cmake_minimum_required(VERSION 3.10)
project(bloat-buster)

include(CMakePrintHelpers)
cmake_print_variables("OS: ${CMAKE_SYSTEM_NAME}")
cmake_print_variables("Build type: ${CMAKE_BUILD_TYPE}")
cmake_print_variables("C flags Debug: ${CMAKE_C_FLAGS_DEBUG}")
cmake_print_variables("CXX flags Debug: ${CMAKE_CXX_FLAGS_DEBUG}")
cmake_print_variables("C flags MinSizeRel: ${CMAKE_C_FLAGS_MINSIZEREL}")
cmake_print_variables("CXX flags MinSizeRel: ${CMAKE_CXX_FLAGS_MINSIZEREL}")
cmake_print_variables("C flags RelWithDebInfo: ${CMAKE_C_FLAGS_RELWITHDEBINFO}")
cmake_print_variables("CXX flags RelWithDebInfo: ${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
cmake_print_variables("C flags Release: ${CMAKE_C_FLAGS_RELEASE}")
cmake_print_variables("CXX flags Release: ${CMAKE_CXX_FLAGS_RELEASE}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
set(SHADER_COMPILATION_USE_SOURCE OFF CACHE BOOL "Variable to control if to invoke command line for shader compilation or not")

set(LIBRARY_NAME "std")
set(RUNNER_NAME "runner")
if (NOT COMPILER_NAME)
    set(COMPILER_NAME "bb" CACHE STRING)
endif()

set(BB_IS_CI OFF CACHE BOOL "Variable that determines if the cmake script is run on the CI or not")

if (BB_IS_CI)
    set(BB_IS_CI_C_FLAG "-DBB_CI=1")
    message(STATUS "CMake is run on CI")
else()
    set(BB_IS_CI_C_FLAG "-DBB_CI=0")
    message(STATUS "CMake is not run on CI")
endif()

set (USE_LLVM ${BB_IS_CI} CACHE BOOL "Variable that determines if LLVM should be linked to the target")
if (SHADER_COMPILATION_USE_SOURCE)
    set(SHADER_COMPILATION_USE_SOURCE_C_FLAG "-DSHADER_COMPILATION_USE_SOURCE=1")
else()
    set(SHADER_COMPILATION_USE_SOURCE_C_FLAG "-DSHADER_COMPILATION_USE_SOURCE=0")
endif()

add_compile_options(
    -pedantic
    -Wall -Wextra -Wpedantic
    -Wno-nested-anon-types -Wno-keyword-macro -Wno-gnu-auto-type -Wno-auto-decl-extensions -Wno-gnu-empty-initializer -Wno-fixed-enum-extension -Wno-gnu-binary-literal
    -fno-exceptions -fno-stack-protector
    -fdiagnostics-color=always
    -fansi-escape-codes
    -ferror-limit=1
    # -march=native
    ${BB_IS_CI_C_FLAG} -DCOMPILER_NAME=\"${COMPILER_NAME}\" -DBUILD_DIR=\"${CMAKE_BINARY_DIR}\" -DBB_DIR=\"${BB_DIR}\" ${SHADER_COMPILATION_USE_SOURCE_C_FLAG}
)
include_directories("bootstrap/include")

add_library("${LIBRARY_NAME}"
    "bootstrap/std/base.c"
    "bootstrap/std/string.c"
    "bootstrap/std/format.c"
    "bootstrap/std/os.c"
    "bootstrap/std/entry_point.c"
    "bootstrap/std/virtual_buffer.c"
    "bootstrap/std/md5.c"
    "bootstrap/std/sha1.c"
)
add_executable("${RUNNER_NAME}" "bootstrap/runner/runner.c")
target_link_libraries(${RUNNER_NAME} PRIVATE ${LIBRARY_NAME})

add_executable("${COMPILER_NAME}"
    "bootstrap/bloat-buster/main.c"
    "bootstrap/bloat-buster/pdb_image.c"
    "bootstrap/bloat-buster/bb_core.c"
)
target_link_libraries(${COMPILER_NAME} PRIVATE ${LIBRARY_NAME})

if (USE_LLVM)
    find_package(LLVM REQUIRED CONFIG)

    find_program(LLVM_CONFIG_EXE
        NAMES llvm-config-19 llvm-config-19.0 llvm-config190 llvm-config19 llvm-config NAMES_PER_DIR
        PATHS
        "/mingw64/bin"
        "/c/msys64/mingw64/bin"
        "c:/msys64/mingw64/bin"
        "C:/Libraries/llvm-19.0.0/bin")

    if ("${LLVM_CONFIG_EXE}" STREQUAL "LLVM_CONFIG_EXE-NOTFOUND")
        if (NOT LLVM_CONFIG_ERROR_MESSAGES STREQUAL "")
            list(JOIN LLVM_CONFIG_ERROR_MESSAGES "\n" LLVM_CONFIG_ERROR_MESSAGE)
            message(FATAL_ERROR ${LLVM_CONFIG_ERROR_MESSAGE})
        else()
            message(FATAL_ERROR "unable to find llvm-config")
        endif()
    endif()

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libs
        OUTPUT_VARIABLE LLVM_LIBRARIES_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBRARIES "${LLVM_LIBRARIES_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --libdir
        OUTPUT_VARIABLE LLVM_LIBDIRS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_LIBDIRS "${LLVM_LIBDIRS_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --system-libs
        OUTPUT_VARIABLE LLVM_SYSTEM_LIBS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_SYSTEM_LIBS "${LLVM_SYSTEM_LIBS_SPACES}")

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --shared-mode
        OUTPUT_VARIABLE LLVM_LINK_MODE
        OUTPUT_STRIP_TRAILING_WHITESPACE)

    cmake_print_variables("LLVM libs: ${LLVM_LIBRARIES}")
    cmake_print_variables("LLVM libdirs: ${LLVM_LIBDIRS}")
    cmake_print_variables("LLVM system libs: ${LLVM_SYSTEM_LIBS}")
    cmake_print_variables("LLVM link mode: ${LLVM_LINK_MODE}")

    if (${LLVM_LINK_MODE} STREQUAL "shared")
        # We always ask for the system libs corresponding to static linking,
        # since on some distros LLD is only available as a static library
        # and we need these libraries to link it successfully
        execute_process(
            COMMAND ${LLVM_CONFIG_EXE} --system-libs --link-static
            OUTPUT_VARIABLE LLVM_STATIC_SYSTEM_LIBS_SPACES
            ERROR_QUIET # Some installations have no static libs, we just ignore the failure
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REPLACE " " ";" LLVM_STATIC_SYSTEM_LIBS "${LLVM_STATIC_SYSTEM_LIBS_SPACES}")
        find_library(LLD_COFF NAMES liblldCOFF.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_COMMON NAMES liblldCommon.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_ELF NAMES liblldELF.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_MACHO NAMES liblldMachO.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_MINGW NAMES liblldMinGW.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_WASM NAMES liblldWasm.so PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)

        set(LLVM_LIBRARIES ${LLVM_LIBRARIES} ${LLVM_SYSTEM_LIBS} ${LLVM_STATIC_SYSTEM_LIBS})
    else()
        find_library(LLD_COFF NAMES lldCOFF.lib lldCOFF.a liblldCOFF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_COMMON NAMES lldCommon.lib lldCommon.a liblldCommon.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_ELF NAMES lldELF.lib lldELF.a liblldELF.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_MACHO NAMES lldMachO.lib lldMachO.a liblldMachO.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_MINGW NAMES lldMinGW.lib lldMinGW.a liblldMinGW.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)
        find_library(LLD_WASM NAMES lldWasm.lib lldWasm.a liblldWasm.a PATHS ${LLVM_LIBRARY_DIRS} NO_DEFAULT_PATH)

        set(LLVM_LIBRARIES ${LLVM_LIBRARIES} ${LLVM_SYSTEM_LIBS})
    endif()

    set(lld_libs
        ${LLD_COFF}
        ${LLD_ELF}
        ${LLD_COMMON}
        ${LLD_MINGW}
        ${LLD_MACHO}
        ${LLD_WASM}
    )

    execute_process(
        COMMAND ${LLVM_CONFIG_EXE} --includedir
        OUTPUT_VARIABLE LLVM_INCLUDE_DIRS_SPACES
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE " " ";" LLVM_INCLUDE_DIRS "${LLVM_INCLUDE_DIRS_SPACES}")

    if (APPLE)
        if (MSVC)
            list(REMOVE_ITEM LLVM_LIBRARIES "zstd.lib")
        else()
            list(REMOVE_ITEM LLVM_LIBRARIES "-lzstd")
        endif()

        find_library(ZSTD NAMES libzstd.a libzstdstatic.a zstd NAMES_PER_DIR)
        list(APPEND LLVM_LIBRARIES "${ZSTD}")
    endif()

    link_directories("${LLVM_LIBDIRS}")

    target_compile_definitions(${COMPILER_NAME} PRIVATE ${LLVM_DEFINITIONS})
    cmake_print_variables("LLVM definitions: ${LLVM_DEFINITIONS}")
    target_include_directories(${COMPILER_NAME} PRIVATE ${LLVM_INCLUDE_DIRS})
    target_link_directories(${COMPILER_NAME} PRIVATE ${LLVM_LIBRARY_DIRS})
    target_link_libraries(${COMPILER_NAME} PRIVATE ${LLVM_LIBRARIES} ${lld_libs})
    target_sources(${COMPILER_NAME} PRIVATE
        "bootstrap/bloat-buster/llvm.cpp"
        "bootstrap/bloat-buster/lld_driver.c"
        "bootstrap/bloat-buster/lld_api.cpp"
    )
endif()

if (NOT BB_IS_CI)
    if (SHADER_COMPILATION_USE_SOURCE)
        add_subdirectory(dependencies/SPIRV-Headers-vulkan-sdk-1.3.296.0)
        add_subdirectory(dependencies/SPIRV-Tools-vulkan-sdk-1.3.296.0)
        add_subdirectory(dependencies/glslang-15.0.0)
        target_link_libraries(${COMPILER_NAME} PRIVATE glslang::glslang glslang::SPIRV glslang::glslang-default-resource-limits)
    endif()

    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

    add_subdirectory(dependencies/glfw-3.4)

    target_link_libraries(${COMPILER_NAME} PRIVATE glfw)

    if(CMAKE_SYSTEM_NAME STREQUAL Windows)
        set(VOLK_STATIC_DEFINES VK_USE_PLATFORM_WIN32_KHR)
        target_compile_definitions(${COMPILER_NAME} PRIVATE GLFW_EXPOSE_NATIVE_WIN32)
    elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
        set(VOLK_STATIC_DEFINES VK_USE_PLATFORM_XLIB_KHR)
        target_compile_definitions(${COMPILER_NAME} PRIVATE GLFW_EXPOSE_NATIVE_X11)
    elseif(CMAKE_SYSTEM_NAME STREQUAL Darwin)
        set(VOLK_STATIC_DEFINES VK_USE_PLATFORM_METAL_EXT)
        target_compile_definitions(${COMPILER_NAME} PRIVATE GLFW_EXPOSE_NATIVE_COCOA)
    endif()

    if (APPLE)
        find_library(METAL_LIBRARY Metal)
        target_link_libraries(${COMPILER_NAME} PRIVATE ${METAL_LIBRARY})
    else()
        if (APPLE)
            execute_process(
                COMMAND brew --prefix vulkan-headers
                OUTPUT_VARIABLE VULKAN_HEADERS_PREFIX
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            include_directories("${VULKAN_HEADERS_PREFIX}/include")
        endif()

        add_subdirectory(dependencies/volk-1.3.301 volk)
        target_link_libraries(${COMPILER_NAME} PRIVATE volk)
    endif()

    target_sources(${COMPILER_NAME} PRIVATE
        "bootstrap/std/image_loader.c"
        "bootstrap/std/shader_compilation.c"
        "bootstrap/std/font_cache.c"
        "bootstrap/std/font_provider.c"
        "bootstrap/std/window.c"
        "bootstrap/std/ui_core.c"
        "bootstrap/std/ui_builder.c"
    )

    if (APPLE)
        target_include_directories(${COMPILER_NAME} PRIVATE dependencies/metal-cpp_macOS15.2_iOS18.2)
        target_sources(${COMPILER_NAME} PRIVATE "bootstrap/std/renderer_metal.cpp")
    else()
        target_sources(${COMPILER_NAME} PRIVATE "bootstrap/std/renderer_vulkan.c")
    endif()

    target_include_directories(${COMPILER_NAME} PRIVATE dependencies/stb)
endif()
