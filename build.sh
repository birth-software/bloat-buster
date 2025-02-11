#!/usr/bin/env bash
set -eu

MY_CWD=$PWD

if [[ -z "${BB_CI-}" ]]; then
    BB_CI=0
fi

if [[ -z "${BB_BUILD_TYPE-}" ]]; then
    BB_BUILD_TYPE=debug
fi

if [[ -z "${BB_ERROR_ON_WARNINGS-}" ]]; then
    BB_ERROR_ON_WARNINGS=$BB_CI
fi

if [[ -z "${BB_ERROR_LIMIT-}" ]]; then
    BB_ERROR_LIMIT=$((1 - BB_CI))
fi

BB_COMPILE_SHADERS=0

BUILD_DIR=cache
LARGE_ASSET_BASE_URL=https://github.com/birth-software/bloat-buster/releases/download/large-assets
mkdir -p $BUILD_DIR

if [[ ! -f "$BUILD_DIR/large_assembly.s" ]]; then
    cd $BUILD_DIR
    wget $LARGE_ASSET_BASE_URL/large_assembly.s -o large_assembly.s
    cd $MY_CWD
fi

if [[ "${BB_COMPILE_SHADERS}" == "1" ]]; then
    glslangValidator -V bootstrap/std/shaders/rect.vert -o $BUILD_DIR/rect.vert.spv --quiet
    glslangValidator -V bootstrap/std/shaders/rect.frag -o $BUILD_DIR/rect.frag.spv --quiet
fi

BUILD_OUT=$BUILD_DIR/build
C_COMPILER=clang
TIME_TRACE=1
BB_TIMETRACE=0
GCC_ARGS=
CLANG_ARGS=
TIME_TRACE_ARG=

if [[ $C_COMPILER == "clang"* ]]; then
    CLANG_ARGS=-ferror-limit=1
    if [[ "$TIME_TRACE" == "1" ]]; then
        CLANG_ARGS="$CLANG_ARGS -ftime-trace"
        BB_TIMETRACE=1
    else
        CLANG_ARGS="$CLANG_ARGS -ftime-trace"
    fi
elif [[ $C_COMPILER == "gcc"* ]]; then
    GCC_ARGS=-fmax-errors=1
fi

$C_COMPILER build.c -g -o $BUILD_OUT -Ibootstrap -std=gnu2x $CLANG_ARGS $GCC_ARGS -DBB_TIMETRACE=$BB_TIMETRACE -DBB_CI=$BB_CI -DBB_BUILD_TYPE=\"$BB_BUILD_TYPE\" -DBB_ERROR_ON_WARNINGS=$BB_ERROR_ON_WARNINGS -DBB_ERROR_LIMIT=$BB_ERROR_LIMIT
$BUILD_OUT $@
exit 0
