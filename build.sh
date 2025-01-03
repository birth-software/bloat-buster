#!/usr/bin/env bash
set -eu
BUILD_DIR=cache
mkdir -p $BUILD_DIR
glslangValidator -V bootstrap/std/shaders/rect.vert -o $BUILD_DIR/rect.vert.spv --quiet
glslangValidator -V bootstrap/std/shaders/rect.frag -o $BUILD_DIR/rect.frag.spv --quiet
BUILD_OUT=$BUILD_DIR/build
C_COMPILER=tcc
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

$C_COMPILER build.c -g -o $BUILD_OUT -Ibootstrap -std=gnu2x $CLANG_ARGS $GCC_ARGS -DBB_TIMETRACE=$BB_TIMETRACE
$BUILD_OUT $@
exit 0
