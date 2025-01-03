#!/usr/bin/env bash
set -eu
BUILD_DIR=cache
mkdir -p $BUILD_DIR
glslangValidator -V bootstrap/std/shaders/rect.vert -o $BUILD_DIR/rect.vert.spv --quiet
glslangValidator -V bootstrap/std/shaders/rect.frag -o $BUILD_DIR/rect.frag.spv --quiet
BUILD_OUT=$BUILD_DIR/build
C_COMPILER=gcc
TIME_TRACE=1
TIME_TRACE_ARG=
if [[ "$C_COMPILER" == "clang"* ]]; then
if [[ "$TIME_TRACE" == "1" ]]; then
TIME_TRACE_ARG="-ftime-trace -DBB_TIMETRACE=1"
else
TIME_TRACE_ARG="-ftime-trace -DBB_TIMETRACE=0"
fi
    CLANG_ARGS=-ferror-limit=1
else
    CLANG_ARGS=
fi
echo "ASdasd"
$C_COMPILER $0 -g -o $BUILD_OUT -Ibootstrap -ferror-limit=1 -std=gnu2x $TIME_TRACE_ARG $CLANG_ARGS
$BUILD_OUT $@
exit 0
