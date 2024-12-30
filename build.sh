#!/usr/bin/env bash
set -eux

source ./common.sh

mkdir -p $BUILD_DIR

MACOS_FLAGS="-x objective-c"
case "$BIRTH_OS" in
    macos) OS_FLAGS=$MACOS_FLAGS;;
    *) OS_FLAGS="";;
esac

case "$BIRTH_OS" in
    macos) WINDOW_LIBRARIES="-lobjc -framework AppKit";;
    linux) WINDOW_LIBRARIES="-lxcb";;
    *) exit 1
esac

time $CC $OS_FLAGS -g bootstrap/bloat-buster/bb.c -o $BUILD_DIR/bb -Ibootstrap/include -std=c2x -ferror-limit=1 $WINDOW_LIBRARIES
$BUILD_DIR/bb
