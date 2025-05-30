#!/usr/bin/env bash
set -eu

if [[ -z "${BB_CI:-}" ]]; then
    CMAKE_BUILD_TYPE=Debug
    LLVM_CMAKE_BUILD_TYPE=Release
    BB_CI=0
else
    LLVM_CMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE
fi

BUILD_DIR=build

BIRTH_NATIVE_OS_STRING=$OSTYPE

case "$BIRTH_NATIVE_OS_STRING" in
    darwin*) BIRTH_OS="macos";;
    linux*) BIRTH_OS="linux";;
    msys*) BIRTH_OS="windows";;
    *) exit 1
esac

BIRTH_NATIVE_ARCH_STRING="$(uname -m)"

case "$BIRTH_NATIVE_ARCH_STRING" in
    x86_64) BIRTH_ARCH="x86_64";;
    arm64) BIRTH_ARCH="aarch64";;
    *) exit 1
esac

case "$BIRTH_OS" in
    linux) LINKER_TYPE=MOLD;;
    *) LINKER_TYPE=DEFAULT;;
esac

rm -rf $BUILD_DIR
mkdir $BUILD_DIR
cd $BUILD_DIR
LLVM_PREFIX_PATH=$HOME/dev/llvm/install/llvm_20.1.3_$BIRTH_ARCH-$BIRTH_OS-$LLVM_CMAKE_BUILD_TYPE

if [[ -z "${CLANG_PATH:-}" ]]; then
    CLANG_PATH=clang
    CLANGXX_PATH=clang++
fi


if [[ -n "${BB_CI+x}" ]]; then
    echo $LLVM_PREFIX_PATH
fi

cmake .. -G Ninja -DCMAKE_C_COMPILER=$CLANG_PATH -DCMAKE_CXX_COMPILER=$CLANGXX_PATH -DCMAKE_LINKER_TYPE=$LINKER_TYPE -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_PREFIX_PATH=$LLVM_PREFIX_PATH -DCMAKE_COLOR_DIAGNOSTICS=ON -DBB_CI=$BB_CI
cd ..
