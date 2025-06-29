#!/usr/bin/env bash
set -eux

if [[ -z "${LLVM_VERSION:-}" ]]; then
    LLVM_VERSION=20.1.7
fi

if [[ -z "${BB_CI:-}" ]]; then
    BB_CI=0
fi

if [[ -z "${CMAKE_BUILD_TYPE:-}" ]]; then
    CMAKE_BUILD_TYPE=Debug
    LLVM_CMAKE_BUILD_TYPE=Release
else
    LLVM_CMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE
fi

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

if [[ -z "${CMAKE_PREFIX_PATH:-}" ]]; then
    CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_${LLVM_VERSION}_${BIRTH_ARCH}-${BIRTH_OS}-${LLVM_CMAKE_BUILD_TYPE}
fi

if [[ -z "${CLANG_PATH:-}" ]]; then
    CLANG_PATH=clang
    CLANGXX_PATH=clang++
fi

OPT_ARGS=""

case "${CMAKE_BUILD_TYPE%%-*}" in
    Debug) OPT_ARGS="-O0 -g";;
    Release*) OPT_ARGS="-O3";;
    RelWithDebInfo*) OPT_ARGS="-O3 -g";;
    MinSizeRel*) OPT_ARGS="-Oz -g";;
    *) exit 1;;
esac

mkdir -p self-hosted-bb-cache
$CLANG_PATH -c tests/c_abi.c -o self-hosted-bb-cache/c_abi.o $OPT_ARGS -std=gnu2x
