#!/usr/bin/env bash
set -eux
ORIGINAL_DIR=$PWD
C_COMPILER_PATH=clang
CXX_COMPILER_PATH=clang++
ASM_COMPILER_PATH=clang

if [[ -z "${BIRTH_OS-}" ]]; then
    case "$OSTYPE" in
        msys*)
            BIRTH_OS=windows
            ;;
        linux*)
            BIRTH_OS=linux
            ;;
        darwin*)
            BIRTH_OS=macos
            ;;
        *)
            exit 1
            ;;
    esac
fi

if [[ "$BIRTH_OS" == "macos" ]]; then
    MY_HOMEBREW_PREFIX=$(brew --prefix llvm)
    C_COMPILER_PATH=$MY_HOMEBREW_PREFIX/bin/clang
    CXX_COMPILER_PATH=$MY_HOMEBREW_PREFIX/bin/clang++
    ASM_COMPILER_PATH=$MY_HOMEBREW_PREFIX/bin/clang
fi

if [[ -z "${BIRTH_ARCH-}" ]]; then
    case "$(uname -m)" in
        x86_64)
            BIRTH_ARCH=x86_64;;
        arm64)
            BIRTH_ARCH=aarch64;;
        *)
            exit 1;;
    esac
fi

if [[ -z "${CMAKE_BUILD_TYPE-}" ]]; then
    CMAKE_BUILD_TYPE=Debug
fi

if [[ -z "${CMAKE_PREFIX_PATH-}" ]]; then
    CMAKE_PREFIX_PATH="$HOME/Downloads/llvm-$BIRTH_ARCH-$BIRTH_OS-$CMAKE_BUILD_TYPE"
fi

if [[ -n "${BB_IS_CI-}" ]]; then
    BB_IS_CI=ON
else
    BB_IS_CI=OFF
fi

if [[ -z "${COMPILER_NAME-}" ]]; then
    COMPILER_NAME=bb
fi

if [[ -z "${BB_DIR-}" ]]; then
    BB_DIR=$COMPILER_NAME
fi

case $BIRTH_OS in
    windows)
        C_COMPILER_OPT_ARG="-DCMAKE_C_COMPILER_TARGET=x86_64-pc-windows-msvc"
        CXX_COMPILER_OPT_ARG="-DCMAKE_CXX_COMPILER_TARGET=x86_64-pc-windows-msvc"
        ASM_COMPILER_OPT_ARG="-DCMAKE_ASM_COMPILER_TARGET=x86_64-pc-windows-msvc"
        ;;
    *)
        C_COMPILER_OPT_ARG=""
        CXX_COMPILER_OPT_ARG=""
        ASM_COMPILER_OPT_ARG=""
        ;;
esac

case $BIRTH_OS in
    linux)
        USE_MOLD_OPT_ARG=-DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=mold"
        ;;
    *)
        USE_MOLD_OPT_ARG=""
        ;;
esac

BUILD_DIR=$ORIGINAL_DIR/build/$CMAKE_BUILD_TYPE
mkdir -p $BUILD_DIR
cmake . \
    -B$BUILD_DIR \
    -G Ninja \
    -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
    -DCMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH \
    -DCMAKE_C_COMPILER=$C_COMPILER_PATH \
    -DCMAKE_CXX_COMPILER=$CXX_COMPILER_PATH \
    -DCMAKE_ASM_COMPILER=$ASM_COMPILER_PATH \
    -DCOMPILER_NAME=$COMPILER_NAME \
    -DBB_DIR=$BB_DIR \
    -DBB_IS_CI=$BB_IS_CI \
    $USE_MOLD_OPT_ARG \
    $C_COMPILER_OPT_ARG \
    $CXX_COMPILER_OPT_ARG \
    $ASM_COMPILER_OPT_ARG
    
cd $BUILD_DIR
ninja -v
cd $ORIGINAL_DIR

if [ "$#" -ne 0 ]; then
    $BUILD_DIR/runner $@
fi

if [ "$BB_IS_CI" == "ON" ]; then
    echo "BUILD_DIR=$BUILD_DIR" >> $GITHUB_ENV
    echo "COMPILER_NAME=$COMPILER_NAME" >> $GITHUB_ENV
fi
