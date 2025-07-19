set -eux

if [[ -z "${BB_CACHE_DIR:-}" ]]; then
    BB_CACHE_DIR=bb-cache
fi

rm -rf bb-cache $BB_CACHE_DIR || true
./generate.sh
CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_${LLVM_VERSION}_x86_64-linux-${CMAKE_BUILD_TYPE} $HOME/bloat-buster-artifacts/releases/main/compiler_generic compile src/compiler.bbb
bb-cache/x86_64_linux_development_di_native/compiler reproduce
mkdir -p $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE
mv $BB_CACHE_DIR $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE/cache
