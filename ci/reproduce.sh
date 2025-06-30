set -eux

if [[ -z "${BB_CACHE_DIR:-}" ]]; then
    BB_CACHE_DIR=self-hosted-bb-cache
fi

rm -rf bb-cache self-hosted-bb-cache $BB_CACHE_DIR || true
./generate.sh
CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_${LLVM_VERSION}_x86_64-linux-${CMAKE_BUILD_TYPE} $HOME/bloat-buster-artifacts/releases/main/compiler_generic reproduce
mkdir -p $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE
mv $BB_CACHE_DIR $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE/cache
