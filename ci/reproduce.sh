set -eux
rm -rf bb-cache self-hosted-bb-cache || true
./generate.sh
CMAKE_PREFIX_PATH=$HOME/dev/llvm/install/llvm_${LLVM_VERSION}_x86_64-linux-${CMAKE_BUILD_TYPE} $HOME/bloat-buster-artifacts/releases/main/compiler_generic_debug reproduce
mkdir -p $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE
mv ./self-hosted-bb-cache $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE/cache
