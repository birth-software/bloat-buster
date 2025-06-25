set -eux
rm -rf bb-cache self-hosted-bb-cache || true
./generate.sh
./build.sh
./build/bb test
mkdir -p $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE
mv ./self-hosted-bb-cache $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/$CMAKE_BUILD_TYPE/cache

