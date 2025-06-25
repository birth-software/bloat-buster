set -eux
mkdir -p $HOME/bloat-buster-artifacts/releases/main/
if [[ -n "${BUILD_DEBUG:-}" ]]; then
    cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic_debug $HOME/bloat-buster-artifacts/releases/main/
fi
cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic $HOME/bloat-buster-artifacts/releases/main/
cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_native $HOME/bloat-buster-artifacts/releases/main/
