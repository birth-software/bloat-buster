set -eux
mkdir -p $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)
if [[ -n "${BUILD_DEBUG:-}" ]]; then
    cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Debug/cache/generic/compiler/debug_none_di/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic_debug
fi
cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Release/cache/generic/aggressively_optimize_for_speed_nodi/compiler/aggressively_optimize_for_speed_nodi/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic
cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Release/cache/native/aggressively_optimize_for_speed_nodi/compiler/aggressively_optimize_for_speed_nodi/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_native
