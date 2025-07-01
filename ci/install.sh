set -eux
mkdir -p $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)

cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Release/cache/compiler/aggressively_optimize_for_speed_nodi/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic

if [[ -z "${BB_BUILD_DEBUG:-}" ]]; then
    BB_BUILD_DEBUG=0
fi

if [[ -z "${BB_BUILD_NATIVE:-}" ]]; then
    BB_BUILD_NATIVE=0
fi

if [[ "$BB_BUILD_DEBUG" == "1" ]]; then
    cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Release/cache/compiler/debug_none_di/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic_debug
fi

if [[ "$BB_BUILD_NATIVE" == "1" ]]; then
    cp $HOME/bloat-buster-artifacts/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/Release/cache/compiler/aggressively_optimize_for_speed_nodi/compiler $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_native
fi
