set -eux
mkdir -p $HOME/bloat-buster-artifacts/releases/main/

cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic $HOME/bloat-buster-artifacts/releases/main/

if [[ -z "${BB_BUILD_DEBUG:-}" ]]; then
    BB_BUILD_DEBUG=0
fi

if [[ -z "${BB_BUILD_NATIVE:-}" ]]; then
    BB_BUILD_NATIVE=0
fi

if [[ "$BB_BUILD_DEBUG" == "1" ]]; then
    cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_generic_debug $HOME/bloat-buster-artifacts/releases/main/
fi

if [[ "$BB_BUILD_NATIVE" == "1" ]]; then
    cp $HOME/bloat-buster-artifacts/releases/$(git rev-parse --abbrev-ref HEAD)/$(git rev-parse HEAD)/compiler_native $HOME/bloat-buster-artifacts/releases/main/
fi
