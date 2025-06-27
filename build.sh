set -eu
if [[ -z "${BOOTSTRAP_COMPILER:-}" ]]; then
    BOOTSTRAP_COMPILER=$HOME/bloat-buster-artifacts/releases/main/compiler_generic
fi

$BOOTSTRAP_COMPILER compile src/compiler.bbb
