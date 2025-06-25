#!/usr/bin/env bash
set -eux
if [[ -n "${BUILD_DEBUG:-}" ]]; then
    export BUILD_DEBUG
    CMAKE_BUILD_TYPE=Debug ci/reproduce.sh
fi
CMAKE_BUILD_TYPE=Release ci/reproduce.sh
CMAKE_BUILD_TYPE=Release-assertions ci/reproduce.sh
ci/install.sh
ci/release.sh
