#!/usr/bin/env bash
set -eux

if [[ -z "${BB_BUILD_DEBUG:-}" ]]; then
    BB_BUILD_DEBUG=0
fi

if [[ -z "${BB_BUILD_NATIVE:-}" ]]; then
    BB_BUILD_NATIVE=0
fi

if [[ "$BB_BUILD_DEBUG" == "1" ]]; then
    CMAKE_BUILD_TYPE=Debug ci/reproduce.sh
fi

CMAKE_BUILD_TYPE=Release ci/reproduce.sh
CMAKE_BUILD_TYPE=Release-assertions ci/reproduce.sh
ci/install.sh
ci/release.sh
