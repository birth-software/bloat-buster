#!/usr/bin/env bash
set -eux
if [[ -n "${BUILD_DEBUG:-}" ]]; then
    export BUILD_DEBUG
    CMAKE_BUILD_TYPE=Debug ./reproduce.sh
fi
CMAKE_BUILD_TYPE=Release ./reproduce.sh
CMAKE_BUILD_TYPE=Release-assertions ./reproduce.sh
./install.sh
./release.sh
