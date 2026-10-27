#!/usr/bin/env bash
# Builds the uCsim ST7 simulator (a test oracle, run as a black box) at the commit the results in
# GHIDRA-RARE.md were produced with.   test/build-ucsim.sh <dir>   then
#   export UCSIM_ST7=<dir>/ucsim/src/sims/st7.src/ucsim_st7
set -euo pipefail
DIR=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$DIR"
[[ -d ucsim ]] || git clone -q https://github.com/danieldrotos/ucsim.git
cd ucsim
git checkout -q 6f7cf7a4a67f5787a3a59847cfbd9f366a222e4b
./configure >/dev/null && make -j"$(nproc)" >/dev/null
ls -l src/sims/st7.src/ucsim_st7
