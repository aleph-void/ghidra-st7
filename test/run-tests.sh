#!/usr/bin/env bash
# Runs every ST7 check that needs no non-redistributable input.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/ST7> \
#     test/run-tests.sh [--real] [--n <random-cases>] <workdir>
#
# Needs: asl (AS 1.42, `asl` on PATH), python3, a JDK for Ghidra. The uCsim ST7 simulator is used
# when UCSIM_ST7 points at it (see test/build-ucsim.sh); without it the semantics check compares
# only with the manual model. --real fetches the RabbitNet firmware (pinned URL + SHA-256) and
# runs test/real-check.sh. Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; N=60000
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --n) N=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "${1:?usage: run-tests.sh [--real] <workdir>}" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
command -v asl >/dev/null || { echo "asl (AS 1.42) not found on PATH" >&2; exit 2; }
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "specs compile (sleigh -l: no unresolved pattern conflicts)"
for s in ST70 ST72; do
	out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/$s.slaspec" 2>&1)
	if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo "FAILED: $s"; fail=1; else echo "$s compiles, no conflicts"; fi
done

step "decode: every asl form, then random words, round-tripped through asl"
python3 "$HERE/asm_forms.py" > "$W/forms.txt"
python3 "$HERE/asl_assemble.py" "$W/forms.txt" "$W/forms.asl" "$W/aslwd"
cut -f1 "$W/forms.asl" > "$W/forms.hex"
for l in ST7 ST72; do
	"$HERE/dis.sh" $l:BE:16:default "$W/forms.hex" "$W/forms.$l.gh"
	ok python3 "$HERE/cmp_asl.py" "$W/forms.asl" "$W/forms.$l.gh" "$l exhaustive forms"
	ok python3 "$HERE/rand_diff.py" "$W/rd" $l:BE:16:default "$N" 1
done

step "every constructor is reached"
python3 - "$W/all.txt" <<'PY'
import sys
with open(sys.argv[1], 'w') as f:
    for pre in ['', '90', '91', '92']:
        for op in range(256):
            f.write(f"{pre}{op:02x}112233\n")
PY
for l in ST7 ST72; do
	out=$("$HERE/every-entry.sh" $l:BE:16:default "$W/all.txt" "$W/ee.$l.txt")
	echo "$l: $out"
	grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }
done

step "p-code: hand-computed emulator cases"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"

step "p-code: random single instructions vs the manual model (and uCsim when available)"
for l in ST7 ST72; do ok python3 "$HERE/sem_diff.py" "$W/sd-$l" 20000 1 $l; done

if ((REAL)); then
	step "real firmware"
	ok "$HERE/real-check.sh" "$W/real"
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
