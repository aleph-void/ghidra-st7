#!/usr/bin/env bash
# Real-code check: import the RabbitNet ST72264 firmware images headless with full auto-analysis,
# decompile every function, and compare the analysed listing with asl, uCsim and the ST linker's
# symbol files.
#
#   GHIDRA_INSTALL_DIR=... test/real-check.sh <workdir> [lang-id]
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
LANG_ID=${2:-ST7:BE:16:default}
"$HERE/fetch-samples.sh" "$W/samples" >/dev/null
rc=0
for n in rnadc rndac rndio rndisp rngpif; do
	P="$W/$n"
	python3 "$HERE/real/s19tobin.py" "$W/samples/$n.S19" "$P.bin"
	PROJ=$(mktemp -d "${TMPDIR:-/tmp}/st7-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$P.bin" -loader BinaryLoader \
		-loader-baseAddr 0 -processor "$LANG_ID" -scriptPath "$HERE" \
		-postScript RealCheck.java "$P" 60 -deleteProject >"$PROJ/log.txt" 2>&1 \
		|| { tail -40 "$PROJ/log.txt" >&2; rm -rf "$PROJ"; exit 1; }
	rm -rf "$PROJ"
	grep -v "^bookmark" "$P.summary"
	python3 "$HERE/real/real_compare.py" "$n" "$P.bin" "$P.dis" "$P.funcs" "$W/samples/$n.sym" "$W/cmp" || rc=1
done
exit $rc
