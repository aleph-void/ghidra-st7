#!/usr/bin/env bash
# Compile the module's Java part (the analyzers) into lib/ST7.jar, for a development install where
# the module directory is symlinked into Ghidra/Processors. (gradle buildExtension does the same for
# release zips.) JAVA_HOME must have javac (JDK 21 or later).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
MOD=$(cd "$(dirname "$0")/.." && pwd)
JAVAC=javac JAR=jar
[[ -n ${JAVA_HOME:-} ]] && JAVAC=$JAVA_HOME/bin/javac JAR=$JAVA_HOME/bin/jar
CLS=$(mktemp -d "${TMPDIR:-/tmp}/st7-cls.XXXXXX")
trap 'rm -rf "$CLS"' EXIT
CP=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" "$GHIDRA_INSTALL_DIR/Ghidra/Features/Base" \
	-path '*/lib/*.jar' ! -name '*-src*' | tr '\n' ':')
"$JAVAC" -nowarn --release 21 -cp "$CP" -d "$CLS" $(find "$MOD/src/main/java" -name '*.java')
mkdir -p "$MOD/lib"
"$JAR" cf "$MOD/lib/ST7.jar.new" -C "$CLS" .
mv "$MOD/lib/ST7.jar.new" "$MOD/lib/ST7.jar"
echo "built $MOD/lib/ST7.jar"
