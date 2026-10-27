#!/usr/bin/env bash
# Fetch the real-code samples used by test/real-check.sh into <dir> (never committed).
#
# RabbitNet ST7 microcode: five ST72264 firmware images (S-record), their sources and the ST linker
# symbol files, from Digi International's Dynamic C 9 open-source release
# (https://github.com/digidotcom/DCRabbit_9, "RabbitNet HW/ST7microcode", Mozilla Public License 2.0).
#
#   test/fetch-samples.sh <dir>
set -euo pipefail
DIR=$(mkdir -p "$1" && cd "$1" && pwd)
SHA=c455732cc2ed0a7590efc34c797aa92655d491de
BASE="https://raw.githubusercontent.com/digidotcom/DCRabbit_9/$SHA/RabbitNet%20HW/ST7microcode"
fetch() {   # <url path> <file> <sha256>
	if [[ ! -f $DIR/$2 ]] || [[ $(sha256sum "$DIR/$2" | cut -d' ' -f1) != "$3" ]]; then
		curl -fsSL "$BASE/$1" -o "$DIR/$2"
	fi
	[[ $(sha256sum "$DIR/$2" | cut -d' ' -f1) == "$3" ]] || { echo "checksum mismatch: $2" >&2; exit 1; }
}
fetch ADC/rnadc.S19 rnadc.S19 a655d188b62892e360cf62224ceaf3f9c14b002e6534fd13382807b0ef0ba7e6
fetch ADC/rnadc.sym rnadc.sym f0e297cc879aec63ee390cd6d134b1554825900f65cea89e2e3b6a1a5e63aa0f
fetch DAC/rndac.S19 rndac.S19 6bcc2af21941bd9a680ff54e0d7040b28fb652a222b076801d4975ae8c036096
fetch DAC/rndac.sym rndac.sym f223f4cf974c41ad1e82f1dd4d27e711c366c07d779d3787a2dfd68e864c0228
fetch rndio/rndio.S19 rndio.S19 f84c2763919418d1cdbd4530f728382cc1875fab37d55d1a14abcf6424d5c9f7
fetch rndio/rndio.sym rndio.sym e8594ef5be23a52a24d626be4a98fb99db27a1ed1639443348ff6e77898500e4
fetch Rndisp/rndisp.S19 rndisp.S19 a7dd4df964bff36c36e26c74b07be55320abf71dbfbf8bbe4067b094166573b9
fetch Rndisp/rndisp.sym rndisp.sym 84e8307f7024bf5f5ebe81fb2213e503c0d858e44f83e589668548ce9839493f
fetch RNIF/rngpif.S19 rngpif.S19 38877db2b9d2269e03536fa43fbe5fd8654b56c2083bca0a28be99b7c0c080b8
fetch RNIF/rngpif.sym rngpif.sym 2f2bc0d48d384ad17a73e14555d091cc83fe401b934d1b16451e317edd26f62d
echo "fetched into $DIR"
