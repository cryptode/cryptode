#!/bin/bash
set -x
set -eu

SPWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CORES="2" && [ -r /proc/cpuinfo ] && CORES=$(grep -c '^$' /proc/cpuinfo)

# checkpatch.pl
if [ ! -e "${CHECKPATCH_INSTALL}/checkpatch.pl" ]; then
	mkdir -p ${CHECKPATCH_INSTALL}
	cd ${CHECKPATCH_INSTALL}
	wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl
	chmod a+x checkpatch.pl
	wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/spelling.txt
	patch -p0 < $SPWD/checkpatch.pl.patch
	echo "invalid.struct.name" > const_structs.checkpatch
fi
