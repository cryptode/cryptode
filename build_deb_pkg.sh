#!/bin/sh

RVC_VERSION=0.9.0
RVC_TAR_NAME="rvc-${RVC_VERSION}.tar.gz"

# remove old dist targets
rm -rf "$RVC_TAR_NAME"

# make dist
./autogen.sh
./configure
make dist

# check if tar is exist
if [ ! -f "$RVC_TAR_NAME" ]; then
    echo "The tar file ${RVC_TAR_NAME} isn't exist"
    exit 1
fi

# copy tar.gz to /tmp directory
rm -rf /tmp/rvc
mkdir -p /tmp/rvc
mv "$RVC_TAR_NAME" /tmp/rvc/

# run dh-make
cd /tmp/rvc
bzr dh_make rvc "$RVC_VERSION" "$RVC_TAR_NAME"
cd rvc
rm -rf debian
cp -dPr platforms/debian .
cd debian/
bzr commit -m "rvc"
bzr builddeb -- -us -uc

exit 0
