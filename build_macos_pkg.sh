#!/bin/bash

# export variables
RVC_BUILD_PKG=1
PLATFORM_DIR="$PWD/platforms/macos"
PKGBUILD_DIR="$PLATFORM_DIR/rvc.dist"

# remove old dist directorys
rm -r "$PKGBUILD_DIR"

# run build script
. build_macos.sh

# install binaries
make install

# copy openvpn binrary to dist directory
install -c "$OPENVPN_DIR/sbin/openvpn" "$PKGBUILD_DIR/sbin"

# build package
pkgbuild \
	--root "$PKGBUILD_DIR" \
	--identifier com.ribose.rvc \
	--install-location /tmp/rvc.dist \
	--scripts "$PLATFORM_DIR/scripts" \
	"$PLATFORM_DIR/rvc.pkg"
