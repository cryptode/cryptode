#!/bin/bash

# export variables
CRYPTODE_BUILD_PKG=1
PLATFORM_DIR="$PWD/platforms/macos"
PKGBUILD_DIR="$PLATFORM_DIR/cryptode.dist"

# remove old dist directories
rm -r "$PKGBUILD_DIR" >/dev/null 2&>1

# run build script
. build_macos.sh
make install

# copy cryptode_install.sh binary to dist directory
mkdir -p "$PLATFORM_DIR/scripts"
install -c "$PLATFORM_DIR/cryptode_install.sh" "$PLATFORM_DIR/scripts/postinstall"

# install openvpn binary to pakage build directory
mkdir -p "$PKGBUILD_DIR/sbin"
install -c "$OPENVPN_DIR/sbin/openvpn" "$PKGBUILD_DIR/sbin"

# build package
pkgbuild \
	--root "$PKGBUILD_DIR" \
	--identifier com.ribose.cryptode \
	--install-location /tmp/cryptode.dist \
	--scripts "$PLATFORM_DIR/scripts" \
	"$PLATFORM_DIR/cryptode.pkg"

rm -r "$PKGBUILD_DIR"
rm -r "$PLATFORM_DIR/scripts"
