#!/bin/bash

PLATFORM_DIR="$PWD/platforms/osx"
PKGBUILD_DIR="$PLATFORM_DIR/rvc.dist"

# remove old dist directory
rm -r "$PKGBUILD_DIR"

# install dependencies
brew install openssl json-c

# get openssl installation directory
OPENSSL_DIR=$(brew --prefix openssl)

# compile and install binaries
./autogen.sh
./configure --prefix="$PKGBUILD_DIR" --sysconfdir='${prefix}/etc' --with-openssl=$OPENSSL_DIR
make
make install

# build package
pkgbuild \
	--root "$PKGBUILD_DIR" \
	--identifier com.ribose.rvc \
	--install-location /opt/rvc.dist \
	--scripts "$PLATFORM_DIR/scripts" \
	"$PLATFORM_DIR/rvc.pkg"
