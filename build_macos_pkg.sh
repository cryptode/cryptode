#!/bin/bash

PLATFORM_DIR="$PWD/platforms/macos"
PKGBUILD_DIR="$PLATFORM_DIR/rvc.dist"

readonly brew="/usr/local/bin/brew"
if [ ! -x "${brew}" ]; then
	echo "Couldn't execute '${brew}'. (Hint: install Homebrew 'https://brew.sh/')"
	exit 1
fi

readonly OPENVPN_DIR="$(${brew} --prefix openvpn)"

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

# copy openvpn binrary to dist directory
install -c $OPENVPN_DIR/sbin/openvpn $PKGBUILD_DIR/sbin

# build package
pkgbuild \
	--root "$PKGBUILD_DIR" \
	--identifier com.ribose.rvc \
	--install-location /tmp/rvc.dist \
	--scripts "$PLATFORM_DIR/scripts" \
	"$PLATFORM_DIR/rvc.pkg"
