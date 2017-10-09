#!/bin/bash

# check if brew is installed
readonly brew="/usr/local/bin/brew"
if [ ! -x "${brew}" ]; then
	echo "Couldn't execute '${brew}'. (Hint: install Homebrew 'https://brew.sh/')"
	exit 1
fi

# check if json-c is installed
readonly JSONC_DIR="$(${brew} --prefix json-c)"
if [ ! -d "${JSONC_DIR}" ]; then
	echo "Couldn't find json-c installation directory. (Hint: 'brew install json-c')"
	exit 1
fi

# check if OpenSSL is installed
readonly OPENSSL_DIR="$(${brew} --prefix openssl)"
if [ ! -d "${OPENSSL_DIR}" ]; then
	echo "Couldn't find OpenSSL installation directory. (Hint: 'brew install openssl')"
	exit 1
fi

# check if OpenVPN is installed when build the package
export OPENVPN_DIR="$(${brew} --prefix openvpn)"
if [ ! -d "${OPENVPN_DIR}" ]; then
	echo "Couldn't find OpenVPN installation directory. (Hint: 'brew install openvpn')"
	exit 1
fi

# compile project
echo "running './autogen.sh':"
./autogen.sh

if [ -z "$RVC_BUILD_PKG" ]; then
	./configure --with-openssl="${OPENSSL_DIR}"
else
	./configure --prefix="$PKGBUILD_DIR" --sysconfdir='${prefix}/etc' --with-openssl="$OPENSSL_DIR"
fi

echo "running 'make':"
make
