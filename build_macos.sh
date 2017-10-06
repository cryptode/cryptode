#!/bin/bash

readonly brew="/usr/local/bin/brew"
if [ ! -x "${brew}" ]; then
	echo "Couldn't execute '${brew}'. (Hint: install Homebrew 'https://brew.sh/')"
	exit 1
fi

# check if OpenSSL is installed
readonly OPENSSL_DIR="$(${brew} --prefix openssl)"
if [ -z "${OPENSSL_DIR}" ]; then
	echo "Couldn't find OpenSSL installation directory. (Hint: 'brew install openssl')"
	exit 1
fi

./autogen.sh
./configure --with-openssl="${OPENSSL_DIR}"
make
