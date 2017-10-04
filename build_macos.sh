#!/bin/sh

# check whether openssl was installed on mac
OPENSSL_DIR=$(brew --prefix openssl)
if [ -z "$OPENSSL_DIR" ]; then
	echo "Couldn't find openssl installation directory. Try to run 'brew install openssl'"
	exit 1
fi

# try to compile rvc on mac
./autogen.sh
./configure --with-openssl=$OPENSSL_DIR
make
