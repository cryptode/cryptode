#!/bin/bash
set -eu

CHECKPATCH=$CHECKPATCH_INSTALL/checkpatch.pl

CHECKPATCH_FLAGS+=" --no-tree"
CHECKPATCH_FLAGS+=" --ignore COMPLEX_MACRO"
CHECKPATCH_FLAGS+=" --ignore TRAILING_SEMICOLON"
CHECKPATCH_FLAGS+=" --ignore LONG_LINE"
CHECKPATCH_FLAGS+=" --ignore LONG_LINE_STRING"
CHECKPATCH_FLAGS+=" --ignore LONG_LINE_COMMENT"
CHECKPATCH_FLAGS+=" --ignore SYMBOLIC_PERMS"
CHECKPATCH_FLAGS+=" --ignore NEW_TYPEDEFS"
CHECKPATCH_FLAGS+=" --ignore SPLIT_STRING"
CHECKPATCH_FLAGS+=" --ignore USE_FUNC"
CHECKPATCH_FLAGS+=" --ignore COMMIT_LOG_LONG_LINE"
CHECKPATCH_FLAGS+=" --ignore FILE_PATH_CHANGES"
CHECKPATCH_FLAGS+=" --ignore MISSING_SIGN_OFF"
CHECKPATCH_FLAGS+=" --ignore RETURN_PARENTHESES"
CHECKPATCH_FLAGS+=" --ignore STATIC_CONST_CHAR_ARRAY"
CHECKPATCH_FLAGS+=" --ignore ARRAY_SIZE"
CHECKPATCH_FLAGS+=" --ignore NAKED_SSCANF"
CHECKPATCH_FLAGS+=" --ignore SSCANF_TO_KSTRTO"
CHECKPATCH_FLAGS+=" --ignore EXECUTE_PERMISSIONS"
CHECKPATCH_FLAGS+=" --ignore MULTISTATEMENT_MACRO_USE_DO_WHILE"
CHECKPATCH_FLAGS+=" --ignore STORAGE_CLASS"

# checkpatch.pl will ignore the following paths
CHECKPATCH_IGNORE+=" checkpatch.pl.patch Makefile test/Makefile test/http.redirect/hello.txt"
CHECKPATCH_EXCLUDE=$(for p in $CHECKPATCH_IGNORE; do echo ":(exclude)$p" ; done)

function _checkpatch() {
		$CHECKPATCH $CHECKPATCH_FLAGS --no-tree -
}

function checkpatch() {
		git show --oneline --no-patch $1
		git format-patch -1 $1 --stdout -- $CHECKPATCH_EXCLUDE . | _checkpatch
}

get_os() {
	if [ -z $OSTYPE ]; then
		echo "$(uname | tr '[:upper:]' '[:lower:]')"
	else
		echo "$(echo $OSTYPE | tr '[:upper:]' '[:lower:]')"
	fi
}

macos_build() {
	readonly OPENSSL_DIR="$(brew --prefix openssl)"
	if [ ! -d "${OPENSSL_DIR}" ]; then
		echo "Couldn't find OpenSSL installation directory. (Hint: 'brew install openssl')"
		exit 1
	fi

	sh autogen.sh && \
		./configure \
			--disable-silent-rules \
			--enable-tests \
			--with-openssl=${OPENSSL_DIR} && \
		make clean && \
		make
}

linux_build() {
	sh autogen.sh && \
		./configure \
			--disable-silent-rules \
			--enable-tests && \
		make clean && \
		make
}

main() {
	case $(get_os) in
		darwin*)
			macos_build ;;
		linux*)
			linux_build ;;
		*) echo "unknown"; exit 1 ;;
	esac
}

main

# checkpatch
if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
	checkpatch HEAD
else
	for c in $(git rev-list HEAD^1..HEAD^2); do
		checkpatch $c
	done
fi

# run openvpn server
./ci/run_tests.sh
