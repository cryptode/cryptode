#!/bin/sh
set -ex

get_os() {
	if [ -z $OSTYPE ]; then
		echo "$(uname | tr '[:upper:]' '[:lower:]')"
	else
		echo "$(echo $OSTYPE | tr '[:upper:]' '[:lower:]')"
	fi
}

macos_install() {
	brew update
	packages="
		make
		autoconf
		automake
		libtool
		openssl
		json-c
		pkg-config
	"
	for p in ${packages}; do
		brew install ${p} || brew upgrade ${p}
	done
}

linux_install() {
	sudo apt-get update
	packages="
		make
		autoconf
		automake
		libtool
		cmake
		libssl-dev
		libjson-c-dev
		pkg-config
	"
	for p in ${packages}; do
		sudo apt-get install -y ${p}
	done

	# install libnereon
	git clone https://github.com/riboseinc/libnereon
	cd libnereon
	mkdir build
	cd build
	cmake ..
	make; make install
}

crossplat_install() {
	echo ""
}

main() {
	case $(get_os) in
		darwin*)
			macos_install ;;
		linux*)
			linux_install ;;
		*) echo "unknown"; exit 1 ;;
	esac

	crossplat_install
}

main
