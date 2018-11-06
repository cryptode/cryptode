#!/bin/bash

set -eu

OS_TYPE=`uname`
if [ "$OS_TYPE" = "Darwin" ]; then
	CRYPTODE_INST_DIR="/opt/cryptode/bin"
	CRYPTODED_INST_DIR="/opt/cryptode/bin"
	OPENVPN_INSTALL_PATH="/usr/local/sbin/openvpn"
	INST_GRP_NAME="wheel"
	CRYPTODED_CONF_FILE="profile/cryptoded_osx_default.conf"
	CRYPTODE_CONF_DIR="/opt/cryptode/etc"
	CRYPTODE_OVPN_DIR="/opt/openvpn/sbin"

	sudo install -d -g "${INST_GRP_NAME}" -m 755 -o root "${CRYPTODE_INST_DIR}/bin" "${CRYPTODE_OVPN_DIR}/sbin"
	sudo install -m 500 -g "${INST_GRP_NAME}" -o root "${OPENVPN_INSTALL_PATH}" "${CRYPTODE_OVPN_DIR}/"
else
	CRYPTODE_INST_DIR="/usr/bin"
	CRYPTODED_INST_DIR="/usr/sbin"
	OPENVPN_INSTALL_PATH="/usr/sbin/openvpn"
	INST_GRP_NAME="root"
	CRYPTODED_CONF_FILE="profile/cryptoded_linux_default.conf"
	CRYPTODE_CONF_DIR="/etc/cryptode"
fi

# run openvpn server
function run_openvpn_server() {
	echo "Try to run openvpn server..."

	sudo ${OPENVPN_INSTALL_PATH} --config ci/profile/server.ovpn --dh ci/profile/dh.pem --daemon
	[ "$?" -eq 0 ] || echo $?
}

# install cryptode
function install_cryptoded() {
	echo "Installing cryptode components..."

	sudo install -d -g "${INST_GRP_NAME}" -m 755 -o root "${CRYPTODE_CONF_DIR}/vpn.d"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "etc/cryptoded.conf" "${CRYPTODE_CONF_DIR}/"
	sudo install -m 500 -g "${INST_GRP_NAME}" -o root "src/cryptode" "${CRYPTODE_INST_DIR}/"
	sudo install -m 555 -g "${INST_GRP_NAME}" -o root "src/cryptoded" "${CRYPTODED_INST_DIR}/"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "etc/cryptoded.conf" "${CRYPTODE_CONF_DIR}/"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "ci/${CRYPTODED_CONF_FILE}" "${CRYPTODE_CONF_DIR}/cryptoded.conf"
}

run_openvpn_server
install_cryptoded
make check

exit 0
