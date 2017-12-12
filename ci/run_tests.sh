#!/bin/bash

set -eu

OS_TYPE=`uname`
if [ "$OS_TYPE" = "Darwin" ]; then
	RVC_INST_DIR="/opt/rvc/bin"
	RVD_INST_DIR="/opt/rvc/bin"
	OPENVPN_INSTALL_PATH="/usr/local/sbin/openvpn"
	INST_GRP_NAME="wheel"
	RVD_CONF_FILE="profile/rvd_osx_default.json"
	RVC_CONF_DIR="/opt/rvc/etc"
	RVC_OVPN_DIR="/opt/openvpn/sbin"

	sudo install -d -g "${INST_GRP_NAME}" -m 755 -o root "${RVC_INST_DIR}/bin" "${RVC_OVPN_DIR}/sbin"
	sudo install -m 500 -g "${INST_GRP_NAME}" -o root "${OPENVPN_INSTALL_PATH}" "${RVC_OVPN_DIR}/"
else
	RVC_INST_DIR="/usr/bin"
	RVD_INST_DIR="/usr/sbin"
	OPENVPN_INSTALL_PATH="/usr/sbin/openvpn"
	INST_GRP_NAME="root"
	RVD_CONF_FILE="profile/rvd_linux_default.json"
	RVC_CONF_DIR="/etc/rvc"
fi

# run openvpn server
function run_openvpn_server() {
	echo "Try to run openvpn server..."

	sudo ${OPENVPN_INSTALL_PATH} --config ci/profile/server.ovpn --dh ci/profile/dh.pem --daemon
	[ "$?" -eq 0 ] || echo $?
}

# install rvc
function install_rvd() {
	echo "Installing rvc components..."

	sudo install -d -g "${INST_GRP_NAME}" -m 755 -o root "${RVC_CONF_DIR}/vpn.d"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "etc/rvd.json" "${RVC_CONF_DIR}/"
	sudo install -m 500 -g "${INST_GRP_NAME}" -o root "src/rvc" "${RVC_INST_DIR}/"
	sudo install -m 555 -g "${INST_GRP_NAME}" -o root "src/rvd" "${RVD_INST_DIR}/"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "etc/rvd.json" "${RVC_CONF_DIR}/"
	sudo install -m 600 -g "${INST_GRP_NAME}" -o root "ci/${RVD_CONF_FILE}" "${RVC_CONF_DIR}/rvd.json"
}

run_openvpn_server
install_rvd
make check

exit 0
