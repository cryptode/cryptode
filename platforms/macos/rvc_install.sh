#!/bin/bash

# check root
if [ "${UID}" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# check base directory is /usr/local/bin
BASEDIR=$(dirname "$0")

if [ "${BASEDIR}" == "/usr/local/bin" ]; then
	RVC_DATA_DIR="/usr/local"
else
	RVC_DATA_DIR="/tmp/rvc.dist"
fi

TARGET_PREFIX="/opt/rvc"
OPT_OPENVPN="/opt/openvpn"
RVD_PLIST_FILE="com.ribose.rvd.plist"
LAUNCHD="/Library/LaunchDaemons"

# install files
install -d -g wheel -m 755 -o root "${TARGET_PREFIX}/bin" "${TARGET_PREFIX}/etc/vpn.d" "${OPT_OPENVPN}/sbin"

install -m 500 -g wheel -o root "${RVC_DATA_DIR}/bin/rvd" "${TARGET_PREFIX}/bin"
install -m 555 -g wheel -o root "${RVC_DATA_DIR}/bin/rvc" "${TARGET_PREFIX}/bin"
install -m 500 -g wheel -o root "${RVC_DATA_DIR}/bin/dns_util.sh" "${TARGET_PREFIX}/bin"
install -m 600 -g wheel -o root "${RVC_DATA_DIR}/etc/rvd.json" "${TARGET_PREFIX}/etc"
install -m 500 -g wheel -o root "${RVC_DATA_DIR}/sbin/openvpn" "${OPT_OPENVPN}/sbin"

# unload rvd daemon
launchctl unload "${LAUNCHD}/${RVD_PLIST_FILE}" >/dev/null 2>&1

install -m 600 -g wheel -o root "${RVC_DATA_DIR}/var/plist/${RVD_PLIST_FILE}" "${LAUNCHD}"
launchctl load -w "${LAUNCHD}/${RVD_PLIST_FILE}"

exit 0
