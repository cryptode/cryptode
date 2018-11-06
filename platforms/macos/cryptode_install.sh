#!/bin/bash

# check root
if [ "${UID}" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# check if executed with sudo
if [ ! "${SUDO_UID}" ]; then
	echo "Please execute with sudo"
	exit 1
fi

# check base directory is /usr/local/bin
BASEDIR=$(dirname "$0")
BUILD_PACKAGE=0

if [ "${BASEDIR}" == "/usr/local/bin" ]; then
	RVC_DATA_DIR="/usr/local"
else
	RVC_DATA_DIR="/tmp/rvc.dist"
	BUILD_PACKAGE=1
fi

TARGET_PREFIX="/opt/rvc"
OPT_OPENVPN="/opt/openvpn"
RVD_PLIST_NAME="com.ribose.rvd.plist"
LAUNCHD="/Library/LaunchDaemons"

# install files
install -d -g wheel -m 755 -o root "${TARGET_PREFIX}/bin" "${TARGET_PREFIX}/etc/vpn.d" "${OPT_OPENVPN}/sbin"

install -m 500 -g wheel -o root "${RVC_DATA_DIR}/bin/rvd" "${TARGET_PREFIX}/bin"
install -m 555 -g wheel -o root "${RVC_DATA_DIR}/bin/rvc" "${TARGET_PREFIX}/bin"
install -m 500 -g wheel -o root "${RVC_DATA_DIR}/bin/dns_util.sh" "${TARGET_PREFIX}/bin"
install -m 600 -g wheel -o root "${RVC_DATA_DIR}/etc/rvd.conf" "${TARGET_PREFIX}/etc"

# set the 'user_id' for 'pre-connect-exec' to the UID of the desktop user
sed -i "" "s/RVC_USER_ID/${SUDO_UID}/g" "${TARGET_PREFIX}/etc/rvd.conf"
install -m 500 -g wheel -o root "${RVC_DATA_DIR}/sbin/openvpn" "${OPT_OPENVPN}/sbin"

# unload rvd daemon
launchctl unload "${LAUNCHD}/${RVD_PLIST_FILE}" >/dev/null 2>&1

# check if rvc was installed with brew
if [ "$BUILD_PACKAGE" -eq 1 ]; then
	RVD_PLIST_FILE="${RVC_DATA_DIR}/var/plist/${RVD_PLIST_NAME}"
else
	readonly RVC_BREW_DIR="$(brew --prefix rvc)"
	if [ -d ${RVC_BREW_DIR} ]; then
		RVD_PLIST_FILE="${RVC_BREW_DIR}/var/plist/${RVD_PLIST_NAME}"
	else
		RVD_PLIST_FILE="${RVC_DATA_DIR}/var/plist/${RVD_PLIST_NAME}"
	fi
fi

install -m 600 -g wheel -o root "${RVD_PLIST_FILE}" "${LAUNCHD}"
launchctl load -w "${LAUNCHD}/${RVD_PLIST_NAME}"

# This is to ensure you will always use the correct rvc that is living in /opt/rvc/bin
rm -f /usr/local/bin/rvc /usr/local/bin/rvd

exit 0
