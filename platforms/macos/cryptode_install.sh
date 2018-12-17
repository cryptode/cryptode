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
	CRYPTODE_DATA_DIR="/usr/local"
else
	CRYPTODE_DATA_DIR="/tmp/cryptode.dist"
	BUILD_PACKAGE=1
fi

TARGET_PREFIX="/opt/cryptode"
OPT_OPENVPN="/opt/openvpn"
CRYPTODED_PLIST_NAME="com.ribose.cryptoded.plist"
LAUNCHD="/Library/LaunchDaemons"

# install files
install -d -g wheel -m 755 -o root "${TARGET_PREFIX}/bin" "${TARGET_PREFIX}/etc/vpn.d" "${OPT_OPENVPN}/sbin"

install -m 500 -g wheel -o root "${CRYPTODE_DATA_DIR}/bin/cryptoded" "${TARGET_PREFIX}/bin"
install -m 555 -g wheel -o root "${CRYPTODE_DATA_DIR}/bin/cryptode" "${TARGET_PREFIX}/bin"
install -m 500 -g wheel -o root "${CRYPTODE_DATA_DIR}/bin/dns_util.sh" "${TARGET_PREFIX}/bin"
install -m 600 -g wheel -o root "${CRYPTODE_DATA_DIR}/etc/cryptoded.conf" "${TARGET_PREFIX}/etc"

# set the 'user_id' for 'pre-connect-exec' to the UID of the desktop user
sed -i "" "s/CRYPTODE_USER_ID/${SUDO_UID}/g" "${TARGET_PREFIX}/etc/cryptoded.conf"
install -m 500 -g wheel -o root "${CRYPTODE_DATA_DIR}/sbin/openvpn" "${OPT_OPENVPN}/sbin"

# unload cryptoded daemon
launchctl unload "${LAUNCHD}/${CRYPTODED_PLIST_FILE}" >/dev/null 2>&1

# check if cryptode was installed with brew
if [ "$BUILD_PACKAGE" -eq 1 ]; then
	CRYPTODED_PLIST_FILE="${CRYPTODE_DATA_DIR}/var/plist/${CRYPTODED_PLIST_NAME}"
else
	readonly CRYPTODE_BREW_DIR="$(brew --prefix cryptode)"
	if [ -d ${CRYPTODE_BREW_DIR} ]; then
		CRYPTODED_PLIST_FILE="${CRYPTODE_BREW_DIR}/var/plist/${CRYPTODED_PLIST_NAME}"
	else
		CRYPTODED_PLIST_FILE="${CRYPTODE_DATA_DIR}/var/plist/${CRYPTODED_PLIST_NAME}"
	fi
fi

install -m 600 -g wheel -o root "${CRYPTODED_PLIST_FILE}" "${LAUNCHD}"
launchctl load -w "${LAUNCHD}/${CRYPTODED_PLIST_NAME}"

# This is to ensure you will always use the correct cryptode that is living in /opt/cryptode/bin
rm -f /usr/local/bin/cryptode /usr/local/bin/cryptoded

exit 0
