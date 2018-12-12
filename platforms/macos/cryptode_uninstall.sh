#!/bin/bash

# check root
if [ "${UID}" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

CRYPTODED_LAUNCHD_PLIST="/Library/LaunchDaemons/com.ribose.cryptoded.plist"

# unload cryptoded
launchctl unload "${CRYPTODED_LAUNCHD_PLIST}" >/dev/null 2>&1
rm -f "${CRYPTODED_LAUNCHD_PLIST}"

# remove log directory
rm -rf /var/log/cryptoded

# remove /opt/cryptode/bin and /opt/openvpn directory but keep /opt/cryptode/etc to preserve any .ovpn files
rm -rf /opt/cryptode/bin /opt/openvpn
