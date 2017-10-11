#!/bin/bash

# check root
if [ "${UID}" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

RVD_LAUNCHD_PLIST="/Library/LaunchDaemons/com.ribose.rvd.plist"

# unload rvd
launchctl unload "${RVD_LAUNCHD_PLIST}" >/dev/null 2>&1
rm -f "${RVD_LAUNCHD_PLIST}"

# remove log directory
rm -rf /var/log/rvd

# remove /opt/rvc/bin and /opt/openvpn directory but keep /opt/rvc/etc to preserve any .ovpn files
rm -rf /opt/rvc/bin /opt/openvpn
