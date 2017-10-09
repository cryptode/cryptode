#!/bin/sh

RVD_LAUNCHD_PLIST=/Library/LaunchDaemons/com.ribose.rvd.plist

# check root
if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# unload rvd daemon
launchctl unload "$RVD_LAUNCHD_PLIST" >/dev/null 2&>1
rm -f "$RVD_LAUNCHD_PLIST"

# remove log directory
rm -rf /var/log/rvd

# remove /opt/rvc, /opt/openvpn directory
rm -rf /opt/rvc
rm -rf /opt/openvpn
