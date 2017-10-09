#!/bin/bash

# check root
if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# check base directory is /usr/local/bin
BASEDIR=$(dirname "$0")

if [ "$BASEDIR" == "/usr/local/bin" ]; then
	RVC_DATA_DIR=/usr/local
else
	RVC_DATA_DIR=/tmp/rvc.dist
fi

TARGET_PREFIX=/opt/rvc
OPT_OPENVPN=/opt/openvpn

RVD_PLIST_FILE=com.ribose.rvd.plist

# rvd and rvc requires to be installed in `/opt`
mkdir -m 755 -p $TARGET_PREFIX/bin $OPT_OPENVPN/sbin
mkdir -m 755 -p $TARGET_PREFIX/etc/vpn.d

chown -R root:wheel $TARGET_PREFIX $OPT_OPENVPN

install -m 500 -g wheel -o root $RVC_DATA_DIR/bin/rvd $TARGET_PREFIX/bin
install -m 555 -g wheel -o root $RVC_DATA_DIR/bin/rvc $TARGET_PREFIX/bin
install -m 500 -g wheel -o root $RVC_DATA_DIR/bin/dns_util.sh $TARGET_PREFIX/bin
install -m 600 -g wheel -o root $RVC_DATA_DIR/etc/rvd.json $TARGET_PREFIX/etc
install -m 500 -g wheel -o root $RVC_DATA_DIR/sbin/openvpn $OPT_OPENVPN/sbin

# ensure that `/opt/rvc/bin` is in your PATH and is set before `/usr/local/bin`. E.g.:
#PATH=/opt/rvc/bin:$PATH

install -m 600 -g wheel -o root "$RVC_DATA_DIR/var/plist/$RVD_PLIST_FILE" /Library/LaunchDaemons
launchctl load -w "/Library/LaunchDaemons/$RVD_PLIST_FILE"

exit 0
