#!/bin/bash
#
# Copyright (c) 2017, [Ribose Inc](https://www.ribose.com)
#

PRI_IFACE=`echo 'show State:/Network/Global/IPv4' | scutil | grep PrimaryInterface | sed -e 's/.*PrimaryInterface : //'`
PRI_SERVICE=`echo 'show State:/Network/Global/IPv4' | scutil | grep PrimaryService | sed -e 's/.*PrimaryService : //'`

RVC_DNS_SETTING_KEY="com.ribose.rvd:/DNSSetting"
RVC_DNS_BACKUP_KEY="com.ribose.rvd:/DNSBackup"

# check root privilege
if ! [ $(id -u) = 0 ]; then
	echo "Please run as root privilege"
	exit 1
fi

# print help message
function print_help {
	echo "usage: dns_util.sh <options> [DNS server IP addresses]"
	echo "  options:"
	echo "    enable <DNS server IP addresses> override DNS settings. DNS server IP addresses are combined by comma"
	echo "    disable                          reset DNS settings to original"
	echo "    status                           show current DNS settings"
}

# check valid IP address
function is_valid_ipaddr() {
	local ip=$1
	local stat=1

	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		OIFS=$IFS
		IFS='.'
		ip=($ip)
		IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
			stat=$?
	fi

	return $stat
}

# check whether DNS was set by rvc
function check_dns_set_by_rvc() {
	echo "show Setup:/Network/Service/${PRI_SERVICE}/DNS" | scutil | grep RVC_DNS_SETTING >/dev/null
}

# backup original DNS settings
function backup_orig_dns_setting() {
	# check if DNS was set by rvc
	if check_dns_set_by_rvc; then
		echo "The DNS was already set by rvc"
		return
	fi

	scutil << _EOF
		d.init
		get Setup:/Network/Service/${PRI_SERVICE}/DNS
		set $RVC_DNS_BACKUP_KEY
_EOF
}

# set RVC DNS
function set_rvc_dns() {
	scutil << _EOF
		d.init
		get $RVC_DNS_SETTING_KEY
		set Setup:/Network/Service/${PRI_SERVICE}/DNS
_EOF
}

# enable RVC DNS settings
function enable_rvc_dns() {
	# backup original DNS setting for primary interface
	backup_orig_dns_setting

	# set rvc DNS settings
	set_rvc_dns
}

# disable RVC DNS settings
function disable_rvc_dns() {
	# check whether current DNS was set by rvc
	if check_dns_set_by_rvc; then
		scutil << _EOF
		d.init
		get $RVC_DNS_BACKUP_KEY
		set Setup:/Network/Service/${PRI_SERVICE}/DNS
_EOF
	else
		echo "The DNS isn't set by rvc."
	fi
}

# show status for DNS settings
function show_status() {
	# check whether current DNS was set by rvc
	if check_dns_set_by_rvc; then
		echo "The current system has DNS settings which set by rvc"
		Prefix="Setup"
	else
		echo "The current system doesn't have DNS settings which set by rvc"
		Prefix=State
	fi

	echo "##################################################################"
	echo "show $Prefix:/Network/Service/${PRI_SERVICE}/DNS" | scutil
	echo "##################################################################"
}

# check arguments
if [ "$1" = "enable" ]; then
	# check primary interface is exist
	if [[ "${PRI_IFACE}" == "" ]]; then
		echo "Error: Couldn't find the primary interface"
		exit 1
	fi

	# check whether DNS address has specified
	if [ "$#" -ne 2 ]; then
		print_help
		exit 1
	fi

	# split IP addresses by comma and check validaty of them
	for ip_addr in $(echo $2 | sed "s/,/ /g"); do
		is_valid_ipaddr $ip_addr
		if [ $? -ne 0 ]; then
			echo "Invalid IP address '$ip_addr'"
			exit 1
		fi

		if [ "$ip_addr_set" = "" ]; then
			ip_addr_set=$ip_addr
		else
			ip_addr_set=$ip_addr_set" "$ip_addr
		fi
	done

	# set directory for DNS setting
	scutil << _EOF
		d.init
		d.add ServerAddresses * $ip_addr_set
		d.add RVC_DNS_SETTING "true"

		set $RVC_DNS_SETTING_KEY
_EOF

	# set DNS for primary interface
	enable_rvc_dns
elif [ "$1" = "disable" ]; then
	# remove rvc DNS setting
	disable_rvc_dns
elif [ "$1" = "status" ]; then
	show_status
else
	print_help
	exit 1
fi
