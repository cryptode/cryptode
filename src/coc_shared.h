/*
 * Copyright (c) 2017, [Ribose Inc](https://www.cryptode.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COC_H__
#define __COC_H__

#define COC_DNS_UTIL_PATH				"/opt/cryptode/bin/dns_util.sh"

/*
 * VPN profile type
 */

enum COC_VPN_PROFILE_TYPE {
	COC_VPN_PROFILE_OVPN = 0,		/* OpenVPN profile */
	COC_VPN_PROFILE_TBLK			/* TunnelBlick profile */
};

/* cryptode VPN connction options */
enum COC_VPNCONN_OPTION {
	COC_VPNCONN_OPT_AUTO_CONNECT,
	COC_VPNCONN_OPT_PREEXEC_CMD,
	COC_VPNCONN_OPT_PROFIEL,
#if 0
	COC_VPNCONN_OPT_CERT,
	COC_VPNCONN_OPT_KEYCHAIN,
#endif
	COC_VPNCONN_OPT_UNKNOWN
};

/*
 * VPN connection status
 */

struct coc_vpnconn_status {
	enum COD_VPNCONN_STATE conn_state;
	bool auto_connect;
	char ovpn_profile_path[COD_MAX_PATH];
	char pre_exec_cmd[COD_MAX_CMD_LEN];
};

/** Try to connect to COC VPN server
 *
 * The JSON buffer to be returned may have two types, single or array JSON buffer
 * by connection name.
 * 
 * Note that the allocated memory for connection status should be freed
 * after used.
 * 
 * @param [in] name 'all' or VPN connection name to be connected
 * @param [in] json_format set output format
 * @param [out] conn_status JSON buffer which keeps connection status
 *			    for given connection name.
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_connect(const char *name, int json_format, char **conn_status);

/** Try to disconnect from COC VPN server
 *
 * The JSON buffer to be returned may have two types, single or array JSON buffer
 * by connection name.
 * 
 * Note that the allocated memory for connection status should be freed
 * after used.
 * 
 * @param [in] name 'all' or VPN connection name to be disconnected
 * @param [in] json_format set output format
 * @param [out] conn_status buffer which keeps connection status for given connection name.
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_disconnect(const char *name, int json_format, char **conn_status);

/** Try to reconnect to COC VPN server
 *
 * The JSON buffer to be returned may have two types, single or array JSON buffer
 * by connection name.
 *
 * Note that the allocated memory for connection status should be freed
 * after used.
 *
 * @param [in] name 'all' or VPN connection name to be reconnected
 * @param [in] json_format set output format
 * @param [out] conn_status JSON buffer which keeps connection status
 *			    for given connection name.
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_reconnect(const char *name, int json_format, char **conn_status);

/** Get connection status
 *
 * The JSON buffer to be returned may have two types, single or array JSON buffer
 * by connection name.
 * 
 * Note that the allocated memory for connection status should be freed
 * after used.
 * 
 * @param [in] name 'all' or VPN connection name to be disconnected
 * @param [in] json_format set output format
 * @param [out] conn_status buffer which keeps connection status for given connection name.
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_get_status(const char *name, int json_format, char **conn_status);

/** Get the configuration directory
 *
 * @param [out] conf_dir buffer which keeps configuration directory
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_get_confdir(char **conf_dir);

/** Reload COD VPN connections
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 * 
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_reload(void);

/** Import OpenVPN or TunnelBlick VPN profile
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 * After imported VPN profiles, then this function will reload VPN connections automatically.
 *
 * @param [in] import_type type of VPN profile to be imported.
 * @param [in] import_path path of VPN profile to be imported.
 * 
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_import(int import_type, const char *import_path);

/*
 * Edit COC VPN connection info
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 * 
 * @param [in] conn_name VPN connection name to be edited
 * @param [in] opt option for VPN connection info
 * @param [in] opt_val option value for VPN connection info
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_edit(const char *conn_name, enum COC_VPNCONN_OPTION opt_type, const char *opt_val);


/** Remove COD VPN connections
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @param [in] conn_name VPN connection name to be removed
 * @param [in] force if connection is in connected or pending status, then force removing
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_remove(const char *conn_name, int force);

/** Override DNS settings on the system
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @param [in] enabled flag for enable/disable DNS overriding
 * @param [in] dns_ip_list list of DNS server IP addresses separated by comma
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_dns_override(int enabled, const char *dns_ip_list);

/** Print the current DNS setting on the system
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @return 0 If success, otherwise non-zero will be returned.
 */

int coc_dns_print(void);

#endif /* __COC_H__ */
