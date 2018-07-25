#ifndef __RVC_H__
#define __RVC_H__

#define RVC_DNS_UTIL_PATH				"/opt/rvc/bin/dns_util.sh"

/*
 * VPN profile type
 */

enum RVC_VPN_PROFILE_TYPE {
	RVC_VPN_PROFILE_OVPN = 0,		/* OpenVPN profile */
	RVC_VPN_PROFILE_TBLK			/* TunnelBlick profile */
};

/* rvc VPN connction options */
enum RVC_VPNCONN_OPTION {
	RVC_VPNCONN_OPT_AUTO_CONNECT,
	RVC_VPNCONN_OPT_PREEXEC_CMD,
	RVC_VPNCONN_OPT_PROFIEL,
#if 0
	RVC_VPNCONN_OPT_CERT,
	RVC_VPNCONN_OPT_KEYCHAIN,
#endif
	RVC_VPNCONN_OPT_UNKNOWN
};

/*
 * VPN connection status
 */

struct rvc_vpnconn_status {
	enum RVD_VPNCONN_STATE conn_state;
	bool auto_connect;
	char ovpn_profile_path[RVD_MAX_PATH];
	char pre_exec_cmd[RVD_MAX_CMD_LEN];
};

/** Try to connect to RVC VPN server
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

int rvc_connect(const char *name, int json_format, char **conn_status);

/** Try to disconnect from RVC VPN server
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

int rvc_disconnect(const char *name, int json_format, char **conn_status);

/** Try to reconnect to RVC VPN server
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

int rvc_reconnect(const char *name, int json_format, char **conn_status);

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

int rvc_get_status(const char *name, int json_format, char **conn_status);

/** Get the configuration directory
 *
 * @param [out] conf_dir buffer which keeps configuration directory
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_get_confdir(char **conf_dir);

/** Reload RVD VPN connections
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 * 
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_reload(void);

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

int rvc_import(int import_type, const char *import_path);

/*
 * Edit RVC VPN connection info
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 * 
 * @param [in] conn_name VPN connection name to be edited
 * @param [in] opt option for VPN connection info
 * @param [in] opt_val option value for VPN connection info
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_edit(const char *conn_name, enum RVC_VPNCONN_OPTION opt_type, const char *opt_val);


/** Remove RVD VPN connections
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @param [in] conn_name VPN connection name to be removed
 * @param [in] force if connection is in connected or pending status, then force removing
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_remove(const char *conn_name, int force);

/** Override DNS settings on the system
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @param [in] enabled flag for enable/disable DNS overriding
 * @param [in] dns_ip_list list of DNS server IP addresses separated by comma
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_dns_override(int enabled, const char *dns_ip_list);

/** Print the current DNS setting on the system
 *
 * This function requires sudo privilege, so it needs to gain root privilege before calling.
 *
 * @return 0 If success, otherwise non-zero will be returned.
 */

int rvc_dns_print(void);

#endif /* __RVC_H__ */
