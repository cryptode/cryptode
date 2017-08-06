#ifndef __RVCD_VPN_H__
#define __RVCD_VPN_H__

#define OVPN_BIN_PATH				"/usr/local/sbin/openvpn"
#define OVPN_MGM_PORT_START			6001

#define OVPN_MGM_CMD_STATE			"state on\n"
#define OVPN_MGM_CMD_SIGTERM			"signal SIGTERM\n"
#define OVPN_MGM_CMD_BYTECOUNT			"bytecount 10\n"

#define OVPN_MGM_RESP_BYTECOUNT			">BYTECOUNT:"
#define OVPN_MGM_RESP_STATE			">STATE:"

#define RVCD_OVPN_CONN_TIMEOUT			20
#define RVCD_OVPN_STOP_TIMEOUT			15

/* OpenVPN connection state */
enum OVPN_CONN_STATE {
	OVPN_STATE_DISCONNECTED = 0,
	OVPN_STATE_CONNECTING,
	OVPN_STATE_WAIT,
	OVPN_STATE_AUTH,
	OVPN_STATE_GETCONFIG,
	OVPN_STATE_ASSIGNIP,
	OVPN_STATE_ADDROUTES,
	OVPN_STATE_CONNECTED,
	OVPN_STATE_RECONNECTING,
	OVPN_STATE_EXITING,
	OVPN_STATE_UNKNOWN
};

/* VPN connection state */
enum RVCD_VPNCONN_STATE {
	RVCD_CONN_STATE_DISCONNECTED = 0,
	RVCD_CONN_STATE_CONNECTED,
	RVCD_CONN_STATE_CONNECTING,
	RVCD_CONN_STATE_DISCONNECTING,
	RVCD_CONN_STATE_RECONNECTING,
};

/* vpn configuration structure */
struct rvcd_vpnconfig {
	char name[RVCD_MAX_CONN_NAME_LEN + 1];
	char ovpn_profile_path[RVCD_MAX_PATH];

	bool auto_connect;

	char up_script[RVCD_MAX_PATH];
	char down_script[RVCD_MAX_PATH];
};

/* vpn connection structure */
struct rvcd_vpnconn {
	bool end_flag;
	bool conn_cancel;

	struct rvcd_vpnconfig config;

	enum RVCD_VPNCONN_STATE conn_state;
	enum OVPN_CONN_STATE ovpn_state;

	time_t connected_tm;

	pid_t ovpn_pid;

	int ovpn_mgm_port;
	int ovpn_mgm_sock;
	fd_set fds;

	long total_bytes_in, total_bytes_out;
	long curr_bytes_in, curr_bytes_out;

	pthread_t pt_conn;
	pthread_t pt_conn_mon;

	struct rvcd_vpnconn *next;
	struct rvcd_vpnconn *prev;
};

/* rvcd VPN connection manager structure */
typedef struct rvcd_vpnconn_mgr {
	bool init_flag;
	bool end_flag;

	int vpn_conns_count;
	struct rvcd_vpnconn *vpn_conns;

	pthread_mutex_t conn_mt;

	struct rvcd_ctx *c;
} rvcd_vpnconn_mgr_t;

/* rvcd VPN connection manager functions */
int rvcd_vpnconn_mgr_init(struct rvcd_ctx *c);
void rvcd_vpnconn_mgr_finalize(rvcd_vpnconn_mgr_t *vpnconn_mgr);

void rvcd_vpnconn_connect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);
void rvcd_vpnconn_disconnect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void rvcd_vpnconn_getstatus(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name, char **state_jstr);

void rvcd_vpnconn_list_to_buffer(rvcd_vpnconn_mgr_t *vpnconn_mgr, bool json_format, char **buffer);
struct rvcd_vpnconn *rvcd_vpnconn_get_byname(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

#endif /* __RVCD_VPN_H__ */
