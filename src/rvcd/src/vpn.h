#ifndef __RVCD_VPN_H__
#define __RVCD_VPN_H__

#define OVPN_BIN_PATH				"/usr/local/sbin/openvpn"
#define OVPN_MGM_PORT_START			6001

#define OVPN_MGM_CMD_STATE			"state\n"
#define OVPN_MGM_CMD_SIGTERM			"signal SIGTERM\n"

#define RVCD_OVPN_CONN_TIMEOUT			20
#define RVCD_OVPN_STOP_TIMEOUT			15

/* OpenVPN connection state */
enum OVPN_CONN_STATE {
	OVPN_STATE_CONNECTING = 0,
	OVPN_STATE_WAIT,
	OVPN_STATE_AUTH,
	OVPN_STATE_GETCONFIG,
	OVPN_STATE_ASSIGNIP,
	OVPN_STATE_ADDROUTES,
	OVPN_STATE_CONNECTED,
	OVPN_STATE_RECONNECTING,
	OVPN_STATE_EXITING,
	OVPN_STATE_DISCONNECTED,
	OVPN_STATE_UNKNOWN
};

/* VPN connection state */
enum RVCD_VPNCONN_STATE {
	RVCD_CONN_STATE_DISCONNECTED = 0,
	RVCD_CONN_STATE_CONNECTED,
	RVCD_CONN_STATE_CONNECTING,
	RVCD_CONN_STATE_DISCONNECTING
};

/* vpn connection structure */
struct rvcd_vpnconn {
	bool end_flag;

	enum RVCD_VPNCONN_STATE conn_state;
	struct rvcd_config_item *config_item;

	pid_t ovpn_pid;

	int ovpn_mgm_port;
	int ovpn_mgm_sock;

	pthread_t pt_conn;
};

/* rvcd VPN connection manager structure */
typedef struct rvcd_vpnconn_mgr {
	bool init_flag;
	bool end_flag;

	int vpn_conns_count;
	struct rvcd_vpnconn *vpn_conns;

	pthread_t pt_conn_mon;

	struct rvcd_ctx *c;
} rvcd_vpnconn_mgr_t;

/* rvcd VPN connection manager functions */
int rvcd_vpnconn_mgr_init(struct rvcd_ctx *c);
void rvcd_vpnconn_mgr_finalize(rvcd_vpnconn_mgr_t *vpnconn_mgr);

int rvcd_vpnconn_connect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);
int rvcd_vpnconn_disconnect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

#endif /* __RVCD_VPN_H__ */
