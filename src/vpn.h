#ifndef __RVD_VPN_H__
#define __RVD_VPN_H__

#define OVPN_MGM_PORT_START				6001

#define OVPN_MGM_CMD_STATE				"state on\n"
#define OVPN_MGM_CMD_SIGTERM			"signal SIGTERM\n"
#define OVPN_MGM_CMD_BYTECOUNT			"bytecount 10\n"

#define OVPN_MGM_RESP_BYTECOUNT			">BYTECOUNT:"
#define OVPN_MGM_RESP_STATE				">STATE:"

#define OVPN_MAX_LOG_FSIZE				32 * 1024 * 1024

#define OVPN_CONN_RETRY_TIMEOUT_MIN		"5"
#define OVPN_CONN_RETRY_TIMEOUT_MAX		"30"

#define RVD_OVPN_CONN_TIMEOUT			10
#define RVD_OVPN_STOP_TIMEOUT			10
#define RVD_PRE_EXEC_TIMEOUT			60

#define OVPN_CONFIG_EXTENSION			".ovpn"
#define RVC_CONFIG_EXTENSION			".json"

struct rvd_vpnconn_mgr;

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

/* vpn configuration structure */
struct rvd_vpnconfig {
	char name[RVD_MAX_CONN_NAME_LEN + 1];
	char ovpn_profile_path[RVD_MAX_PATH];

	bool auto_connect;

	uid_t pre_exec_uid;
	char pre_exec_cmd[512];

	int pre_exec_status;
};

/* vpn connection structure */
struct rvd_vpnconn {
	bool end_flag;
	bool conn_cancel;

	struct rvd_vpnconfig config;

	enum RVD_VPNCONN_STATE conn_state;
	enum OVPN_CONN_STATE ovpn_state;

	time_t connected_tm;

	pid_t ovpn_pid;
	bool enable_script_sec;

	int ovpn_mgm_port;
	int ovpn_mgm_sock;
	fd_set fds;

	long total_bytes_in, total_bytes_out;
	long curr_bytes_in, curr_bytes_out;

	pthread_t pt_conn;
	pthread_t pt_conn_mon;

	struct rvd_vpnconn_mgr *vpnconn_mgr;

	struct rvd_vpnconn *next;
	struct rvd_vpnconn *prev;
};

/* rvd VPN connection manager structure */
typedef struct rvd_vpnconn_mgr {
	bool init_flag;
	bool end_flag;

	int vpn_conns_count;
	struct rvd_vpnconn *vpn_conns;

	pthread_mutex_t conn_mt;

	struct rvd_ctx *c;
} rvd_vpnconn_mgr_t;

/* rvd VPN connection manager functions */
int rvd_vpnconn_mgr_init(struct rvd_ctx *c);
void rvd_vpnconn_mgr_finalize(rvd_vpnconn_mgr_t *vpnconn_mgr);

void rvd_vpnconn_connect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);
void rvd_vpnconn_disconnect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void rvd_vpnconn_getstatus(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name, bool json_format, char **state_jstr);

struct rvd_vpnconn *rvd_vpnconn_get_byname(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void rvd_vpnconn_enable_script_sec(rvd_vpnconn_mgr_t *vpnconn_mgr, bool enable_script_security);

#endif /* __RVD_VPN_H__ */
