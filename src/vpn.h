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

#ifndef __COD_VPN_H__
#define __COD_VPN_H__

#define OVPN_MGM_PORT_START                  6001

#define OVPN_MGM_CMD_NOTIFY                 "state on\nbytecount 10\n"
#define OVPN_MGM_CMD_SIGTERM                "signal SIGTERM\n"

#define OVPN_MGM_RESP_BYTECOUNT             ">BYTECOUNT:"
#define OVPN_MGM_RESP_STATE                 ">STATE:"
#define OVPN_MGM_RESP_REMOTE                ">REMOTE:"

#define OVPN_MAX_LOG_FSIZE                  32 * 1024 * 1024

#define OVPN_CONN_RETRY_TIMEOUT_MIN         "5"
#define OVPN_CONN_RETRY_TIMEOUT_MAX         "30"

#define COD_OVPN_CONN_TIMEOUT               10
#define COD_OVPN_STOP_TIMEOUT               10
#define COD_PRE_EXEC_TIMEOUT                60

struct cod_vpnconn_mgr;

/* OpenVPN proto version */
enum OVPN_PROTO_VERSION {
	OVPN_PROTO_VERSION_4 = 4,
	OVPN_PROTO_VERSION_6 = 6
};

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

/* vpn connection structure */
struct coc_vpn_conn {
	bool end_flag;
	bool conn_cancel;

	struct coc_vpn_config config;

	enum COD_VPNCONN_STATE conn_state;
	enum OVPN_CONN_STATE ovpn_state;

	time_t connected_tm;

	char tun_ip[COD_MAX_IPADDR_LEN + 1];

	pid_t ovpn_pid;
	bool enable_script_sec;

	int ovpn_mgm_port;
	int ovpn_mgm_sock;
	fd_set fds;

	long total_bytes_in, total_bytes_out;
	long curr_bytes_in, curr_bytes_out;

	pthread_t pt_conn, pt_disconn, pt_reconn;
	pthread_t pt_conn_mon;

	struct cod_vpnconn_mgr *vpnconn_mgr;

	struct coc_vpn_conn *next;
	struct coc_vpn_conn *prev;
};

/* cryptoded VPN connection manager structure */
typedef struct cod_vpnconn_mgr {
	bool init_flag;
	bool end_flag;

	int vpn_conns_count;
	struct coc_vpn_conn *vpn_conns;

	pthread_t pt_read_conf;
	pthread_mutex_t conn_mt;

	struct cod_ctx *c;
} cod_vpnconn_mgr_t;

/* cryptoded VPN connection manager functions */
int cod_vpnconn_mgr_init(struct cod_ctx *c);
void cod_vpnconn_mgr_finalize(cod_vpnconn_mgr_t *vpnconn_mgr);

int cod_vpnconn_connect(cod_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);
void cod_vpnconn_disconnect(cod_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void cod_vpnconn_reconnect(cod_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void cod_vpnconn_getstatus(cod_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name, bool json_format, char **state_jstr);

struct coc_vpn_conn *cod_vpnconn_get_byname(cod_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name);

void cod_vpnconn_enable_script_sec(cod_vpnconn_mgr_t *vpnconn_mgr, bool enable_script_security);

#endif /* __COD_VPN_H__ */
