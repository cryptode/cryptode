/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <json-c/json.h>

#include "rvcd.h"

/*
 * rvcd VPN connection monitor
 */

static void *rvcd_vpnconn_monitor(void *p)
{
	return 0;
}

/*
 * add configuration item
 */

static void add_vpn_conn(rvcd_vpnconn_mgr_t *vpnconn_mgr, struct rvcd_vpnconfig *config)
{
	struct rvcd_vpnconn *vpn_conn;

	/* allocate memory for vpn connection info */
	vpn_conn = (struct rvcd_vpnconn *) malloc(sizeof(struct rvcd_vpnconn));
	if (!vpn_conn)
		return;

	/* set head if it's NULL */
	if (vpnconn_mgr->vpn_conns_count == 0)
		vpnconn_mgr->vpn_conns = vpn_conn;
	else {
		struct rvcd_vpnconn *p = vpnconn_mgr->vpn_conns;

		while (p->next)
			p = p->next;

		p->next = vpn_conn;
		vpn_conn->prev = p;
	}

	/* initialize vpn connection info */
	memset(vpn_conn, 0, sizeof(struct rvcd_vpnconn));

	/* set configuration item infos */
	memcpy(&vpn_conn->config, config, sizeof(struct rvcd_vpnconfig));

	RVCD_DEBUG_MSG("VPN: Added VPN configuration with name '%s', openvpn path '%s'", config->name, config->ovpn_profile_path);

	/* increase configuration items count */
	vpnconn_mgr->vpn_conns_count++;
}

/*
 * free VPN connection
 */

static void free_vpn_conns(struct rvcd_vpnconn *vpn_conns)
{
	if (!vpn_conns)
		return;

	/* free next item recursively */
	if (vpn_conns->next)
		free_vpn_conns(vpn_conns->next);

	/* free self */
	free(vpn_conns);
}

/*
 * get VPN connection by name
 */

static struct rvcd_vpnconn *get_vpnconn_byname(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	pthread_mutex_lock(&vpnconn_mgr->conn_mt);

	while (vpn_conn) {
		if (strcmp(vpn_conn->config.name, conn_name) == 0)
			break;

		vpn_conn = vpn_conn->next;
	}

	pthread_mutex_unlock(&vpnconn_mgr->conn_mt);

	return vpn_conn;
}

/*
 * send command to openvpn management socket
 */

static int send_cmd_to_ovpn_mgm(struct rvcd_vpnconn *vpn_conn, const char *cmd)
{
	char resp[512];

	/* send command via management socket */
	if (send(vpn_conn->ovpn_mgm_sock, cmd, strlen(cmd), 0) != strlen(cmd)) {
		RVCD_DEBUG_ERR("VPN: Couldn't send '%s' command to OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}

	/* receive current openvpn connection state */
	memset(resp, 0, sizeof(resp));
	if (recv(vpn_conn->ovpn_mgm_sock, resp, sizeof(resp), 0) <= 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't receive response for '%s' command from OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}

	return 0;
}

/*
 * close openvpn management socket
 */

static void close_ovpn_mgm_sock(struct rvcd_vpnconn *vpn_conn)
{
	/* remove socket from fds */
	FD_ZERO(&vpn_conn->fds);

	/* close socket */
	close(vpn_conn->ovpn_mgm_sock);
	vpn_conn->ovpn_mgm_sock = -1;
}

/*
 * connect to openvpn management socket
 */

static int connect_to_ovpn_mgm(struct rvcd_vpnconn *vpn_conn)
{
	int sock;
	struct sockaddr_in mgm_addr;

	char resp[512];

	RVCD_DEBUG_MSG("VPN: Creating OpenVPN management socket for connection '%s'", vpn_conn->config.name);

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;

	/* set management address */
	memset(&mgm_addr, 0, sizeof(mgm_addr));
	mgm_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(mgm_addr.sin_addr));
	mgm_addr.sin_port = htons(vpn_conn->ovpn_mgm_port);

	/* connet to openvpn management console */
	if (connect(sock, (const struct sockaddr *) &mgm_addr, sizeof(struct sockaddr_in)) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't connect to OpenVPN management console '127.0.0.1:%d'(err:%d)", vpn_conn->ovpn_mgm_port, errno);
		close(sock);

		return -1;
	}

	/* get first response from management socket */
	if (recv(sock, resp, sizeof(resp), 0) <= 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't get first response from OpenVPN management socket(err:%d)", errno);
		close(sock);

		return -1;
	}

	/* set management socket */
	vpn_conn->ovpn_mgm_sock = sock;

	/* add management socket into fdset */
	FD_ZERO(&vpn_conn->fds);
	FD_SET(sock, &vpn_conn->fds);

	/* send command to openvpn management */
	if (send_cmd_to_ovpn_mgm(vpn_conn, OVPN_MGM_CMD_BYTECOUNT) != 0 ||
		send_cmd_to_ovpn_mgm(vpn_conn, OVPN_MGM_CMD_STATE) != 0) {
		close_ovpn_mgm_sock(vpn_conn);
		return -1;
	}

	return 0;
}


/*
 * send SIGTERM signal to openvpn process via management socket
 */

static int send_sigterm_to_ovpn(struct rvcd_vpnconn *vpn_conn)
{
	int ret = 0;

	/* check if management socket is valid */
	if (vpn_conn->ovpn_mgm_sock < 0)
		return -1;

	RVCD_DEBUG_MSG("VPN: Sending SIGTERM signal to OpenVPN process with connection name '%s'", vpn_conn->config.name);

	/* send SIGTERM command to openvpn */
	ret = send_cmd_to_ovpn_mgm(vpn_conn, OVPN_MGM_CMD_SIGTERM);

	/* close openvpn mgm socket */
	close_ovpn_mgm_sock(vpn_conn);

	return ret;
}

/*
 * stop VPN connection
 */

static void *stop_vpn_conn(void *p)
{
	struct rvcd_vpnconn *vpn_conn = (struct rvcd_vpnconn *) p;

	RVCD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s'", vpn_conn->config.name);

	/* if vpn connection thread is already run, then wait until it was finished */
	pthread_join(vpn_conn->pt_conn, NULL);

	/* check openvpn process ID */
	if (vpn_conn->ovpn_pid <= 0) {
		RVCD_DEBUG_MSG("VPN: OpenVPN process isn't running with name '%s'", vpn_conn->config.name);
	} else {
		bool force_kill_ovpn = false;

		/* send SIGTERM command to openvpn */
		if (send_sigterm_to_ovpn(vpn_conn) == 0) {
			int w, status;
			int timeout = 0;

			do {
				w = waitpid(vpn_conn->ovpn_pid, &status, 0);
				if (w < 0)
					break;

				if (WIFEXITED(status))
					break;

				/* check timeout */
				if (timeout == RVCD_OVPN_STOP_TIMEOUT)
					force_kill_ovpn = true;

				timeout++;
			} while(1);
		} else
			force_kill_ovpn = true;

		/* if openvpn process isn't response, then try killing it force */
		if (force_kill_ovpn) {
			RVCD_DEBUG_ERR("VPN: OpenVPN process isn't responding. Try killing it in force...");
			kill(vpn_conn->ovpn_pid, SIGTERM);
		}
	}

	RVCD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s' has succeeded", vpn_conn->config.name);

	/* init openvpn process ID */
	vpn_conn->ovpn_pid = -1;

	/* set total bytes */
	vpn_conn->total_bytes_in += vpn_conn->curr_bytes_in;
	vpn_conn->total_bytes_out += vpn_conn->curr_bytes_out;

	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTED;
	vpn_conn->ovpn_state = OVPN_STATE_DISCONNECTED;

	return 0;
}


/*
 * Run openvpn process
 */

static int run_openvpn_proc(struct rvcd_vpnconn *vpn_conn)
{
	pid_t ovpn_pid;

	char mgm_port_str[32];
	char ovpn_log_fpath[RVCD_MAX_PATH];

	RVCD_DEBUG_MSG("VPN: Running OpenVPN process for connection '%s'", vpn_conn->config.name);

	/* get openvpn management port */
	vpn_conn->ovpn_mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (vpn_conn->ovpn_mgm_port < 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't get free port for OpenVPN management socket.");
		return -1;
	}

	snprintf(mgm_port_str, sizeof(mgm_port_str), "%d", vpn_conn->ovpn_mgm_port);
	snprintf(ovpn_log_fpath, sizeof(ovpn_log_fpath), "/tmp/%s.ovpn.log", vpn_conn->config.name);

	/* create openvpn process */
	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		char *const ovpn_params[] = {OPENVPN_BINARY_PATH, "--config", vpn_conn->config.ovpn_profile_path,
			"--management", "127.0.0.1", mgm_port_str, "--log", ovpn_log_fpath, NULL};

		/* set new session */
		setsid();

		/* child process */
		execv(OPENVPN_BINARY_PATH, ovpn_params);

		/* if failed, then exit child with error */
		exit(1);
	} else if (ovpn_pid < 0)
		return -1;

	/* set openvpn process ID */
	vpn_conn->ovpn_pid = ovpn_pid;

	return 0;
}

/*
 * parse response from openvpn management socket
 */

struct rvcd_ovpn_state {
	enum OVPN_CONN_STATE ovpn_state;
	const char *ovpn_state_str;
} g_ovpn_state[] = {
	{OVPN_STATE_DISCONNECTED, "DISCONNECTED"},
	{OVPN_STATE_CONNECTING, "TCP_CONNECT"},
	{OVPN_STATE_WAIT, "WAIT"},
	{OVPN_STATE_AUTH, "AUTH"},
	{OVPN_STATE_GETCONFIG, "GET_CONFIG"},
	{OVPN_STATE_ASSIGNIP, "ASSIGN_IP"},
	{OVPN_STATE_ADDROUTES, "ADD_ROUTES"},
	{OVPN_STATE_CONNECTED, "CONNECTED"},
	{OVPN_STATE_RECONNECTING, "RECONNECTING"},
	{OVPN_STATE_EXITING, "EXITING"},
	{OVPN_STATE_UNKNOWN, NULL}
};

static void parse_ovpn_mgm_resp(struct rvcd_vpnconn *vpn_conn, char *mgm_resp)
{
	char *tok, *p;

	RVCD_DEBUG_MSG("VPN: Try parsing OpenVPN management response '%s'", mgm_resp);

	char sep[] = "\n";

	tok = strtok(mgm_resp, sep);
	while (tok != NULL) {
		if (strncmp(tok, OVPN_MGM_RESP_BYTECOUNT, strlen(OVPN_MGM_RESP_BYTECOUNT)) == 0) {
			char bytes[64];

			p = tok + strlen(OVPN_MGM_RESP_BYTECOUNT);

			/* get in bytes */
			get_token_by_comma(&p, bytes, sizeof(bytes));
			vpn_conn->curr_bytes_in = strtol(bytes, NULL, 10);

			/* get out bytes */
			get_token_by_comma(&p, bytes, sizeof(bytes));
			vpn_conn->curr_bytes_out = strtol(bytes, NULL, 10);
		} else if (strncmp(tok, OVPN_MGM_RESP_STATE, strlen(OVPN_MGM_RESP_STATE)) == 0) {
			char ts_str[32];
			char conn_state[64];

			int i;

			p = tok + strlen(OVPN_MGM_RESP_STATE);

			/* get timestamp */
			get_token_by_comma(&p, ts_str, sizeof(ts_str));

			/* get connection state */
			get_token_by_comma(&p, conn_state, sizeof(conn_state));
			for (i = 0; g_ovpn_state[i].ovpn_state_str != NULL; i++) {
				if (strcmp(conn_state, g_ovpn_state[i].ovpn_state_str) == 0) {
					vpn_conn->ovpn_state = g_ovpn_state[i].ovpn_state;
					break;
				}
			}

			/* if connected, then set timestamp */
			if (vpn_conn->ovpn_state == OVPN_STATE_CONNECTED)
				vpn_conn->connected_tm = strtol(ts_str, NULL, 10);
		}

		tok = strtok(NULL, sep);
	}
}

/*
 * get connection state from openvpn management socket
 */

static int get_vpn_conn_state(struct rvcd_vpnconn *vpn_conn, time_t *tm)
{
	int failed_count = 0;

	RVCD_DEBUG_MSG("VPN: Getting OpenVPN connection state with name '%s'", vpn_conn->config.name);

	do {
		int ovpn_state = vpn_conn->ovpn_state;

		/* check end flag */
		if (vpn_conn->conn_cancel || vpn_conn->end_flag)
			break;

		RVCD_DEBUG_MSG("VPN: The connection state for name '%s' is '%s'",
			vpn_conn->config.name, g_ovpn_state[ovpn_state].ovpn_state_str);

		/* check openvpn state */
		if (ovpn_state == OVPN_STATE_CONNECTED)
			return 0;

		/* check if connection is failed for timeout */
		if (ovpn_state == OVPN_STATE_CONNECTING || ovpn_state == OVPN_STATE_WAIT || ovpn_state == OVPN_STATE_RECONNECTING) {
			if (failed_count == RVCD_OVPN_CONN_TIMEOUT)
				break;

			failed_count++;
		}
		else
			failed_count = 0;

		sleep(1);
	} while(1);

	return -1;
}

/*
 * VPN connection thread
 */

static void *start_vpn_conn(void *p)
{
	struct rvcd_vpnconn *vpn_conn = (struct rvcd_vpnconn *) p;
	time_t tm;

	RVCD_DEBUG_MSG("VPN: Starting VPN connection with name '%s'", vpn_conn->config.name);

	/* init */
	vpn_conn->curr_bytes_in = vpn_conn->curr_bytes_out = 0;

	/* run openvpn process */
	if (run_openvpn_proc(vpn_conn) != 0) {
		vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTED;
		return 0;
	}

	sleep(1);

	/* connect to openvpn process via management console */
	if (connect_to_ovpn_mgm(vpn_conn) == 0 && get_vpn_conn_state(vpn_conn, &tm) == 0) {
		RVCD_DEBUG_MSG("VPN: VPN connection with name '%s' has been succeeded", vpn_conn->config.name);
		vpn_conn->conn_state = RVCD_CONN_STATE_CONNECTED;
		vpn_conn->connected_tm = tm;
	} else {
		/* check end flag */
		if (vpn_conn->end_flag || vpn_conn->conn_cancel)
			return 0;

		RVCD_DEBUG_MSG("VPN: Failed VPN connection with name '%s'. Try to stop OpenVPN", vpn_conn->config.name);
		stop_vpn_conn(vpn_conn);
	}

	return 0;
}

/*
 * start single VPN connection
 */

static void start_single_conn(struct rvcd_vpnconn *vpn_conn)
{
	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_CONNECTING;

	/* set end flag as false */
	vpn_conn->conn_cancel = false;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, start_vpn_conn, (void *) vpn_conn) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * start all VPN connections
 */

static void start_all_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		start_single_conn(vpn_conn);
		vpn_conn = vpn_conn->next;
	}
}

/*
 * connect to rvcd vpn servers
 */

void rvcd_vpnconn_connect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvcd_vpnconn *vpn_conn;

	RVCD_DEBUG_MSG("VPN: Try to connect a VPN with name '%s'", conn_name);

	/* if connection name is 'all', try start all connections */
	if (strcmp(conn_name, "all") == 0) {
		start_all_conns(vpnconn_mgr);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn)
		return;

	/* start VPN connection */
	start_single_conn(vpn_conn);
}

/*
 * stop single VPN connection
 */

static void stop_single_conn(struct rvcd_vpnconn *vpn_conn)
{
	if (vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTED ||
		vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTING) {
		RVCD_DEBUG_MSG("VPN: The VPN connection with name '%s' is already disconnected or is pending", vpn_conn->config.name);
		return;
	}

	/* set end flag */
	vpn_conn->conn_cancel = true;

	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTING;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, stop_vpn_conn, (void *) vpn_conn) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * stop all VPN connections
 */

static void stop_all_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		stop_single_conn(vpn_conn);
		vpn_conn = vpn_conn->next;
	}
}

/*
 * disconnect VPN connection(s)
 */

void rvcd_vpnconn_disconnect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvcd_vpnconn *vpn_conn;

	RVCD_DEBUG_MSG("VPN: Try to disconnect from VPN with name '%s'", conn_name);

	/* if connection name is 'all', try stop all connections */
	if (strcmp(conn_name, "all") == 0) {
		stop_all_conns(vpnconn_mgr);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn) {
		RVCD_DEBUG_ERR("VPN: Couldn't find VPN connection with name '%s'", conn_name);
		return;
	}

	/* stop VPN connection */
	stop_single_conn(vpn_conn);

	return;
}

/*
 * get status of single connection
 */

static void get_single_conn_status(struct rvcd_vpnconn *vpn_conn, char **status_jstr)
{
	json_object *j_obj, *j_sub_obj;
	const char *p;

	char *ret_jstr;

	RVCD_DEBUG_MSG("VPN: Getting status of VPN connection with name '%s'", vpn_conn->config.name);

	/* create json object */
	j_obj = json_object_new_object();
	if (!j_obj)
		return;

	j_sub_obj = json_object_new_object();
	if (!j_sub_obj) {
		json_object_put(j_obj);
		return;
	}

	/* add fields */
	json_object_object_add(j_obj, "name", json_object_new_string(vpn_conn->config.name));
	json_object_object_add(j_obj, "status", json_object_new_string(g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str));

	if (vpn_conn->conn_state == RVCD_CONN_STATE_CONNECTED) {
		json_object_object_add(j_obj, "connected-time", json_object_new_int64(vpn_conn->connected_tm));

		json_object_object_add(j_sub_obj, "in-current", json_object_new_int64(vpn_conn->curr_bytes_in));
		json_object_object_add(j_sub_obj, "out-current", json_object_new_int64(vpn_conn->curr_bytes_out));
	}

	json_object_object_add(j_sub_obj, "in-total", json_object_new_int64(vpn_conn->total_bytes_in + vpn_conn->curr_bytes_in));
	json_object_object_add(j_sub_obj, "out-total", json_object_new_int64(vpn_conn->total_bytes_out + vpn_conn->curr_bytes_out));

	json_object_object_add(j_obj, "timestamp", json_object_new_int64(time(NULL)));

	json_object_object_add(j_obj, "network", j_sub_obj);

	/* get json buffer from json object */
	p = json_object_get_string(j_obj);
	if (p) {
		ret_jstr = (char *) malloc(strlen(p) + 1);
		if (ret_jstr) {
			strncpy(ret_jstr, p, strlen(p));
			ret_jstr[strlen(p)] = '\0';

			*status_jstr = ret_jstr;
		}
	}

	/* free json object */
	json_object_put(j_obj);
}

/*
 * get status of all connections
 */

static void get_all_conn_status(rvcd_vpnconn_mgr_t *vpnconn_mgr, char **status_jstr)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	json_object *j_obj;
	const char *p;
	char *ret_jstr = NULL;

	/* create new json object */
	j_obj = json_object_new_array();

	while (vpn_conn) {
		json_object *j_sub_obj;
		char *conn_status_jstr = NULL;

		/* get connection status */
		get_single_conn_status(vpn_conn, &conn_status_jstr);
		if (conn_status_jstr) {
			j_sub_obj = json_tokener_parse(conn_status_jstr);
			if (j_sub_obj)
				json_object_array_add(j_obj, j_sub_obj);
		}

		vpn_conn = vpn_conn->next;
	}

	/* set all status */
	p = json_object_get_string(j_obj);

	ret_jstr = (char *) malloc(strlen(p) + 1);
	if (ret_jstr) {
		strncpy(ret_jstr, p, strlen(p));
		ret_jstr[strlen(p)] = '\0';

		*status_jstr = ret_jstr;
	}

	/* free json object */
	json_object_put(j_obj);
}

/*
 * get VPN connection status
 */

void rvcd_vpnconn_getstatus(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name, char **status_str)
{
	struct rvcd_vpnconn *vpn_conn;

	RVCD_DEBUG_MSG("VPN: Getting connection status for VPN connection with name '%s'", conn_name);

	/* if connection name is 'all', then try get all connection info */
	if (strcmp(conn_name, "all") == 0) {
		get_all_conn_status(vpnconn_mgr, status_str);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn) {
		RVCD_DEBUG_ERR("VPN: Couldn't find VPN connection with name '%s', conn_name");
		return;
	}

	/* stop VPN connection */
	get_single_conn_status(vpn_conn, status_str);
}

/*
 * finalize VPN connections
 */

static void finalize_vpn_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	/* set end flag for each vpn connection */
	while (vpn_conn) {
		/* stop all VPN connection */
		vpn_conn->conn_cancel = true;
		if (vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTED) {
			if (vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTING)
				pthread_join(vpn_conn->pt_conn, NULL);
			else
				stop_vpn_conn(vpn_conn);
		}

		/* stop VPN connection monitoring thread */
		vpn_conn->end_flag = true;
		pthread_join(vpn_conn->pt_conn_mon, NULL);

		vpn_conn = vpn_conn->next;
	}

	/* free vpn connections */
	free_vpn_conns(vpnconn_mgr->vpn_conns);
}

/*
 * parse configuration
 */

static int parse_config(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *config_buffer)
{
	json_object *j_obj;

	int i;
	size_t count;

	/* parse json object */
	j_obj = json_tokener_parse(config_buffer);
	if (!j_obj) {
		RVCD_DEBUG_ERR("VPN: Invalid configuration JSON buffer");
		return -1;
	}

	/* check if the type of json object is array */
	if (json_object_get_type(j_obj) != json_type_array) {
		RVCD_DEBUG_ERR("VPN: Invalid configuration JSON array");
		json_object_put(j_obj);
		return -1;
	}

	/* get configuration item count */
	count = json_object_array_length(j_obj);
	for (i = 0; i < count; i++) {
		json_object *j_item_obj, *j_sub_obj;

		struct rvcd_vpnconfig config;

		/* get json object for item */
		j_item_obj = json_object_array_get_idx(j_obj, i);
		if (!j_item_obj)
			continue;

		/* init config item */
		memset(&config, 0, sizeof(config));

		/* get name object */
		if (!json_object_object_get_ex(j_item_obj, "name", &j_sub_obj)) {
			RVCD_DEBUG_WARN("VPN: Couldn't find object with key 'name' at index:%d", i);
			continue;
		}

		snprintf(config.name, sizeof(config.name), "%s", json_object_get_string(j_sub_obj));
		if (!is_valid_conn_name(config.name)) {
			RVCD_DEBUG_ERR("VPN: Invalid VPN connection name '%s'. The name should contain only alphabetic characters.",
				config.name);
			continue;
		}

		/* get ovpn object */
		if (!json_object_object_get_ex(j_item_obj, "ovpn", &j_sub_obj)) {
			RVCD_DEBUG_WARN("VPN: Couldn't find object with key 'ovpn' at index:%d", i);
			continue;
		}

		snprintf(config.ovpn_profile_path, sizeof(config.ovpn_profile_path), "%s", json_object_get_string(j_sub_obj));

		/* get autoconnect flag */
		if (json_object_object_get_ex(j_item_obj, "auto-connect", &j_sub_obj))
			config.auto_connect = json_object_get_boolean(j_sub_obj);

		/* get up/down script path */
		if (json_object_object_get_ex(j_item_obj, "up-script", &j_sub_obj))
			snprintf(config.up_script, sizeof(config.up_script), "%s", json_object_get_string(j_sub_obj));

		if (json_object_object_get_ex(j_item_obj, "down-script", &j_sub_obj))
			snprintf(config.down_script, sizeof(config.down_script), "%s", json_object_get_string(j_sub_obj));

		/* add vpn connection */
		add_vpn_conn(vpnconn_mgr, &config);
	}

	/* free json object */
	json_object_put(j_obj);

	return 0;
}

/*
 * read configuration
 */

static int read_config(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *config_path)
{
	struct stat st;
	char *config_buf = NULL;

	int fd;
	FILE *fp;
	size_t read_len;

	int ret = -1;

	RVCD_DEBUG_MSG("VPN: Reading configuration from '%s'", config_path);

	/* get size of configuration file */
	if (stat(config_path, &st) != 0)
		return -1;

	if (!S_ISREG(st.st_mode) || st.st_size == 0)
		return -1;

	/* open configuration file */
	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
		return -1;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		RVCD_DEBUG_ERR("VPN: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
		close(fd);

		return -1;
	}

	/* read config buffer */
	config_buf = (char *) malloc(st.st_size + 1);
	if (!config_buf) {
		fclose(fp);
		return -1;
	}

	memset(config_buf, 0, st.st_size + 1);

	read_len = fread(config_buf, 1, st.st_size, fp);
	if (read_len > 0)
		ret = parse_config(vpnconn_mgr, config_buf);

	/* free buffer */
	free(config_buf);

	/* close file */
	fclose(fp);

	return ret;
}

/*
 * get VPN connection by name
 */

struct rvcd_vpnconn *rvcd_vpnconn_get_byname(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	return get_vpnconn_byname(vpnconn_mgr, conn_name);
}


/*
 * write VPN connection list into buffer
 */

static void add_conninfo_to_buffer(struct rvcd_vpnconn *vpn_conn, char **buffer)
{
	struct rvcd_vpnconfig *config = &vpn_conn->config;
	char config_buffer[RVCD_MAX_CONN_INFO_LEN + 1];

	char *p = *buffer;
	size_t len;

	/* get length of original buffer */
	len = p ? strlen(p) : 0;

	/* set config buffer */
	snprintf(config_buffer, sizeof(config_buffer), "name: %s\n"
					"\t\tprofile: %s\n"
					"\t\tauto-connect: %s\n"
					"\t\tup-script: %s\n\t\tdown-script:%s\n",
					config->name, config->ovpn_profile_path, config->auto_connect ? "Enabled" : "Disabled",
					strlen(config->up_script) > 0 ? config->up_script : "none",
					strlen(config->down_script) > 0 ? config->down_script : "none");

	/* allocate and set new buffer */
	if (!p)
		p = (char *) malloc(strlen(config_buffer) + 1);
	else
		p = (char *) realloc(p, strlen(config_buffer) + len + 1);

	strcpy(&p[len], config_buffer);
	p[len + strlen(config_buffer)] = '\0';

	*buffer = p;
}

/*
 * add VPN connection info into json object
 */

static void add_conninfo_to_json(struct rvcd_vpnconn *vpn_conn, json_object *j_obj)
{
	struct rvcd_vpnconfig *config = &vpn_conn->config;
	json_object *j_sub_obj;

	/* create new json object */
	j_sub_obj = json_object_new_object();
	if (!j_sub_obj)
		return;

	json_object_object_add(j_sub_obj, "name", json_object_new_string(config->name));
	json_object_object_add(j_sub_obj, "profile", json_object_new_string(config->ovpn_profile_path));
	json_object_object_add(j_sub_obj, "auto-connect", json_object_new_boolean(config->auto_connect));

	if (strlen(config->up_script) > 0)
		json_object_object_add(j_sub_obj, "up-script", json_object_new_string(config->up_script));

	if (strlen(config->down_script) > 0)
		json_object_object_add(j_sub_obj, "down-script", json_object_new_string(config->down_script));

	json_object_array_add(j_obj, j_sub_obj);
}

/*
 * get VPN connection list
 */

void rvcd_vpnconn_list_to_buffer(rvcd_vpnconn_mgr_t *vpnconn_mgr, bool json_format, char **buffer)
{
	struct rvcd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;
	json_object *j_obj;

	RVCD_DEBUG_MSG("VPN: Writing VPN connection list into buffer");

	if (json_format) {
		j_obj = json_object_new_array();
		if (!j_obj) {
			RVCD_DEBUG_ERR("VPN: Coudn't create json object");
			return;
		}
	}

	/* lock mutex */
	pthread_mutex_lock(&vpnconn_mgr->conn_mt);

	while (vpn_conn) {
		if (!json_format)
			add_conninfo_to_buffer(vpn_conn, buffer);
		else
			add_conninfo_to_json(vpn_conn, j_obj);

		vpn_conn = vpn_conn->next;
	}

	/* unlock mutex */
	pthread_mutex_unlock(&vpnconn_mgr->conn_mt);

	if (json_format) {
		const char *p = json_object_get_string(j_obj);

		*buffer = (char *) malloc(strlen(p) + 1);
		if (*buffer) {
			memset(*buffer, 0, strlen(p) + 1);
			strcpy(*buffer, p);
		}

		/* free json object */
		json_object_put(j_obj);
	}
}

/*
 * VPN connection monitoring thread
 */

static void *monitor_vpn_conn(void *p)
{
	struct rvcd_vpnconn *vpn_conn = (struct rvcd_vpnconn *) p;

	RVCD_DEBUG_MSG("VPN: Starting VPN connection monitoring thread with name '%s'", vpn_conn->config.name);

	while (!vpn_conn->end_flag) {
		int ovpn_state;
		time_t tm;

		fd_set tmp_fds;
		struct timeval tv;

		int ret;

		char ovpn_mgm_resp[512];
		bool failed = false;

		/* check openvpn management socket has been created */
		if (vpn_conn->ovpn_mgm_sock < 0) {
			sleep(1);
			continue;
		}

		/* copy fd set */
		FD_COPY(&vpn_conn->fds, &tmp_fds);

		/* set timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 50;

		/* get notifications from openvpn client */
		ret = select(vpn_conn->ovpn_mgm_sock + 1, &tmp_fds, NULL, NULL, &tv);
		if (ret < 0) {
			RVCD_DEBUG_ERR("VPN: Exception has occurred on openvpn management socket(errno: %d)", errno);
			break;
		}

		if (!FD_ISSET(vpn_conn->ovpn_mgm_sock, &vpn_conn->fds)) {
			sleep(1);
			continue;
		}

		/* get respnose */
		memset(ovpn_mgm_resp, 0, sizeof(ovpn_mgm_resp));
		ret = recv(vpn_conn->ovpn_mgm_sock, ovpn_mgm_resp, sizeof(ovpn_mgm_resp), 0);
		if (ret > 0) {
			/* parse openvpn response */
			parse_ovpn_mgm_resp(vpn_conn, ovpn_mgm_resp);

			/* check if openvpn connection has abnormally disconnected */
			if (vpn_conn->conn_state == RVCD_CONN_STATE_CONNECTED && vpn_conn->ovpn_state != OVPN_STATE_CONNECTED)
				vpn_conn->conn_state = RVCD_CONN_STATE_RECONNECTING;
			else if (vpn_conn->conn_state == RVCD_CONN_STATE_RECONNECTING && vpn_conn->conn_state == OVPN_STATE_CONNECTED)
				vpn_conn->conn_state = RVCD_CONN_STATE_CONNECTED;
		} else if (ret == 0) {
			failed = true;
		} else {
			if (errno != EWOULDBLOCK)
				failed = true;
		}

		if (failed) {
			/* stop vpn connection */
			if (vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTED ||
				vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTING) {
				vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTING;
				stop_vpn_conn(vpn_conn);
			}

			close_ovpn_mgm_sock(vpn_conn);
			continue;
		}

		sleep(1);
	}

	RVCD_DEBUG_MSG("VPN: VPN connection monitoring thread with name '%s' stopped", vpn_conn->config.name);

	return 0;
}

/*
 * initialize rvcd VPN connection manager
 */

int rvcd_vpnconn_mgr_init(struct rvcd_ctx *c)
{
	rvcd_vpnconn_mgr_t *vpnconn_mgr = &c->vpnconn_mgr;
	struct rvcd_vpnconn *vpn_conn;

	const char *config_path;

	RVCD_DEBUG_MSG("VPN: Initializing VPN connection manager");

	/* initialize mutex */
	pthread_mutex_init(&vpnconn_mgr->conn_mt, NULL);

	/* set configuration path */
	read_config(vpnconn_mgr, c->config_path ? c->config_path : RVCD_CONFIG_DEFAULT_PATH);

	/* create thread for monitoring vpn connections */
	vpn_conn = vpnconn_mgr->vpn_conns;
	while (vpn_conn) {
		/* if auto connect flag enabled, then start VPN connection */
		if (vpn_conn->config.auto_connect) {
			RVCD_DEBUG_MSG("VPN: The auto-connect for VPN connection '%s' is enabled. Try to start it.", vpn_conn->config.name);
			start_single_conn(vpn_conn);
		}

		if (pthread_create(&vpn_conn->pt_conn_mon, NULL, monitor_vpn_conn, (void *) vpn_conn) != 0) {
			RVCD_DEBUG_ERR("VPN: Couldn't create VPN connection monitoring thread");
		}

		vpn_conn = vpn_conn->next;
	}

	/* set init status */
	vpnconn_mgr->init_flag = true;

	/* set context object */
	vpnconn_mgr->c = c;

	return 0;
}

/*
 * finalize rvcd VPN connection manager
 */

void rvcd_vpnconn_mgr_finalize(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	/* check init state */
	if (!vpnconn_mgr->init_flag)
		return;

	RVCD_DEBUG_MSG("VPN: Finalizing VPN connection manager");

	/* set end status */
	vpnconn_mgr->end_flag = true;

	/* stop all VPN connections */
	finalize_vpn_conns(vpnconn_mgr);

	/* destroy mutex */
	pthread_mutex_destroy(&vpnconn_mgr->conn_mt);
}
