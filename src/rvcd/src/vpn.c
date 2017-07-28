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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rvcd.h"

/*
 * rvcd VPN connection monitor
 */

static void *rvcd_vpnconn_monitor(void *p)
{
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

	RVCD_DEBUG_MSG("VPN: Sending SIGTERM signal to OpenVPN process with connection name '%s'", vpn_conn->config_item->name);

	/* send sigterm signal */
	if (send(vpn_conn->ovpn_mgm_sock, OVPN_MGM_CMD_SIGTERM, strlen(OVPN_MGM_CMD_SIGTERM), 0) != strlen(OVPN_MGM_CMD_SIGTERM)) {
		RVCD_DEBUG_ERR("VPN: Couldn't send SIGTERM signal to OpenVPN process(err:%d)", errno);
		ret = -1;
	} else {
		char resp[512];

		/* receive response from openvpn process */
		if (recv(vpn_conn->ovpn_mgm_sock, resp, sizeof(resp), 0) <= 0) {
			RVCD_DEBUG_ERR("VPN: Couldn't receive response from OpenVPN management socket(err:%d)", errno);
			ret = -1;
		}
	}

	/* close management socket */
	close(vpn_conn->ovpn_mgm_sock);
	vpn_conn->ovpn_mgm_sock = -1;

	return ret;
}

/*
 * stop VPN connection
 */

static void *stop_vpn_conn(void *p)
{
	struct rvcd_vpnconn *vpn_conn = (struct rvcd_vpnconn *) p;

	RVCD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s'", vpn_conn->config_item->name);

	if (vpn_conn->conn_state == RVCD_CONN_STATE_CONNECTING) {
		vpn_conn->end_flag = true;
		pthread_join(vpn_conn->pt_conn, NULL);
	}

	/* check openvpn process ID */
	if (vpn_conn->ovpn_pid < 0) {
		RVCD_DEBUG_MSG("VPN: OpenVPN process isn't running with name '%s'", vpn_conn->config_item->name);
		return 0;
	}

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
			if (timeout == RVCD_OVPN_STOP_TIMEOUT) {
				RVCD_DEBUG_ERR("VPN: OpenVPN process isn't responding. Try killing it in force...");
				kill(vpn_conn->ovpn_pid, SIGTERM);
			}

			timeout++;
		} while(1);

		
	}

	RVCD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s' has succeeded", vpn_conn->config_item->name);

	/* init openvpn process ID */
	vpn_conn->ovpn_pid = -1;

	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTED;

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

	RVCD_DEBUG_MSG("VPN: Running OpenVPN process for connection '%s'", vpn_conn->config_item->name);

	/* get openvpn management port */
	vpn_conn->ovpn_mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (vpn_conn->ovpn_mgm_port < 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't get free port for OpenVPN management socket.");
		return -1;
	}

	snprintf(mgm_port_str, sizeof(mgm_port_str), "%d", vpn_conn->ovpn_mgm_port);
	snprintf(ovpn_log_fpath, sizeof(ovpn_log_fpath), "/tmp/%s.ovpn.log", vpn_conn->config_item->name);

	/* create openvpn process */
	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		char *const ovpn_params[] = {OVPN_BIN_PATH, "--config", vpn_conn->config_item->ovpn_profile_path,
			"--management", "127.0.0.1", mgm_port_str, "--log", ovpn_log_fpath, NULL};

		/* child process */
		execv(OVPN_BIN_PATH, ovpn_params);

		/* if failed, then exit child with error */
		exit(1);
	} else if (ovpn_pid < 0)
		return -1;

	/* set openvpn process ID */
	vpn_conn->ovpn_pid = ovpn_pid;

	return 0;
}

/*
 * connect to openvpn management socket
 */

static int connect_to_ovpn_mgm(struct rvcd_vpnconn *vpn_conn)
{
	int sock;
	struct sockaddr_in mgm_addr;

	char resp[512];

	RVCD_DEBUG_MSG("VPN: Creating OpenVPN management socket for connection '%s'", vpn_conn->config_item->name);

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

	return 0;
}

/*
 * parse response from openvpn management socket
 */

struct rvcd_ovpn_state {
	enum OVPN_CONN_STATE ovpn_state;
	const char *ovpn_state_str;
} g_ovpn_state[] = {
	{OVPN_STATE_CONNECTING, "TCP_CONNECT"},
	{OVPN_STATE_WAIT, "WAIT"},
	{OVPN_STATE_AUTH, "AUTH"},
	{OVPN_STATE_GETCONFIG, "GET_CONFIG"},
	{OVPN_STATE_ASSIGNIP, "ASSIGN_IP"},
	{OVPN_STATE_ADDROUTES, "ADD_ROUTES"},
	{OVPN_STATE_CONNECTED, "CONNECTED"},
	{OVPN_STATE_RECONNECTING, "RECONNECTING"},
	{OVPN_STATE_EXITING, "EXITING"},
	{OVPN_STATE_DISCONNECTED, "DISCONNECTED"},
	{OVPN_STATE_UNKNOWN, NULL}
};

static void parse_ovpn_mgm_resp(char *resp, int *state)
{
	char *p = resp;
	char time[64], ovpn_state_str[64], desc[128];

	int i, ovpn_state = OVPN_STATE_UNKNOWN;

	/* get unix date and time */
	get_token_by_comma(&p, time, sizeof(time));

	/* get state */
	get_token_by_comma(&p, ovpn_state_str, sizeof(ovpn_state_str));

	for (i = 0; g_ovpn_state[i].ovpn_state_str != NULL; i++) {
		if (strcmp(ovpn_state_str, g_ovpn_state[i].ovpn_state_str) == 0) {
			ovpn_state = g_ovpn_state[i].ovpn_state;
			break;
		}
	}

	*state = ovpn_state;
}

/*
 * parse connection state from openvpn management console
 */

static int get_conn_state_via_mgm(struct rvcd_vpnconn *vpn_conn, int *ovpn_state)
{
	char resp[512];

	/* send command via management socket */
	if (send(vpn_conn->ovpn_mgm_sock, OVPN_MGM_CMD_STATE, strlen(OVPN_MGM_CMD_STATE), 0) != strlen(OVPN_MGM_CMD_STATE)) {
		RVCD_DEBUG_ERR("VPN: Couldn't send 'state' command to OpenVPN management socket(err:%d)", errno);
		return -1;
	}

	/* receive current openvpn connection state */
	memset(resp, 0, sizeof(resp));
	if (recv(vpn_conn->ovpn_mgm_sock, resp, sizeof(resp), 0) <= 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't receive response for 'state' command from OpenVPN management socket(err:%d)", errno);
		return -1;
	}

	/* parse response */
	parse_ovpn_mgm_resp(resp, ovpn_state);

	return 0;
}

/*
 * get connection state from openvpn management socket
 */

static int get_vpn_conn_state(struct rvcd_vpnconn *vpn_conn)
{
	int ovpn_state;
	int failed_count = 0;

	RVCD_DEBUG_MSG("VPN: Getting OpenVPN connection state with name '%s'", vpn_conn->config_item->name);

	do {
		/* check end flag */
		if (vpn_conn->end_flag)
			break;

		/* get openvpn state via management socket */
		if (get_conn_state_via_mgm(vpn_conn, &ovpn_state) != 0)
			return -1;

		RVCD_DEBUG_MSG("VPN: The connection state for name '%s' is '%s'",
			vpn_conn->config_item->name, g_ovpn_state[ovpn_state].ovpn_state_str);

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

	RVCD_DEBUG_MSG("VPN: Starting VPN connection with name '%s'", vpn_conn->config_item->name);

	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_CONNECTING;

	/* set end flag as false */
	vpn_conn->end_flag = false;

	/* run openvpn process */
	if (run_openvpn_proc(vpn_conn) != 0) {
		vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTED;
		return 0;
	}

	sleep(1);

	/* connect to openvpn process via management console */
	if (connect_to_ovpn_mgm(vpn_conn) == 0 && get_vpn_conn_state(vpn_conn) == 0) {
		RVCD_DEBUG_MSG("VPN: VPN connection with name '%s' has been succeeded", vpn_conn->config_item->name);
		vpn_conn->conn_state = RVCD_CONN_STATE_CONNECTED;
	} else {
		/* check end flag */
		if (vpn_conn->end_flag)
			return 0;

		RVCD_DEBUG_MSG("VPN: VPN connection with name '%s' has been failed. Try stop OpenVPN", vpn_conn->config_item->name);
		stop_vpn_conn(vpn_conn);
	}

	return 0;
}

/*
 * start single VPN connection
 */

static void start_single_conn(struct rvcd_vpnconn *vpn_conn)
{
	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, start_vpn_conn, (void *) vpn_conn) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config_item->name);
		return;
	}
}

/*
 * start all VPN connections
 */

static void start_all_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	int i;

	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		struct rvcd_vpnconn *vpn_conn = &vpnconn_mgr->vpn_conns[i];
		if (vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTED)
			start_single_conn(vpn_conn);
	}
}

/*
 * connect to rvcd vpn servers
 */

int rvcd_vpnconn_connect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	int i;
	bool found_conn = false;

	struct rvcd_vpnconn *vpn_conn = NULL;

	RVCD_DEBUG_MSG("VPN: Try connect using VPN name '%s'", conn_name);

	/* if connection name is 'all', try start all connections */
	if (strcmp(conn_name, "all") == 0) {
		start_all_conns(vpnconn_mgr);
		return RVCD_RESP_OK;
	}

	/* check if given connection name is exist */
	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		vpn_conn = &vpnconn_mgr->vpn_conns[i];
		if (strcmp(conn_name, vpn_conn->config_item->name) == 0) {
			found_conn = true;
			break;
		}
	}

	if (!found_conn) {
		RVCD_DEBUG_ERR("VPN: Couldn't found VPN connection name with '%s'", conn_name);
		return RVCD_RESP_CONN_NOT_FOUND;
	}

	/* check if connection is in progress */
	if (vpn_conn->conn_state == RVCD_CONN_STATE_CONNECTED) {
		RVCD_DEBUG_ERR("VPN: The current connection with name '%s' is already connected", conn_name);
		return RVCD_RESP_CONN_ALREADY_CONNECTED;
	} else if (vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTED) {
		RVCD_DEBUG_ERR("VPN: The current connection with name '%s' is in pending", conn_name);
		return RVCD_RESP_CONN_IN_PROGRESS;
	}

	/* start VPN connection */
	start_single_conn(vpn_conn);

	return RVCD_RESP_OK;
}

/*
 * stop single VPN connection
 */

static void stop_single_conn(struct rvcd_vpnconn *vpn_conn)
{
	/* set connection state */
	vpn_conn->conn_state = RVCD_CONN_STATE_DISCONNECTING;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, stop_vpn_conn, (void *) vpn_conn) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config_item->name);
		return;
	}
}

/*
 * stop all VPN connections
 */

static void stop_all_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	int i;

	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		struct rvcd_vpnconn *vpn_conn = &vpnconn_mgr->vpn_conns[i];
		if (vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTED || vpn_conn->conn_state != RVCD_CONN_STATE_DISCONNECTING)
			stop_single_conn(vpn_conn);
	}
}

/*
 * disconnect VPN connection(s)
 */

int rvcd_vpnconn_disconnect(rvcd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	int i;
	bool found_conn = false;

	struct rvcd_vpnconn *vpn_conn = NULL;

	RVCD_DEBUG_MSG("VPN: Try disconnect using VPN name '%s'", conn_name);

	/* if connection name is 'all', try stop all connections */
	if (strcmp(conn_name, "all") == 0) {
		stop_all_conns(vpnconn_mgr);
		return RVCD_RESP_OK;
	}

	/* check if given connection name is exist */
	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		vpn_conn = &vpnconn_mgr->vpn_conns[i];
		if (strcmp(conn_name, vpn_conn->config_item->name) == 0) {
			found_conn = true;
			break;
		}
	}

	if (!found_conn) {
		RVCD_DEBUG_ERR("VPN: Couldn't found VPN connection name with '%s'", conn_name);
		return RVCD_RESP_CONN_NOT_FOUND;
	}

	/* check if connection is in progress */
	if (vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTED) {
		RVCD_DEBUG_ERR("VPN: The current connection with name '%s' is already disconnected", conn_name);
		return RVCD_RESP_CONN_ALREADY_DISCONNECTED;
	} else if (vpn_conn->conn_state == RVCD_CONN_STATE_DISCONNECTING) {
		RVCD_DEBUG_ERR("VPN: The current connection with name '%s' is in disconnecting progress", conn_name);
		return RVCD_RESP_CONN_IN_PROGRESS;
	}

	/* stop VPN connection */
	stop_single_conn(vpn_conn);

	return RVCD_RESP_OK;
}

/*
 * finalize VPN connections
 */

static void finalize_vpn_conns(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	int i;

	/* set end flag for each vpn connection */
	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		stop_vpn_conn(&vpnconn_mgr->vpn_conns[i]);
	}

	if (vpnconn_mgr->vpn_conns_count > 0)
		free(vpnconn_mgr->vpn_conns);
}

/*
 * init VPN connections
 */

static int init_vpn_connections(rvcd_vpnconn_mgr_t *vpnconn_mgr)
{
	rvcd_config_t *config = &vpnconn_mgr->c->config;
	int i;

	/* allocate memory for vpn connections */
	if (config->config_items_count == 0)
		return 0;

	vpnconn_mgr->vpn_conns = (struct rvcd_vpnconn *) malloc(config->config_items_count * sizeof(struct rvcd_vpnconn));
	if (!vpnconn_mgr->vpn_conns)
		return -1;

	memset(vpnconn_mgr->vpn_conns, 0, config->config_items_count * sizeof(struct rvcd_vpnconn));
	vpnconn_mgr->vpn_conns_count = config->config_items_count;

	/* init vpn connection params */
	for (i = 0; i < vpnconn_mgr->vpn_conns_count; i++) {
		struct rvcd_vpnconn *vpn_conn = &vpnconn_mgr->vpn_conns[i];

		vpn_conn->config_item = &config->config_items[i];
		vpn_conn->ovpn_pid = -1;
		vpn_conn->ovpn_mgm_sock = -1;
	}

	return 0;
}


/*
 * initialize rvcd VPN connection manager
 */

int rvcd_vpnconn_mgr_init(struct rvcd_ctx *c)
{
	rvcd_vpnconn_mgr_t *vpnconn_mgr = &c->vpnconn_mgr;

	RVCD_DEBUG_MSG("VPN: Initializing VPN connection manager");

	/* set context object */
	vpnconn_mgr->c = c;

	/* init VPN connections */
	if (init_vpn_connections(vpnconn_mgr) != 0) {
		RVCD_DEBUG_ERR("VPN: Out of memory!");
		return -1;
	}

	/* create thread to monitor VPN connections */
	if (pthread_create(&vpnconn_mgr->pt_conn_mon, NULL, rvcd_vpnconn_monitor, (void *) vpnconn_mgr) != 0) {
		RVCD_DEBUG_ERR("VPN: Couldn't create thread to monitor OpenVPN connections.");
		return -1;
	}

	/* set init status */
	vpnconn_mgr->init_flag = true;

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

	RVCD_DEBUG_MSG("VPN: Finalizing VPN connection manager.");

	/* set end status */
	vpnconn_mgr->end_flag = true;

	/* wait until VPN connection monitoring thread has terminated */
	pthread_join(vpnconn_mgr->pt_conn_mon, NULL);

	/* stop all VPN connections */
	finalize_vpn_conns(vpnconn_mgr);
}

