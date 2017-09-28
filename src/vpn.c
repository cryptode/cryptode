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
#include <dirent.h>

#include <json-c/json.h>

#include "rvd.h"

/*
 * rvd connection state strings
 */

struct rvd_vpn_state {
	enum RVD_VPNCONN_STATE state;
	const char *state_str;
} g_rvd_state[] = {
	{RVD_CONN_STATE_DISCONNECTED, "DISCONNECTED"},
	{RVD_CONN_STATE_CONNECTED, "CONNECTED"},
	{RVD_CONN_STATE_CONNECTING, "CONNECTING"},
	{RVD_CONN_STATE_DISCONNECTING, "DISCONNECTING"},
	{RVD_CONN_STATE_RECONNECTING, "RECONNECTING"},
	{RVD_CONN_STATE_UNKNOWN, NULL}
};

/*
 * openvpn connection state strings
 */

struct rvd_ovpn_state {
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

/*
 * add configuration item
 */

static void add_vpn_conn(rvd_vpnconn_mgr_t *vpnconn_mgr, struct rvd_vpnconfig *config)
{
	struct rvd_vpnconn *vpn_conn;

	/* allocate memory for vpn connection info */
	vpn_conn = (struct rvd_vpnconn *) malloc(sizeof(struct rvd_vpnconn));
	if (!vpn_conn)
		return;

	/* set head if it's NULL */
	if (vpnconn_mgr->vpn_conns_count == 0)
		vpnconn_mgr->vpn_conns = vpn_conn;
	else {
		struct rvd_vpnconn *p = vpnconn_mgr->vpn_conns;

		while (p->next)
			p = p->next;

		p->next = vpn_conn;
		vpn_conn->prev = p;
	}

	/* initialize vpn connection info */
	memset(vpn_conn, 0, sizeof(struct rvd_vpnconn));

	/* set configuration item infos */
	memcpy(&vpn_conn->config, config, sizeof(struct rvd_vpnconfig));

	RVD_DEBUG_MSG("VPN: Added VPN configuration with name '%s', openvpn path '%s'", config->name, config->ovpn_profile_path);

	/* set vpnconn_mgr pointer */
	vpn_conn->vpnconn_mgr = vpnconn_mgr;

	/* increase configuration items count */
	vpnconn_mgr->vpn_conns_count++;
}

/*
 * free VPN connection
 */

static void free_vpn_conns(struct rvd_vpnconn *vpn_conns)
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

static struct rvd_vpnconn *get_vpnconn_byname(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

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

static int send_cmd_to_ovpn_mgm(struct rvd_vpnconn *vpn_conn, const char *cmd)
{
	char resp[512];

	/* send command via management socket */
	if (send(vpn_conn->ovpn_mgm_sock, cmd, strlen(cmd), 0) <= 0) {
		RVD_DEBUG_ERR("VPN: Couldn't send '%s' command to OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}

	/* receive current openvpn connection state */
	memset(resp, 0, sizeof(resp));
	if (recv(vpn_conn->ovpn_mgm_sock, resp, sizeof(resp), 0) <= 0) {
		RVD_DEBUG_ERR("VPN: Couldn't receive response for '%s' command from OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}

	return 0;
}

/*
 * close openvpn management socket
 */

static void close_ovpn_mgm_sock(struct rvd_vpnconn *vpn_conn)
{
	/* close socket */
	close(vpn_conn->ovpn_mgm_sock);
	vpn_conn->ovpn_mgm_sock = -1;
}

/*
 * connect to openvpn management socket
 */

static int connect_to_ovpn_mgm(struct rvd_vpnconn *vpn_conn)
{
	int sock;
	struct sockaddr_in mgm_addr;

	char resp[512];

	RVD_DEBUG_MSG("VPN: Creating OpenVPN management socket for connection '%s'", vpn_conn->config.name);

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
		RVD_DEBUG_ERR("VPN: Couldn't connect to OpenVPN management console '127.0.0.1:%d'(err:%d)", vpn_conn->ovpn_mgm_port, errno);
		close(sock);

		return -1;
	}

	/* get first response from management socket */
	if (recv(sock, resp, sizeof(resp), 0) <= 0) {
		RVD_DEBUG_ERR("VPN: Couldn't get first response from OpenVPN management socket for connection '%s'(err:%d)",
			vpn_conn->config.name, errno);
		close(sock);

		return -1;
	}

	/* set management socket */
	vpn_conn->ovpn_mgm_sock = sock;

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

static int send_sigterm_to_ovpn(struct rvd_vpnconn *vpn_conn)
{
	int ret = 0;

	/* check if management socket is valid */
	if (vpn_conn->ovpn_mgm_sock <= 0)
		return -1;

	RVD_DEBUG_MSG("VPN: Sending SIGTERM signal to OpenVPN process with connection name '%s'", vpn_conn->config.name);

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
	struct rvd_vpnconn *vpn_conn = (struct rvd_vpnconn *) p;

	RVD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s'", vpn_conn->config.name);

	/* if vpn connection thread is already run, then wait until it was finished */
	pthread_join(vpn_conn->pt_conn, NULL);

	/* check openvpn process ID */
	if (vpn_conn->ovpn_pid <= 0) {
		RVD_DEBUG_MSG("VPN: OpenVPN process isn't running with name '%s'", vpn_conn->config.name);
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
				if (timeout == RVD_OVPN_STOP_TIMEOUT)
					force_kill_ovpn = true;

				timeout++;
			} while(1);
		} else
			force_kill_ovpn = true;

		/* if openvpn process isn't response, then try killing it force */
		if (force_kill_ovpn) {
			RVD_DEBUG_ERR("VPN: OpenVPN process for connection '%s' isn't responding. Try killing it in force...",
				vpn_conn->config.name);

			kill(vpn_conn->ovpn_pid, SIGTERM);
		}
	}

	RVD_DEBUG_MSG("VPN: Stopping VPN connection with name '%s' has succeeded", vpn_conn->config.name);

	/* init openvpn process ID */
	vpn_conn->ovpn_pid = -1;

	/* set total bytes */
	vpn_conn->total_bytes_in += vpn_conn->curr_bytes_in;
	vpn_conn->total_bytes_out += vpn_conn->curr_bytes_out;

	/* set connection state */
	vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTED;
	vpn_conn->ovpn_state = OVPN_STATE_DISCONNECTED;

	return 0;
}

/*
 * check whether openvpn binrary is available
 */

static int check_ovpn_binary(const char *ovpn_bin_path, bool root_check)
{
	struct stat st;

	/* get stat of openvpn binrary file */
	if (stat(ovpn_bin_path, &st) != 0 || !S_ISREG(st.st_mode)) {
		RVD_DEBUG_ERR("VPN: Wrong path of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	/* check executable status */
	if (!is_valid_permission(ovpn_bin_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
		RVD_DEBUG_ERR("VPN: Wrong permission of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	/* check root status */
	if (root_check && !is_owned_by_user(ovpn_bin_path, "root")) {
		RVD_DEBUG_ERR("VPN: Wrong owner of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	return 0;
}

/*
 * run pre-connect command
 */

static int run_preconn_cmd(struct rvd_vpnconn *vpn_conn)
{
	int w, status = -1;
	int timeout = 0;

	pid_t pre_cmd_pid;

	/* check whether pre-connect command is exist */
	if (strlen(vpn_conn->config.pre_exec_cmd) == 0)
		return 0;

	RVD_DEBUG_MSG("VPN: Running pre-connect command '%s' with uid '%d'",
			vpn_conn->config.pre_exec_cmd, vpn_conn->config.pre_exec_uid);

	/* create pre fork exec process */
	pre_cmd_pid = fork();
	if (pre_cmd_pid == 0) {
		int ret;
		gid_t gid;

		/* set UID */
		setuid(vpn_conn->config.pre_exec_uid);

		/* set gid */
		if (get_gid_by_uid(vpn_conn->config.pre_exec_uid, &gid) == 0)
			setgid(gid);

		/* run command */
		ret = system(vpn_conn->config.pre_exec_cmd);
		exit(ret);
	} else if (pre_cmd_pid < 0) {
		RVD_DEBUG_ERR("VPN: Forking new process for pre-connect-exec has failed(err:%d)", errno);
		return -1;
	}

	/* wait until pre-connect command has finished */
	do {
		w = waitpid(pre_cmd_pid, &status, 0);
		if (w < 0)
			break;

		if (WIFEXITED(status))
			break;

		/* check timeout */
		if (timeout == RVD_PRE_EXEC_TIMEOUT)
			break;

		timeout++;
	} while(1);

	return status;
}

/*
 * rotate original OpenVPN log file
 */

static void rotate_orig_ovpn_log(const char *ovpn_log_path)
{
	struct stat st;
	char backup_log_path[RVD_MAX_PATH];

	/* get state of openvpn log file */
	if (stat(ovpn_log_path, &st) != 0 || !S_ISREG(st.st_mode)) {
		remove(ovpn_log_path);
		return;
	}

	/* check the size of openvpn log file */
	if (st.st_size <= OVPN_MAX_LOG_FSIZE)
		return;

	/* backup original log file */
	snprintf(backup_log_path, sizeof(backup_log_path), "%s.0", ovpn_log_path);

	rename(ovpn_log_path, backup_log_path);
}

/*
 * Run openvpn process
 */

static int run_openvpn_proc(struct rvd_vpnconn *vpn_conn)
{
	pid_t ovpn_pid;

	char mgm_port_str[32];

	char ovpn_log_fname[RVD_MAX_FILE_NAME];
	char ovpn_log_fpath[RVD_MAX_PATH];

	uid_t uid;

	rvd_ctx_t *c = vpn_conn->vpnconn_mgr->c;

	RVD_DEBUG_MSG("VPN: Running OpenVPN process for connection '%s'", vpn_conn->config.name);

	/* check openvpn binrary */
	if (check_ovpn_binary(c->opt.ovpn_bin_path, c->opt.ovpn_root_check) != 0) {
		RVD_DEBUG_ERR("VPN: Failed to check openvpn binrary availability.");
		return -1;
	}

	/* run pre connect exec command */
	if (run_preconn_cmd(vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Failed exit code from running pre-connect command");
		return -1;
	}

	/* check connection cancel flag */
	if (vpn_conn->conn_cancel)
		return -1;

	/* get openvpn management port */
	vpn_conn->ovpn_mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (vpn_conn->ovpn_mgm_port < 0) {
		RVD_DEBUG_ERR("VPN: Couldn't get free port for OpenVPN management socket.");
		return -1;
	}

	snprintf(mgm_port_str, sizeof(mgm_port_str), "%d", vpn_conn->ovpn_mgm_port);
	snprintf(ovpn_log_fname, sizeof(ovpn_log_fname), "%s.ovpn.log", vpn_conn->config.name);
	get_full_path(c->opt.log_dir_path, ovpn_log_fname, ovpn_log_fpath, sizeof(ovpn_log_fpath));

	/* remove log path */
	rotate_orig_ovpn_log(ovpn_log_fpath);

	/* create openvpn process */
	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		char *const ovpn_params[] = {c->opt.ovpn_bin_path,
			    "--config", vpn_conn->config.ovpn_profile_path,
			    "--management", "127.0.0.1", mgm_port_str,
			    "--log-append", ovpn_log_fpath,
			    "--resolv-retry", "infinite",
			    "--connect-retry", OVPN_CONN_RETRY_TIMEOUT_MIN, OVPN_CONN_RETRY_TIMEOUT_MAX,
			    NULL};

		/* child process */
		execv(c->opt.ovpn_bin_path, ovpn_params);

		/* if failed, then exit child with error */
		exit(1);
	} else if (ovpn_pid < 0)
		return -1;

	RVD_DEBUG_MSG("VPN: The OpenVPN process ID for connection '%s' is %d", vpn_conn->config.name, ovpn_pid);

	/* set openvpn process ID */
	vpn_conn->ovpn_pid = ovpn_pid;

	/* sleep for 1 sec due to initialization delay */
	sleep(1);

	/* set owner of openvpn log file */
	uid = vpn_conn->vpnconn_mgr->c->opt.allowed_uid;
	if (uid > 0) {
		gid_t gid;

		if (get_gid_by_uid(uid, &gid) == 0)
			chown(ovpn_log_fpath, uid, gid);
	}

	return 0;
}

/*
 * parse response from openvpn management socket
 */

static void parse_ovpn_mgm_resp(struct rvd_vpnconn *vpn_conn, char *mgm_resp)
{
	char *tok, *p;

	char sep[] = "\n";

	if (strncmp(mgm_resp, OVPN_MGM_RESP_STATE, strlen(OVPN_MGM_RESP_STATE)) == 0) {
		RVD_DEBUG_MSG("VPN: Try parsing OpenVPN management response '%s' for state", mgm_resp);
	}

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

static int get_vpn_conn_state(struct rvd_vpnconn *vpn_conn)
{
	int failed_count = 0;

	RVD_DEBUG_MSG("VPN: Getting OpenVPN connection state with name '%s'", vpn_conn->config.name);

	do {
		int ovpn_state = vpn_conn->ovpn_state;

		/* check end flag */
		if (vpn_conn->conn_cancel || vpn_conn->end_flag)
			break;

		RVD_DEBUG_MSG("VPN: The connection state for name '%s' is '%s'",
			vpn_conn->config.name, g_ovpn_state[ovpn_state].ovpn_state_str);

		/* check openvpn state */
		if (ovpn_state == OVPN_STATE_CONNECTED)
			return 0;

		/* check if connection is failed for timeout */
		if (failed_count == RVD_OVPN_CONN_TIMEOUT)
			break;

		failed_count++;

		sleep(1);
	} while(1);

	return -1;
}

/*
 * VPN connection thread
 */

static void *start_vpn_conn(void *p)
{
	struct rvd_vpnconn *vpn_conn = (struct rvd_vpnconn *) p;

	RVD_DEBUG_MSG("VPN: Starting VPN connection with name '%s'", vpn_conn->config.name);

	/* init */
	vpn_conn->curr_bytes_in = vpn_conn->curr_bytes_out = 0;

	/* run openvpn process */
	if (run_openvpn_proc(vpn_conn) != 0) {
		vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTED;
		return 0;
	}

	/* connect to openvpn process via management console */
	if (connect_to_ovpn_mgm(vpn_conn) == 0 && get_vpn_conn_state(vpn_conn) == 0 &&
			!vpn_conn->conn_cancel) {
		RVD_DEBUG_MSG("VPN: VPN connection with name '%s' has been succeeded", vpn_conn->config.name);
		vpn_conn->conn_state = RVD_CONN_STATE_CONNECTED;
	} else {
		/* check end flag */
		if (vpn_conn->end_flag || vpn_conn->conn_cancel)
			return 0;

		RVD_DEBUG_MSG("VPN: Failed VPN connection with name '%s'. Try to stop OpenVPN", vpn_conn->config.name);
		stop_vpn_conn(vpn_conn);
	}

	return 0;
}

/*
 * start single VPN connection
 */

static void start_single_conn(struct rvd_vpnconn *vpn_conn)
{
	/* set connection state */
	vpn_conn->conn_state = RVD_CONN_STATE_CONNECTING;

	/* set end flag as false */
	vpn_conn->conn_cancel = false;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, start_vpn_conn, (void *) vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * start all VPN connections
 */

static void start_all_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTED)
			start_single_conn(vpn_conn);

		vpn_conn = vpn_conn->next;
	}
}

/*
 * connect to rvd vpn servers
 */

void rvd_vpnconn_connect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvd_vpnconn *vpn_conn;

	/* if connection name is 'all', try start all connections */
	if (strcmp(conn_name, "all") == 0) {
		RVD_DEBUG_MSG("VPN: Try to up all VPN connections");

		start_all_conns(vpnconn_mgr);
		return;
	}

	RVD_DEBUG_MSG("VPN: Try to connect a VPN with name '%s'", conn_name);

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

static void stop_single_conn(struct rvd_vpnconn *vpn_conn)
{
	if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTED ||
		vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTING) {
		RVD_DEBUG_MSG("VPN: The VPN connection with name '%s' is already disconnected or is pending", vpn_conn->config.name);
		return;
	}

	/* set end flag */
	vpn_conn->conn_cancel = true;

	/* set connection state */
	vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTING;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, stop_vpn_conn, (void *) vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * stop all VPN connections
 */

static void stop_all_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED)
			stop_single_conn(vpn_conn);

		vpn_conn = vpn_conn->next;
	}
}

/*
 * disconnect VPN connection(s)
 */

void rvd_vpnconn_disconnect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvd_vpnconn *vpn_conn;

	RVD_DEBUG_MSG("VPN: Try to disconnect VPN with name '%s'", conn_name);

	/* if connection name is 'all', try stop all connections */
	if (strcmp(conn_name, "all") == 0) {
		stop_all_conns(vpnconn_mgr);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn) {
		RVD_DEBUG_ERR("VPN: Couldn't find VPN connection with name '%s'", conn_name);
		return;
	}

	/* stop VPN connection */
	stop_single_conn(vpn_conn);

	return;
}

/*
 * get status of single connection
 */

static void get_single_conn_status(struct rvd_vpnconn *vpn_conn, bool json_format, char **status_str)
{
	char *ret_str;

	time_t ts = time(NULL);

	RVD_DEBUG_MSG("VPN: Getting status of VPN connection with name '%s'", vpn_conn->config.name);

	if (json_format) {
		rvd_json_object_t conn_status_objs[] = {
			{"name", RVD_JTYPE_STR, vpn_conn->config.name, 0, false, NULL},
			{"profile", RVD_JTYPE_STR, (void *)vpn_conn->config.ovpn_profile_path, 0, false, NULL},
			{"status", RVD_JTYPE_STR, (void *)g_rvd_state[vpn_conn->conn_state].state_str, 0, false, NULL},
			{"ovpn-status", RVD_JTYPE_STR, (void *)g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str, 0, false, NULL},
			{"in-total", RVD_JTYPE_INT64, &vpn_conn->total_bytes_in, 0, false, NULL},
			{"out-total", RVD_JTYPE_INT64, &vpn_conn->total_bytes_out, 0, false, NULL},
			{"timestamp", RVD_JTYPE_INT64, &ts, 0, false, NULL}
		};

		/* create json object */
		if (rvd_json_build(conn_status_objs, sizeof(conn_status_objs) / sizeof(rvd_json_object_t), &ret_str) != 0)
			return;

		if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED) {
			char *tmp_jstr;

			rvd_json_object_t conn_objs[] = {
				{"network", RVD_JTYPE_OBJ, NULL, 0, false, NULL},
				{"connected-time", RVD_JTYPE_INT64, &vpn_conn->connected_tm, 0, false, "network"},
				{"in-current", RVD_JTYPE_INT64, &vpn_conn->curr_bytes_in, 0, false, "network"},
				{"out-current", RVD_JTYPE_INT64, &vpn_conn->curr_bytes_out, 0, false, "network"},
			};

			if (rvd_json_add(ret_str, conn_objs, sizeof(conn_objs) / sizeof(rvd_json_object_t), &tmp_jstr) == 0) {
				free(ret_str);
				ret_str = tmp_jstr;
			}
		}
	} else {
		char status_buffer[RVD_MAX_CONN_STATUS_LEN];

		/* set status buffer by plain format */
		if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED)
			snprintf(status_buffer, sizeof(status_buffer), "name: %s\n"
				"\tprofile: %s\n"
				"\tstatus: %s\n"
				"\topenvpn-status: %s\n"
				"\tin-total: %lu\n"
				"\tout-total: %lu\n"
				"\tconnected-time: %lu\n"
				"\tin-current: %lu\n"
				"\tout-current: %lu\n"
				"\ttimestamp: %lu\n",
				vpn_conn->config.name,
				vpn_conn->config.ovpn_profile_path,
				g_rvd_state[vpn_conn->conn_state].state_str,
				g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str,
				vpn_conn->total_bytes_in, vpn_conn->curr_bytes_out,
				vpn_conn->connected_tm,
				vpn_conn->curr_bytes_in, vpn_conn->curr_bytes_out,
				ts);
		else
			snprintf(status_buffer, sizeof(status_buffer), "name: %s\n"
				"\tprofile: %s\n"
				"\tstatus: %s\n"
				"\topenvpn-status: %s\n"
				"\tin-total: %lu\n"
				"\tout-total: %lu\n"
				"\ttimestamp: %lu\n",
				vpn_conn->config.name,
				vpn_conn->config.ovpn_profile_path,
				g_rvd_state[vpn_conn->conn_state].state_str,
				g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str,
				vpn_conn->total_bytes_in, vpn_conn->curr_bytes_out,
				ts);

		/* allocate buffer for ret_str */
		ret_str = (char *) malloc(strlen(status_buffer) + 1);
		if (ret_str) {
			strcpy(ret_str, status_buffer);
			ret_str[strlen(status_buffer)] = '\0';
		}
	}

	*status_str = ret_str;
}

/*
 * get status of all connections
 */

static void get_all_conn_status(rvd_vpnconn_mgr_t *vpnconn_mgr, bool json_format, char **status_str)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;
	char *ret_str = NULL;

	if (json_format) {
		json_object *j_obj;
		const char *p;

		/* create new json object */
		j_obj = json_object_new_array();

		while (vpn_conn) {
			json_object *j_sub_obj;
			char *conn_status_jstr = NULL;

			/* get connection status */
			get_single_conn_status(vpn_conn, true, &conn_status_jstr);
			if (conn_status_jstr) {
				j_sub_obj = json_tokener_parse(conn_status_jstr);
				if (j_sub_obj)
					json_object_array_add(j_obj, j_sub_obj);
			}

			vpn_conn = vpn_conn->next;
		}

		/* set all status */
		p = json_object_get_string(j_obj);

		ret_str = (char *) malloc(strlen(p) + 1);
		if (ret_str) {
			strncpy(ret_str, p, strlen(p));
			ret_str[strlen(p)] = '\0';
		}

		/* free json object */
		json_object_put(j_obj);
	} else {
		while (vpn_conn) {
			char *conn_status_str = NULL;

			/* get single connection status */
			get_single_conn_status(vpn_conn, false, &conn_status_str);
			if (conn_status_str) {
				size_t len = ret_str ? strlen(ret_str) : 0;

				/* allocate and copy buffer */
				ret_str = realloc(ret_str, len + strlen(conn_status_str) + 1);
				if (ret_str) {
					strcpy(&ret_str[len], conn_status_str);
					ret_str[len + strlen(conn_status_str)] = '\0';
				}

				/* free buffer */
				free(conn_status_str);
			}

			vpn_conn = vpn_conn->next;
		}
	}

	*status_str = ret_str;
}

/*
 * get VPN connection status
 */

void rvd_vpnconn_getstatus(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name,
	bool json_format, char **status_str)
{
	struct rvd_vpnconn *vpn_conn;

	RVD_DEBUG_MSG("VPN: Getting connection status for VPN connection with name '%s'", conn_name);

	/* if connection name is 'all', then try get all connection info */
	if (strcmp(conn_name, "all") == 0) {
		get_all_conn_status(vpnconn_mgr, json_format, status_str);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn) {
		RVD_DEBUG_ERR("VPN: Couldn't find VPN connection with name '%s', conn_name");
		return;
	}

	/* stop VPN connection */
	get_single_conn_status(vpn_conn, json_format, status_str);
}

/*
 * finalize VPN connections
 */

static void finalize_vpn_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	/* set end flag for each vpn connection */
	while (vpn_conn) {
		/* stop all VPN connection */
		vpn_conn->conn_cancel = true;
		if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED) {
			if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTING)
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
 * check whether VPN configuration is valid
 */

static bool check_vpn_config(struct rvd_vpnconfig *config)
{
	/* check whether connection name is valid */
	if (!is_valid_conn_name(config->name)) {
		RVD_DEBUG_ERR("VPN: Invalid VPN connection name '%s'", config->name);
		return false;
	}

	/* check whether VPN profile has valid owner and permission */
	if (!is_owned_by_user(config->ovpn_profile_path, "root") ||
	    !is_valid_permission(config->ovpn_profile_path, S_IRUSR | S_IWUSR)) {
		RVD_DEBUG_ERR("VPN: Invalid owner or permission for VPN configuration file '%s'",
				config->ovpn_profile_path);
		return false;
	}

	return true;
}

/*
 * parse configuration
 */

static void parse_config(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *config_path,
	const char *conf_name, const char *ovpn_profile_path)
{
	struct rvd_vpnconfig config;
	bool add_config = true;

	/* init configuration */
	memset(&config, 0, sizeof(config));

	/* set VPN profile path */
	strlcpy(config.ovpn_profile_path, ovpn_profile_path, sizeof(config.ovpn_profile_path));

	if (config_path) {
		int fd;
		FILE *fp;

		struct stat st;

		char *config_buf;
		size_t read_len;

		rvd_json_object_t vpn_config[] = {
			{"name", RVD_JTYPE_STR, config.name, sizeof(config.name), true, NULL},
			{"auto-connect", RVD_JTYPE_BOOL, &config.auto_connect, 0, false, NULL},
			{"pre-connect-exec", RVD_JTYPE_STR, config.pre_exec_cmd, sizeof(config.pre_exec_cmd), false, NULL}
		};

		RVD_DEBUG_MSG("VPN: Parsing configuration file '%s'", config_path);

		if (stat(config_path, &st) != 0 || !S_ISREG(st.st_mode) ||
			st.st_size == 0) {
			RVD_DEBUG_ERR("VPN: Couldn't get state of configuration file '%s'", config_path);
			return;
		}

		/* open configuration file */
		fd = open(config_path, O_RDONLY);
		if (fd < 0) {
			RVD_DEBUG_ERR("VPN: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
			return;
		}

		fp = fdopen(fd, "r");
		if (!fp) {
			RVD_DEBUG_ERR("VPN: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
			close(fd);

			return;
		}

		/* read config buffer */
		config_buf = (char *) malloc(st.st_size + 1);
		if (!config_buf) {
			fclose(fp);
			return;
		}

		memset(config_buf, 0, st.st_size + 1);
		read_len = fread(config_buf, 1, st.st_size, fp);

		/* close file */
		fclose(fp);

		if (read_len <= 0) {
			RVD_DEBUG_ERR("VPN: Invalid the configuration file '%s'", config_path);
			free(config_buf);

			return;
		}

		/* parse json object */
		if (rvd_json_parse(config_buf, vpn_config, sizeof(vpn_config) / sizeof(rvd_json_object_t)) == 0)
			config.pre_exec_uid = vpnconn_mgr->c->opt.allowed_uid;
		else {
			RVD_DEBUG_ERR("VPN: Couldn't parse configuration file '%s'", config_path);
			add_config = false;
		}

		/* free configuration buffer */
		free(config_buf);
	} else
		strlcpy(config.name, conf_name, sizeof(config.name));

	/* check the flag whether add a config */
	if (!add_config)
		return;

	/* check VPN configuration */
	if (!check_vpn_config(&config))
		return;

	/* add VPN connection */
	add_vpn_conn(vpnconn_mgr, &config);
}

/*
 * read configuration from directory
 */

static void read_config(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *dir_path)
{
	DIR *dir;
	struct dirent *dp;

	RVD_DEBUG_MSG("VPN: Reading configuration files in '%s'", dir_path);

	/* open config directory */
	dir = opendir(dir_path);
	if (!dir) {
		RVD_DEBUG_ERR("VPN: Couldn't open directory '%s'", dir_path);
		return;
	}

	while ((dp = readdir(dir)) != NULL) {
		char ovpn_profile_path[RVD_MAX_PATH];
		char conf_json_path[RVD_MAX_PATH];

		char conf_name[RVD_MAX_CONN_NAME_LEN];

		struct stat st;
		const char *p;

		bool conf_exist = true;

		/* init paths */
		memset(ovpn_profile_path, 0, sizeof(ovpn_profile_path));
		memset(conf_json_path, 0, sizeof(conf_json_path));
		memset(conf_name, 0, sizeof(conf_name));

		strlcpy(ovpn_profile_path, dir_path, sizeof(ovpn_profile_path));
		strlcpy(conf_json_path, dir_path, sizeof(conf_json_path));

		if (dir_path[strlen(dir_path) - 1] != '/') {
			strcat(conf_json_path, "/");
			strcat(ovpn_profile_path, "/");
		}

		/* check whether the file is ovpn file */
		p = strstr(dp->d_name, ".ovpn");
		if (!p || strlen(p) != 5)
			continue;

		/* set openvpn profile path */
		strlcat(ovpn_profile_path, dp->d_name, sizeof(ovpn_profile_path));

		/* check whether openvpn profile is exist */
		if (stat(ovpn_profile_path, &st) != 0 || !S_ISREG(st.st_mode)
			|| st.st_size == 0)
			continue;

		/* set json configuration path */
		strncat(conf_json_path, dp->d_name, strlen(dp->d_name) - strlen(p));
		strcat(conf_json_path, ".json");

		/* check whether configuration file is exist */
		if (stat(conf_json_path, &st) != 0 || !S_ISREG(st.st_mode) ||
			st.st_size == 0) {
			/* set connection name */
			strncpy(conf_name, dp->d_name, strlen(dp->d_name) - 5);
			conf_exist = false;
		}

		/* parse configuration file */
		parse_config(vpnconn_mgr, conf_exist ? conf_json_path : NULL, conf_name, ovpn_profile_path);
	}

	/* close directory */
	closedir(dir);
}

/*
 * get VPN connection by name
 */

struct rvd_vpnconn *rvd_vpnconn_get_byname(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	return get_vpnconn_byname(vpnconn_mgr, conn_name);
}


/*
 * write VPN connection list into buffer
 */

static void add_conninfo_to_buffer(struct rvd_vpnconn *vpn_conn, char **buffer)
{
	struct rvd_vpnconfig *config = &vpn_conn->config;
	char config_buffer[RVD_MAX_CONN_INFO_LEN + 1];

	char *p = *buffer;
	size_t len;

	/* get length of original buffer */
	len = p ? strlen(p) : 0;

	/* set config buffer */
	snprintf(config_buffer, sizeof(config_buffer), "name: %s\n"
					"\tprofile: %s\n"
					"\tauto-connect: %s\n"
					"\tpre-exec-cmd: %s\n",
					config->name, config->ovpn_profile_path,
					config->auto_connect ? "Enabled" : "Disabled",
					config->pre_exec_cmd);

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

static void add_conninfo_to_json(struct rvd_vpnconn *vpn_conn, json_object *j_obj)
{
	struct rvd_vpnconfig *config = &vpn_conn->config;
	json_object *j_sub_obj;

	char *p = NULL;

	rvd_json_object_t conn_info_objs[] = {
		{"name", RVD_JTYPE_STR, config->name, 0, false, NULL},
		{"profile", RVD_JTYPE_STR, config->ovpn_profile_path, 0, false, NULL},
		{"auto-connect", RVD_JTYPE_BOOL, &config->auto_connect, 0, false, NULL},
		{"pre-exec-cmd", RVD_JTYPE_STR, config->pre_exec_cmd, 0, false, NULL}
	};

	/* create new json object */
	if (rvd_json_build(conn_info_objs, sizeof(conn_info_objs) / sizeof(rvd_json_object_t), &p) != 0)
		return;

	j_sub_obj = json_tokener_parse(p);
	if (j_sub_obj)
		json_object_array_add(j_obj, j_sub_obj);

	free(p);
}

/*
 * get VPN connection list
 */

void rvd_vpnconn_list_to_buffer(rvd_vpnconn_mgr_t *vpnconn_mgr, bool json_format, char **buffer)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;
	json_object *j_obj;

	RVD_DEBUG_MSG("VPN: Writing VPN connection list into buffer");

	if (json_format) {
		j_obj = json_object_new_array();
		if (!j_obj) {
			RVD_DEBUG_ERR("VPN: Coudn't create json object");
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
			strcpy(*buffer, p);
			(*buffer)[strlen(p)] = '\0';
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
	struct rvd_vpnconn *vpn_conn = (struct rvd_vpnconn *) p;

	RVD_DEBUG_MSG("VPN: Starting VPN connection monitoring thread with name '%s'", vpn_conn->config.name);

	while (!vpn_conn->end_flag) {
		fd_set fds;
		struct timeval tv;

		int ret;

		char ovpn_mgm_resp[512];
		bool failed = false;

		/* check openvpn management socket has been created */
		if (vpn_conn->ovpn_mgm_sock <= 0) {
			sleep(1);
			continue;
		}

		/* copy fd set */
		FD_ZERO(&fds);
		FD_SET(vpn_conn->ovpn_mgm_sock, &fds);

		/* set timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 50;

		/* get notifications from openvpn client */
		ret = select(vpn_conn->ovpn_mgm_sock + 1, &fds, NULL, NULL, &tv);
		if (ret < 0) {
			RVD_DEBUG_ERR("VPN: Exception has occurred on openvpn management socket(errno: %d)", errno);
			break;
		}

		if (!FD_ISSET(vpn_conn->ovpn_mgm_sock, &fds)) {
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
			if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED && vpn_conn->ovpn_state != OVPN_STATE_CONNECTED)
				vpn_conn->conn_state = RVD_CONN_STATE_RECONNECTING;
			else if (vpn_conn->conn_state == RVD_CONN_STATE_RECONNECTING && vpn_conn->ovpn_state == OVPN_STATE_CONNECTED)
				vpn_conn->conn_state = RVD_CONN_STATE_CONNECTED;
		} else if (ret == 0) {
			failed = true;
		} else {
			if (errno != EWOULDBLOCK)
				failed = true;
		}

		if (failed) {
			/* stop vpn connection */
			if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED ||
				vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTING) {
				vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTING;
				stop_vpn_conn(vpn_conn);
			}

			close_ovpn_mgm_sock(vpn_conn);
			continue;
		}

		sleep(1);
	}

	RVD_DEBUG_MSG("VPN: VPN connection monitoring thread with name '%s' stopped", vpn_conn->config.name);

	return 0;
}

/*
 * enable/disable script security
 */

void rvd_vpnconn_enable_script_sec(rvd_vpnconn_mgr_t *vpnconn_mgr, bool enable_script_sec)
{
	struct rvd_vpnconn *vpn_conn = vpnconn_mgr->vpn_conns;

	RVD_DEBUG_MSG("VPN: %s script security", enable_script_sec ? "Enable" : "Disable");

	while (vpn_conn) {
		vpn_conn->enable_script_sec = enable_script_sec;
		vpn_conn = vpn_conn->next;
	}
}

/*
 * initialize rvd VPN connection manager
 */

int rvd_vpnconn_mgr_init(struct rvd_ctx *c)
{
	rvd_vpnconn_mgr_t *vpnconn_mgr = &c->vpnconn_mgr;
	struct rvd_vpnconn *vpn_conn;

	RVD_DEBUG_MSG("VPN: Initializing VPN connection manager");

	/* set context object */
	vpnconn_mgr->c = c;

	/* initialize mutex */
	pthread_mutex_init(&vpnconn_mgr->conn_mt, NULL);

	/* set configuration path */
	read_config(vpnconn_mgr, c->opt.vpn_config_dir);

	/* create thread for monitoring vpn connections */
	vpn_conn = vpnconn_mgr->vpn_conns;
	while (vpn_conn) {
		/* if auto connect flag enabled, then start VPN connection */
		if (vpn_conn->config.auto_connect) {
			RVD_DEBUG_MSG("VPN: The auto-connect for VPN connection '%s' is enabled. Try to start it.", vpn_conn->config.name);
			start_single_conn(vpn_conn);
		}

		if (pthread_create(&vpn_conn->pt_conn_mon, NULL, monitor_vpn_conn, (void *) vpn_conn) != 0) {
			RVD_DEBUG_ERR("VPN: Couldn't create VPN connection monitoring thread");
		}

		vpn_conn = vpn_conn->next;
	}

	/* set init status */
	vpnconn_mgr->init_flag = true;

	return 0;
}

/*
 * finalize rvd VPN connection manager
 */

void rvd_vpnconn_mgr_finalize(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	/* check init state */
	if (!vpnconn_mgr->init_flag)
		return;

	RVD_DEBUG_MSG("VPN: Finalizing VPN connection manager");

	/* set end status */
	vpnconn_mgr->end_flag = true;

	/* stop all VPN connections */
	finalize_vpn_conns(vpnconn_mgr);

	/* destroy mutex */
	pthread_mutex_destroy(&vpnconn_mgr->conn_mt);
}
