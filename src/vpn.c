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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>

#include <json-c/json.h>

#include "rvd.h"

#define CLOSE_PIPE(p)            { close(p[0]); close(p[1]); }

/*
 * rvd connection state strings
 */

struct rvd_vpn_state {
	enum RVD_VPNCONN_STATE state;
	char *state_str;
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
	char *ovpn_state_str;
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

static void add_vpn_conn(rvd_vpnconn_mgr_t *vpnconn_mgr, struct rvc_vpn_config *config)
{
	struct rvc_vpn_conn *vpn_conn;

	/* allocate memory for vpn connection info */
	vpn_conn = (struct rvc_vpn_conn *) malloc(sizeof(struct rvc_vpn_conn));
	if (!vpn_conn)
		return;

	/* lock mutex */
	pthread_mutex_lock(&vpnconn_mgr->conn_mt);

	/* set head if it's NULL */
	if (vpnconn_mgr->vpn_conns_count == 0)
		vpnconn_mgr->vpn_conns = vpn_conn;
	else {
		struct rvc_vpn_conn *p = vpnconn_mgr->vpn_conns;

		while (p->next)
			p = p->next;

		p->next = vpn_conn;
		vpn_conn->prev = p;
	}

	/* initialize vpn connection info */
	memset(vpn_conn, 0, sizeof(struct rvc_vpn_conn));

	/* set configuration item infos */
	memcpy(&vpn_conn->config, config, sizeof(struct rvc_vpn_config));

	RVD_DEBUG_MSG("VPN: Added VPN configuration with name '%s', openvpn path '%s'", config->name, config->ovpn_profile_path);

	/* set vpnconn_mgr pointer */
	vpn_conn->vpnconn_mgr = vpnconn_mgr;

	/* increase configuration items count */
	vpnconn_mgr->vpn_conns_count++;

	/* unlock mutex */
	pthread_mutex_unlock(&vpnconn_mgr->conn_mt);
}

/*
 * free VPN connection
 */

static void free_vpn_conns(struct rvc_vpn_conn *vpn_conns)
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

static struct rvc_vpn_conn *get_vpnconn_byname(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

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

static int send_cmd_to_ovpn_mgm(struct rvc_vpn_conn *vpn_conn, const char *cmd)
{
	char resp[512];

	if (send(vpn_conn->ovpn_mgm_sock, cmd, strlen(cmd), 0) <= 0) {
		RVD_DEBUG_ERR("VPN: Couldn't send '%s' command to OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}

	memset(resp, 0, sizeof(resp));
	if (recv(vpn_conn->ovpn_mgm_sock, resp, sizeof(resp), 0) <= 0) {
		RVD_DEBUG_ERR("VPN: Couldn't receive response for '%s' command from OpenVPN management socket(err:%d)", cmd, errno);
		return -1;
	}
	RVD_DEBUG_MSG("VPN: The response is '%s' for cmd '%s'", resp, cmd);

	return 0;
}

/*
 * close openvpn management socket
 */

static void close_ovpn_mgm_sock(struct rvc_vpn_conn *vpn_conn)
{
	/* close socket */
	close(vpn_conn->ovpn_mgm_sock);
	vpn_conn->ovpn_mgm_sock = -1;
}

/*
 * connect to openvpn management socket
 */

static int connect_to_ovpn_mgm(struct rvc_vpn_conn *vpn_conn)
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

	/* send 'state' command to openvpn management */
	if (send_cmd_to_ovpn_mgm(vpn_conn, OVPN_MGM_CMD_NOTIFY) != 0) {
		close_ovpn_mgm_sock(vpn_conn);
		return -1;
	}

	return 0;
}


/*
 * send SIGTERM signal to openvpn process via management socket
 */

static int send_sigterm_to_ovpn(struct rvc_vpn_conn *vpn_conn)
{
	int ret = 0;

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
	struct rvc_vpn_conn *vpn_conn = (struct rvc_vpn_conn *) p;

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
				w = waitpid(vpn_conn->ovpn_pid, &status, WNOHANG);
				if (w < 0)
					break;
				else if (w == 0) {
					/* check timeout */
					if (timeout == RVD_OVPN_STOP_TIMEOUT) {
						force_kill_ovpn = true;
						break;
					}

					timeout++;
					sleep(1);
				}

				if (WIFEXITED(status))
					break;
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

	/* set connection state */
	vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTED;
	vpn_conn->ovpn_state = OVPN_STATE_DISCONNECTED;

	vpn_conn->tun_ip[0] = '\0';

	return 0;
}

/*
 * check whether openvpn binary is available
 */

static int check_ovpn_binary(const char *ovpn_bin_path, bool root_check)
{
	struct stat st;

	/* get stat of openvpn binary file */
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
 * add pre exec command fail log into log file
 */

static void log_pre_exec_output(int fd, const char *log_path, const char *cmd, int status)
{
	int log_fd;
	FILE *log_fp = NULL;

	char buffer[512];
	ssize_t read_bytes;

	ssize_t buffer_size = 0;

	char *cmd_out = NULL;

	/* read bytes from pipe */
	while ((read_bytes = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
		ssize_t total_size = read_bytes + buffer_size + 1;

		cmd_out = realloc(cmd_out, total_size);
		if (!cmd_out) {
			RVD_DEBUG_ERR("VPN: Out of memory");
			return;
		}

		buffer[read_bytes] = '\0';
		strlcpy(&cmd_out[buffer_size], buffer, total_size);
	}

	/* open log file for append mode and write pre-exec command output */
	log_fd = open(log_path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
	if (log_fd < 0) {
		RVD_DEBUG_ERR("VPN: Couldn't open openvpn log file '%s'", log_path);

		if (cmd_out)
			free(cmd_out);

		return;
	}

	log_fp = fdopen(log_fd, "a");
	if (!log_fp) {
		RVD_DEBUG_ERR("VPN: Couldn't open openvpn log file '%s'", log_path);

		close(log_fd);

		if (cmd_out)
			free(cmd_out);

		return;
	}

	if (status != 0)
		fprintf(log_fp, "Warning, pre-exec-cmd '%s' has failed with exit code '%d'\n", cmd, status);

	fprintf(log_fp, "The result of pre-exec-cmd '%s' is\n%s\n", cmd, cmd_out);

	fclose(log_fp);
	free(cmd_out);
}

/*
 * run pre-connect command
 */

static int run_preconn_cmd(struct rvc_vpn_conn *vpn_conn)
{
	pid_t pre_cmd_pid;
	int pipeout[2], pipeerr[2];

	char *cmd, *tok;
	char **args = NULL;

	int tok_count = 0;

	int cmd_status = EXIT_FAILURE;

	/* check whether pre-connect command is exist */
	if (strlen(vpn_conn->config.pre_exec_cmd) == 0)
		return 0;

	RVD_DEBUG_MSG("VPN: Running pre-connect command '%s' with uid '%d'",
			vpn_conn->config.pre_exec_cmd, vpn_conn->config.pre_exec_uid);

	/* init exit status and timestamp */
	vpn_conn->config.pre_exec_status = EXIT_FAILURE;
	vpn_conn->config.pre_exec_ts = 0;

	/* open pipe to get output of pre-exec-cmd */
	if (pipe(pipeout) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create pipe to get stdout of pre-exec-cmd");
		return -1;
	}

	if (pipe(pipeerr) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create pipe to get stderr of pre-exec-cmd");

		CLOSE_PIPE(pipeout);
		return -1;
	}

	/* separate commad to args */
	cmd = strdup(vpn_conn->config.pre_exec_cmd);
	if (!cmd) {
		RVD_DEBUG_ERR("VPN: Out of memory(strdup)");

		CLOSE_PIPE(pipeout);
		CLOSE_PIPE(pipeerr);
		return -1;
	}

	tok = strtok(cmd, " ");
	while (tok) {
		args = realloc(args, (++tok_count + 1) * sizeof(char *));
		if (!args) {
			RVD_DEBUG_ERR("VPN: Out of memory(strdup)");

			CLOSE_PIPE(pipeout);
			CLOSE_PIPE(pipeerr);

			free(cmd);

			return -1;
		}
		args[tok_count - 1] = tok;

		tok = strtok(NULL, " ");
	}
	args[tok_count] = NULL;

	/* create pre fork exec process */
	pre_cmd_pid = fork();
	if (pre_cmd_pid == 0) {
		/* redirect output to pipe */
		close(pipeout[0]);
		close(pipeerr[0]);

		dup2(pipeout[1], STDOUT_FILENO);
		dup2(pipeerr[1], STDERR_FILENO);

		/* set UID */
		if (vpn_conn->config.pre_exec_uid > 0)
			setuid(vpn_conn->config.pre_exec_uid);

		/* run command */
		execvp(args[0], args);
		exit(EXIT_FAILURE);
	} else if (pre_cmd_pid > 0) {
		int w, status;
		int timeout = 0;

		/* close output of pipe */
		close(pipeout[1]);
		close(pipeerr[1]);

		/* wait until pre-connect command has finished */
		do {
			w = waitpid(pre_cmd_pid, &status, WNOHANG);
			if (w < 0)
				break;
			else if (w == 0) {
				if (timeout == RVD_PRE_EXEC_TIMEOUT) {
					kill(pre_cmd_pid, SIGKILL);
					break;
				}
				timeout++;
				sleep(1);
				continue;
			}

			if (WIFEXITED(status)) {
				cmd_status = WEXITSTATUS(status);
				break;
			}
		} while(1);
	} else {
		RVD_DEBUG_ERR("VPN: Forking new process for pre-connect-exec has failed(err:%d)", errno);
	}

	RVD_DEBUG_MSG("VPN: The status of pre-exec-cmd is '%d'", cmd_status);

	/* append log line into openvpn log file */
	log_pre_exec_output(cmd_status == 0 ? pipeout[0] : pipeerr[0], vpn_conn->config.ovpn_log_path,
				vpn_conn->config.pre_exec_cmd, cmd_status);

	/* free memory */
	if (args)
		free(args);

	if (cmd)
		free(cmd);

	/* close pipe file */
	close(pipeout[0]);
	close(pipeerr[0]);

	/* set status */
	vpn_conn->config.pre_exec_status = cmd_status;

	/* set timestamp if status is OK */
	vpn_conn->config.pre_exec_ts = time(NULL);

	return cmd_status;
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
		unlink(ovpn_log_path);
		return;
	}

	/* check the size of openvpn log file */
	if (st.st_size <= OVPN_MAX_LOG_FSIZE)
		return;

	/* backup original log file */
	snprintf(backup_log_path, sizeof(backup_log_path), "%s.0", ovpn_log_path);
	unlink(backup_log_path);

	if (rename(ovpn_log_path, backup_log_path) != 0)
		RVD_DEBUG_WARN("VPN: Failed to backup OpenVPN log file.(err:%d)\n", errno);
}

/*
 * Run openvpn process
 */

static int run_openvpn_proc(struct rvc_vpn_conn *vpn_conn)
{
	pid_t ovpn_pid;
	char mgm_port_str[32];
	char ovpn_log_fname[RVD_MAX_FILE_NAME];
	char ovpn_pid_fpath[RVD_MAX_PATH];
	int uid;

	rvd_ctx_t *c = vpn_conn->vpnconn_mgr->c;

	RVD_DEBUG_MSG("VPN: Running OpenVPN process for connection '%s'", vpn_conn->config.name);

	/* rotate openvpn log file */
	snprintf(ovpn_log_fname, sizeof(ovpn_log_fname), "%s.ovpn.log", vpn_conn->config.name);
	get_full_path(c->opt.log_dir_path, ovpn_log_fname,
				vpn_conn->config.ovpn_log_path, sizeof(vpn_conn->config.ovpn_log_path));

	rotate_orig_ovpn_log(vpn_conn->config.ovpn_log_path);

	/* run pre connect exec command */
	if (run_preconn_cmd(vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Failed exit code from running pre-connect command");
		return -1;
	}

	/* check connection cancel flag */
	if (vpn_conn->conn_cancel)
		return -1;

	/* create openvpn process */
	vpn_conn->ovpn_mgm_port = get_free_listen_port(OVPN_MGM_PORT_START);
	if (vpn_conn->ovpn_mgm_port < 0) {
		RVD_DEBUG_ERR("VPN: Couldn't get free port for OpenVPN management socket.");
		return -1;
	}

	snprintf(mgm_port_str, sizeof(mgm_port_str), "%d", vpn_conn->ovpn_mgm_port);
	snprintf(ovpn_pid_fpath, sizeof(ovpn_pid_fpath), "%s/%s.ovpn.pid", RVD_PID_DPATH, vpn_conn->config.name);
	unlink(ovpn_pid_fpath);

	ovpn_pid = fork();
	if (ovpn_pid == 0) {
		char *const ovpn_params[] = {c->opt.ovpn_bin_path,
			    "--config", vpn_conn->config.ovpn_profile_path,
			    "--management", "127.0.0.1", mgm_port_str,
			    "--log-append", vpn_conn->config.ovpn_log_path,
			    "--resolv-retry", "infinite",
			    "--writepid", ovpn_pid_fpath,
#if 0
			    "--connect-retry", OVPN_CONN_RETRY_TIMEOUT_MIN, OVPN_CONN_RETRY_TIMEOUT_MAX,
#endif
			    NULL};

		execv(c->opt.ovpn_bin_path, ovpn_params);
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

		if (get_gid_by_uid(uid, &gid) != 0 ||
			chown(vpn_conn->config.ovpn_log_path, uid, gid) != 0) {
			RVD_DEBUG_WARN("VPN: Couldn't set the permission for OpenVPN log file '%s'",
						vpn_conn->config.ovpn_log_path);
		}
	}

	return 0;
}

/*
 * parse response from openvpn management socket
 */

static void parse_ovpn_mgm_resp(struct rvc_vpn_conn *vpn_conn, const char *mgm_resp)
{
	char *buffer;
	char *tok, *p;

	char sep[] = "\n";

	buffer = strdup(mgm_resp);
	if (!buffer) {
		RVD_DEBUG_ERR("VPN: Out of memory!");
		return;
	}

	tok = strtok(buffer, sep);
	while (tok != NULL) {
		if (strncmp(tok, OVPN_MGM_RESP_BYTECOUNT, strlen(OVPN_MGM_RESP_BYTECOUNT)) == 0) {
			char bytes[64];

			p = tok + strlen(OVPN_MGM_RESP_BYTECOUNT);

			/* get in bytes */
			get_token_by_char(&p, ',', bytes, sizeof(bytes));
			vpn_conn->curr_bytes_in = strtol(bytes, NULL, 10);

			/* get out bytes */
			get_token_by_char(&p, ',', bytes, sizeof(bytes));
			vpn_conn->curr_bytes_out = strtol(bytes, NULL, 10);
		} else if (strncmp(tok, OVPN_MGM_RESP_STATE, strlen(OVPN_MGM_RESP_STATE)) == 0) {
			char ts_str[32];
			char conn_state[64];

			int i;

			RVD_DEBUG_MSG("VPN: Try parsing OpenVPN management response '%s' for state", tok);

			/* parse state response */
			p = tok + strlen(OVPN_MGM_RESP_STATE);

			get_token_by_char(&p, ',', ts_str, sizeof(ts_str));
			get_token_by_char(&p, ',', conn_state, sizeof(conn_state));
			for (i = 0; g_ovpn_state[i].ovpn_state_str != NULL; i++) {
				if (strcmp(conn_state, g_ovpn_state[i].ovpn_state_str) == 0) {
					vpn_conn->ovpn_state = g_ovpn_state[i].ovpn_state;
					break;
				}
			}

			if (vpn_conn->ovpn_state == OVPN_STATE_CONNECTED) {
				char desc[128];

				get_token_by_char(&p, ',', desc, sizeof(desc));
				get_token_by_char(&p, ',', vpn_conn->tun_ip, sizeof(vpn_conn->tun_ip));

				vpn_conn->connected_tm = strtol(ts_str, NULL, 10);
			}
		}
		tok = strtok(NULL, sep);
	}

	free(buffer);
}

/*
 * get connection state from openvpn management socket
 */

static int get_vpn_conn_state(struct rvc_vpn_conn *vpn_conn)
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
	struct rvc_vpn_conn *vpn_conn = (struct rvc_vpn_conn *) p;

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

static int start_single_conn(struct rvc_vpn_conn *vpn_conn)
{
	rvd_vpnconn_mgr_t *vpnconn_mgr = vpn_conn->vpnconn_mgr;
	int conf_load_status;

	/* get load status of openvpn configuration */
	conf_load_status = vpn_conn->config.load_status & OVPN_STATUS_LOADED;
	if (!conf_load_status) {
		RVD_DEBUG_ERR("VPN: Unloaded VPN configuration with name '%s'", vpn_conn->config.name);
		return RVD_RESP_WRONG_PERMISSION;
	}

	/* check openvpn binary */
	if (check_ovpn_binary(vpnconn_mgr->c->opt.ovpn_bin_path, vpnconn_mgr->c->opt.ovpn_root_check) != 0) {
		RVD_DEBUG_ERR("VPN: Failed to check openvpn binary availability.");
		return RVD_RESP_ERR_INVALID_OVPN_BIN;
	}

	/* set connection state */
	vpn_conn->conn_state = RVD_CONN_STATE_CONNECTING;

	/* set end flag as false */
	vpn_conn->conn_cancel = false;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_conn, NULL, start_vpn_conn, (void *) vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return RVD_RESP_UNKNOWN_ERR;
	}

	return RVD_RESP_OK;
}

/*
 * start all VPN connections
 */

static void start_all_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTED)
			start_single_conn(vpn_conn);

		vpn_conn = vpn_conn->next;
	}
}

/*
 * connect to rvd vpn servers
 */

int rvd_vpnconn_connect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvc_vpn_conn *vpn_conn;

	/* if connection name is 'all', try start all connections */
	if (strcmp(conn_name, "all") == 0) {
		RVD_DEBUG_MSG("VPN: Try to up all VPN connections");

		start_all_conns(vpnconn_mgr);
		return RVD_RESP_OK;
	}

	RVD_DEBUG_MSG("VPN: Try to connect a VPN with name '%s'", conn_name);

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn)
		return RVD_RESP_CONN_NOT_FOUND;

	/* start VPN connection */
	return start_single_conn(vpn_conn);
}

/*
 * stop single VPN connection
 */

static void stop_single_conn(struct rvc_vpn_conn *vpn_conn)
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

	/* update total bytes */
	vpn_conn->total_bytes_in += vpn_conn->curr_bytes_in;
	vpn_conn->total_bytes_out += vpn_conn->curr_bytes_out;

	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_disconn, NULL, stop_vpn_conn, (void *) vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * stop all VPN connections
 */

static void stop_all_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

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
	struct rvc_vpn_conn *vpn_conn;

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
 * VPN reconnection thread
 */

static void *reconnect_vpn_conn(void *p)
{
	struct rvc_vpn_conn *vpn_conn = (struct rvc_vpn_conn *) p;

	RVD_DEBUG_MSG("VPN: Reconnecting VPN connection with name '%s'", vpn_conn->config.name);

	/* stop the connection */
	vpn_conn->conn_cancel = true;
	if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED) {
		if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTING)
			pthread_join(vpn_conn->pt_disconn, NULL);
		else
			stop_vpn_conn((void *)vpn_conn);
	}

	/* start the connection */
	start_single_conn(p);

	return 0;
}

/*
 * reconnect single VPN connection
 */

static void reconnect_single_conn(struct rvc_vpn_conn *vpn_conn)
{
	/* create thread to start vpn connection */
	if (pthread_create(&vpn_conn->pt_reconn, NULL, reconnect_vpn_conn, (void *) vpn_conn) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't create thread to start VPN connection with name '%s'", vpn_conn->config.name);
		return;
	}
}

/*
 * reconnect all VPN connections
 */

static void reconnect_all_conns(rvd_vpnconn_mgr_t *vpnconn_mgr)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

	while (vpn_conn) {
		reconnect_single_conn(vpn_conn);
		vpn_conn = vpn_conn->next;
	}
}

/*
 * reconnect VPN connection
 */

void rvd_vpnconn_reconnect(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	struct rvc_vpn_conn *vpn_conn;

	RVD_DEBUG_MSG("VPN: Try to reconnect a VPN with name '%s'", conn_name);

	/* if connection name is 'all', try stop all connections */
	if (strcmp(conn_name, "all") == 0) {
		reconnect_all_conns(vpnconn_mgr);
		return;
	}

	/* get configuration item by connection name */
	vpn_conn = get_vpnconn_byname(vpnconn_mgr, conn_name);
	if (!vpn_conn) {
		RVD_DEBUG_ERR("VPN: Couldn't find VPN connection with name '%s'", conn_name);
		return;
	}

	/* stop VPN connection */
	reconnect_single_conn(vpn_conn);

	return;
}

/*
 * parse OpenVPN configuration file
 */

static int
parse_ovpn_config(struct rvc_vpn_conn *vpn_conn, char *vpn_srv_addr, size_t addr_s, int *vpn_srv_port,
		char *vpn_proto, size_t proto_s, int *proto_ver)
{
	FILE *fp;

	const char *remote_prefix = "remote ";
	const char *proto_prefix = "proto ";

	/* open openvpn configuration file */
	fp = fopen(vpn_conn->config.ovpn_profile_path, "r");
	if (!fp) {
		RVD_DEBUG_ERR("VPN: Could not open OpenVPN configuration file '%s' for reading", vpn_conn->config.ovpn_profile_path);
		return -1;
	}

	while (1) {
		char *buf = NULL;
		size_t buf_size = 0;
		ssize_t buf_len;

		char *p;
		char sep = ' ';

		buf_len = getline(&buf, &buf_size, fp);
		if (buf_len < 0)
			break;

		p = buf;
		if (strncmp(p, remote_prefix, strlen(remote_prefix)) == 0) {
			char port_str[32];

			get_token_by_char(&p, sep, NULL, -1);
			get_token_by_char(&p, sep, vpn_srv_addr, addr_s);
			get_token_by_char(&p, sep, port_str, sizeof(port_str));

			*vpn_srv_port = (int)strtol(port_str, NULL, 10);
		} else if (strncmp(p, proto_prefix, strlen(proto_prefix)) == 0) {
			get_token_by_char(&p, sep, NULL, -1);
			get_token_by_char(&p, sep, vpn_proto, proto_s);

			if (strcmp(vpn_proto, "udp6") == 0 || strcmp(vpn_proto, "tcp6") == 0)
				*proto_ver = 6;
			else
				*proto_ver = 4;
		}
		free(buf);
	}
	fclose(fp);

	return 0;
}

/*
 * get status of single connection
 */

static void get_single_conn_status(struct rvc_vpn_conn *vpn_conn, bool json_format, char **status_str)
{
	char *ret_str;

	char pre_exec_status[64];
	char pre_exec_interval[64];
	char conf_load_status[64];

	char vpn_srv_addr[RVD_MAX_HNAME_LEN];
	int vpn_srv_port;
	char vpn_proto[RVD_MAX_PROTOSTR_LEN];

	int proto_ver = OVPN_PROTO_VERSION_4;

	char connected_time[RVD_MAX_DATETIME_LEN];
	int netmask;

	long total_bytes_in, total_bytes_out;
	time_t ts = time(NULL);

	/* parse OpenVPN configuration */
	if (parse_ovpn_config(vpn_conn, vpn_srv_addr, sizeof(vpn_srv_addr), &vpn_srv_port,
			vpn_proto, sizeof(vpn_proto), &proto_ver) != 0) {
		RVD_DEBUG_WARN("VPN: Could not parse OpenVPN configuration file '%s'", vpn_conn->config.ovpn_profile_path);
	}
	netmask = proto_ver == OVPN_PROTO_VERSION_4 ? 32 : 128;

	/* calculate total in-bytes and out-bytes */
	if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED) {
		total_bytes_in = vpn_conn->total_bytes_in + vpn_conn->curr_bytes_in;
		total_bytes_out = vpn_conn->total_bytes_out + vpn_conn->curr_bytes_out;
	} else {
		total_bytes_in = vpn_conn->total_bytes_in;
		total_bytes_out = vpn_conn->total_bytes_out;
	}

	/* set pre-exec status */
	pre_exec_status[0] = pre_exec_interval[0] = '\0';
	if (strlen(vpn_conn->config.pre_exec_cmd) > 0) {
		if (vpn_conn->config.pre_exec_ts > 0)
			snprintf(pre_exec_status, sizeof(pre_exec_status), "%s [%d]",
				vpn_conn->config.pre_exec_status == 0 ? "SUCCESSFUL" : "FAILED",
				vpn_conn->config.pre_exec_status);

		if (vpn_conn->config.pre_exec_interval > 0)
			snprintf(pre_exec_interval, sizeof(pre_exec_interval), "%d (seconds)",
				vpn_conn->config.pre_exec_interval);
		else
			snprintf(pre_exec_interval, sizeof(pre_exec_interval), "none");
	}

	/* set config loading status */
	conf_load_status[0] = '\0';
	if (vpn_conn->config.load_status == OVPN_STATUS_NOT_LOADED)
		strlcpy(conf_load_status, "Not Loaded", sizeof(conf_load_status));
	else if (vpn_conn->config.load_status == OVPN_STATUS_INVALID_PERMISSION)
		strlcpy(conf_load_status, "Invalid permission", sizeof(conf_load_status));
	else {
		if (vpn_conn->config.load_status & OVPN_STATUS_HAVE_NOC)
			strlcpy(conf_load_status, "NOC configuration exists", sizeof(conf_load_status));
		else
			strlcpy(conf_load_status, "No NOC configuration exists", sizeof(conf_load_status));
	}

	/* get connected time */
	memset(connected_time, 0, sizeof(connected_time));
	if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED)
		convert_tt_to_str(vpn_conn->connected_tm, connected_time, sizeof(connected_time));

	RVD_DEBUG_MSG("VPN: Getting status of VPN connection with name '%s'", vpn_conn->config.name);

	if (json_format) {
		rvd_json_object_t conn_status_objs[] = {
			{"name", RVD_JTYPE_STR, vpn_conn->config.name, 0, false, NULL},
			{"profile", RVD_JTYPE_STR, (void *)vpn_conn->config.ovpn_profile_path, 0, false, NULL},
			{"autoConnect", RVD_JTYPE_BOOL, &vpn_conn->config.auto_connect, 0, false, NULL},

			{"endpointIp", RVD_JTYPE_OBJ, NULL, 0, false, NULL},
			{"address", RVD_JTYPE_STR, vpn_srv_addr, 0, false, "endpointIp"},
			{"netmask", RVD_JTYPE_INT, &netmask, 0, false, "endpointIp"},

			{"assignedIp", RVD_JTYPE_OBJ, NULL, 0, false, NULL},
			{"address", RVD_JTYPE_STR, vpn_conn->tun_ip, 0, false, "assignedIp"},
			{"netmask", RVD_JTYPE_INT, &netmask, 0, false, "assignedIp"},

			{"port", RVD_JTYPE_INT, &vpn_srv_port, 0, false, NULL},
			{"protocol", RVD_JTYPE_STR, vpn_proto, 0, false, NULL},
			{"ipVersion", RVD_JTYPE_INT, &proto_ver, 0, false, NULL},

			{"RvdConnectionStatus", RVD_JTYPE_OBJ, NULL, 0, false, NULL},
			{"state", RVD_JTYPE_STR, g_rvd_state[vpn_conn->conn_state].state_str, 0, false, "RvdConnectionStatus"},
			{"ovpnState", RVD_JTYPE_STR, g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str, 0, false, "RvdConnectionStatus"},
			{"connectionTime", RVD_JTYPE_STR, connected_time, 0, false, "RvdConnectionStatus"},
			{"netIn", RVD_JTYPE_INT64, &vpn_conn->curr_bytes_in, 0, false, "RvdConnectionStatus"},
			{"netOut", RVD_JTYPE_INT64, &vpn_conn->curr_bytes_out, 0, false, "RvdConnectionStatus"},

			{"RvdPreExec", RVD_JTYPE_OBJ, NULL, 0, false, NULL},
			{"command", RVD_JTYPE_STR, vpn_conn->config.pre_exec_cmd, 0, false, "RvdPreExec"},
			{"interval", RVD_JTYPE_INT, &vpn_conn->config.pre_exec_interval, 0, false, "RvdPreExec"},
			{"userId", RVD_JTYPE_INT, &vpn_conn->config.pre_exec_uid, 0, false, "RvdPreExec"},
			{"returnCode", RVD_JTYPE_INT, &vpn_conn->config.pre_exec_status, 0, false, "RvdPreExec"}
		};

		/* create json object */
		if (rvd_json_build(conn_status_objs, sizeof(conn_status_objs) / sizeof(rvd_json_object_t), &ret_str) != 0)
			return;
	} else {
		char status_buffer[RVD_MAX_CONN_STATUS_LEN];

		/* set status buffer by plain format */
		if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED)
			snprintf(status_buffer, sizeof(status_buffer), "name: %s\n"
				"\tconfig-status: %s\n"
				"\tprofile: %s\n"
				"\tstatus: %s\n"
				"\topenvpn-status: %s\n"
				"\tin-total: %lu\n"
				"\tout-total: %lu\n"
				"\tconnected-time: %s\n"
				"\tin-current: %lu\n"
				"\tout-current: %lu\n"
				"\ttimestamp: %lu\n"
				"\tauto-connect: %s\n"
				"\tpre-exec-cmd: %s\n"
				"\tpre-exec-status: %s\n"
				"\tpre-exec-interval: %s\n",
				vpn_conn->config.name,
				conf_load_status,
				vpn_conn->config.ovpn_profile_path,
				g_rvd_state[vpn_conn->conn_state].state_str,
				g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str,
				total_bytes_in, total_bytes_out,
				connected_time,
				vpn_conn->curr_bytes_in, vpn_conn->curr_bytes_out,
				ts,
				vpn_conn->config.auto_connect ? "Enabled" : "Disabled",
				vpn_conn->config.pre_exec_cmd,
				pre_exec_status,
				pre_exec_interval);
		else {
			if (vpn_conn->config.load_status & OVPN_STATUS_LOADED) {
				snprintf(status_buffer, sizeof(status_buffer), "name: %s\n"
					"\tconfig-status: %s\n"
					"\tprofile: %s\n"
					"\tstatus: %s\n"
					"\topenvpn-status: %s\n"
					"\tin-total: %lu\n"
					"\tout-total: %lu\n"
					"\ttimestamp: %lu\n"
					"\tauto-connect: %s\n"
					"\tpre-exec-cmd: %s\n"
					"\tpre-exec-status: %s\n"
					"\tpre-exec-interval: %s\n",
					vpn_conn->config.name,
					conf_load_status,
					vpn_conn->config.ovpn_profile_path,
					g_rvd_state[vpn_conn->conn_state].state_str,
					g_ovpn_state[vpn_conn->ovpn_state].ovpn_state_str,
					total_bytes_in, total_bytes_out,
					ts,
					vpn_conn->config.auto_connect ? "Enabled" : "Disabled",
					vpn_conn->config.pre_exec_cmd,
					pre_exec_status,
					pre_exec_interval);
			} else {
				snprintf(status_buffer, sizeof(status_buffer), "name: %s\n"
					"\tconfig-status: %s\n"
					"\tprofile: %s\n",
					vpn_conn->config.name,
					conf_load_status,
					vpn_conn->config.ovpn_profile_path);
			}
		}

		/* allocate buffer for ret_str */
		ret_str = strdup(status_buffer);
	}

	*status_str = ret_str;
}

/*
 * get status of all connections
 */

static void get_all_conn_status(rvd_vpnconn_mgr_t *vpnconn_mgr, bool json_format, char **status_str)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;
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
		if (vpnconn_mgr->vpn_conns_count == 0) {
			char err_str[128];

			/* set error string */
			snprintf(err_str, sizeof(err_str), "no VPNs found in '%s'",
							vpnconn_mgr->c->opt.vpn_config_dir);
			*status_str = strdup(err_str);

			return;
		}

		while (vpn_conn) {
			char *conn_status_str = NULL;
			size_t size;

			/* get single connection status */
			get_single_conn_status(vpn_conn, false, &conn_status_str);
			if (conn_status_str) {
				size_t len = ret_str ? strlen(ret_str) : 0;

				/* allocate and copy buffer */
				size = len + strlen(conn_status_str) + 1;
				ret_str = realloc(ret_str, size);
				if (ret_str)
					strlcpy(&ret_str[len], conn_status_str, size - len);

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
	struct rvc_vpn_conn *vpn_conn;

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
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

	/* set end flag for each vpn connection */
	while (vpn_conn) {
		/* stop all VPN connection */
		vpn_conn->conn_cancel = true;
		if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED) {
			if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTING)
				pthread_join(vpn_conn->pt_disconn, NULL);
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
 * read configuration from directory
 */

static void read_config(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *dir_path, bool load_status)
{
	DIR *dir;
	struct dirent *dp;

	if (load_status) {
		RVD_DEBUG_MSG("VPN: Loading VPN configurations from %s", dir_path);
	}

	/* open config directory */
	dir = opendir(dir_path);
	if (!dir) {
		RVD_DEBUG_ERR("VPN: Couldn't open directory '%s'", dir_path);
		return;
	}

	while ((dp = readdir(dir)) != NULL) {
		char conf_name[RVD_MAX_FILE_NAME];
		size_t conf_name_len;

		const char *p;

		struct rvc_vpn_config vpn_config;

		/* check whether the file is ovpn file */
		p = strstr(dp->d_name, OVPN_CONFIG_EXTENSION);
		if (!p || strlen(p) != strlen(OVPN_CONFIG_EXTENSION))
			continue;

		/* set conf name */
		conf_name_len = strlen(dp->d_name) - strlen(OVPN_CONFIG_EXTENSION);
		if (conf_name_len <= 0)
			continue;

		strncpy(conf_name, dp->d_name, conf_name_len);
		conf_name[conf_name_len] = '\0';

		/* check whether configuration is exist with given name */
		if (!load_status && rvd_vpnconn_get_byname(vpnconn_mgr, conf_name))
			continue;

		/* parse configuration file */
		if (rvc_read_vpn_config(dir_path, conf_name, &vpn_config) == 0) {
			if (!load_status)
				vpn_config.load_status = OVPN_STATUS_NOT_LOADED;

			/* set allowed UID info */
			vpn_config.pre_exec_uid = vpnconn_mgr->c->opt.allowed_uid;

			/* add VPN connection */
			add_vpn_conn(vpnconn_mgr, &vpn_config);
		}
	}

	/* close directory */
	closedir(dir);
}

/*
 * get VPN connection by name
 */

struct rvc_vpn_conn *rvd_vpnconn_get_byname(rvd_vpnconn_mgr_t *vpnconn_mgr, const char *conn_name)
{
	return get_vpnconn_byname(vpnconn_mgr, conn_name);
}

/*
 * VPN connection monitoring thread
 */

static void *monitor_vpn_conn(void *p)
{
	struct rvc_vpn_conn *vpn_conn = (struct rvc_vpn_conn *) p;

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

		/* check if connected and run pre-exec-command by interval */
		if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED &&
			vpn_conn->config.pre_exec_interval > 0) {
			time_t curr_ts = time(NULL);

			if (curr_ts - vpn_conn->config.pre_exec_ts > vpn_conn->config.pre_exec_interval) {
				if (run_preconn_cmd(vpn_conn) != 0) {
					RVD_DEBUG_ERR("VPN: Failed exit code from running pre-connect command");
				}
			}
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
			usleep(50 * 1000);
			continue;
		}

		/* get respnose */
		memset(ovpn_mgm_resp, 0, sizeof(ovpn_mgm_resp));
		ret = recv(vpn_conn->ovpn_mgm_sock, ovpn_mgm_resp, sizeof(ovpn_mgm_resp), 0);
		if (ret > 0) {
			/* parse openvpn response */
			parse_ovpn_mgm_resp(vpn_conn, ovpn_mgm_resp);

			/* check if openvpn connection has abnormally disconnected */
			if (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED
				&& vpn_conn->ovpn_state != OVPN_STATE_CONNECTED) {
				RVD_DEBUG_WARN("VPN: Detected that OpenVPN connection was abnormally terminated.");
				vpn_conn->conn_state = RVD_CONN_STATE_RECONNECTING;

				vpn_conn->tun_ip[0] = '\0';
			} else if (vpn_conn->conn_state == RVD_CONN_STATE_RECONNECTING
				&& vpn_conn->ovpn_state == OVPN_STATE_CONNECTED) {
				RVD_DEBUG_MSG("VPN: OpenVPN connection was recovered after abnormal termination.");
				vpn_conn->conn_state = RVD_CONN_STATE_CONNECTED;
			}
		} else if (ret == 0)
			failed = true;
		else {
			if (errno != EWOULDBLOCK)
				failed = true;
		}

		/* stop VPN connection */
		if (failed) {
			if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED &&
				vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTING) {
				vpn_conn->conn_state = RVD_CONN_STATE_DISCONNECTING;
				RVD_DEBUG_WARN("VPN: Detected that OpenVPN process was abnormally terminated.");
				stop_vpn_conn(vpn_conn);
			}
			close_ovpn_mgm_sock(vpn_conn);
		}
	}

	RVD_DEBUG_MSG("VPN: VPN connection monitoring thread with name '%s' stopped", vpn_conn->config.name);

	return 0;
}

/*
 * enable/disable script security
 */

void rvd_vpnconn_enable_script_sec(rvd_vpnconn_mgr_t *vpnconn_mgr, bool enable_script_sec)
{
	struct rvc_vpn_conn *vpn_conn = vpnconn_mgr->vpn_conns;

	RVD_DEBUG_MSG("VPN: %s script security", enable_script_sec ? "Enable" : "Disable");

	while (vpn_conn) {
		vpn_conn->enable_script_sec = enable_script_sec;
		vpn_conn = vpn_conn->next;
	}
}

/*
 * thread for reading VPN configurations
 */

static void *read_vpn_configs(void *p)
{
	rvd_vpnconn_mgr_t *vpnconn_mgr = (rvd_vpnconn_mgr_t *) p;
	rvd_ctx_t *c = vpnconn_mgr->c;

	RVD_DEBUG_MSG("VPN: Starting VPN configurations reading thread");

	while (!vpnconn_mgr->end_flag) {
		read_config(vpnconn_mgr, c->opt.vpn_config_dir, false);
		sleep(1);
	}

	return 0;
}

/*
 * initialize rvd VPN connection manager
 */

int rvd_vpnconn_mgr_init(struct rvd_ctx *c)
{
	rvd_vpnconn_mgr_t *vpnconn_mgr = &c->vpnconn_mgr;
	struct rvc_vpn_conn *vpn_conn;

	RVD_DEBUG_MSG("VPN: Initializing VPN connection manager");

	/* set context object */
	vpnconn_mgr->c = c;

	/* initialize mutex */
	pthread_mutex_init(&vpnconn_mgr->conn_mt, NULL);

	/* set configuration path */
	read_config(vpnconn_mgr, c->opt.vpn_config_dir, true);

	/* set init status */
	vpnconn_mgr->init_flag = true;

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
			return -1;
		}

		vpn_conn = vpn_conn->next;
	}

	/* create thread for reading VPN configurations */
	if (pthread_create(&vpnconn_mgr->pt_read_conf, NULL, read_vpn_configs, (void *) vpnconn_mgr) != 0) {
		RVD_DEBUG_ERR("VPN: Couldn't read VPN configuration list thread");
		return -1;
	}

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
