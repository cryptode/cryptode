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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include "common.h"
#include "log.h"
#include "util.h"

#include "rvd.h"

/*
 * create listen socket
 */

static int create_listen_socket(rvd_ctx_opt_t *op)
{
	int listen_sock;
	struct sockaddr_un listen_addr;

	/* create unix domain socket */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		RVD_DEBUG_ERR("CMD: Couldn't create UNIX domain socket(err:%d)", errno);
		return -1;
	}

	/* set listen address */
	memset(&listen_addr, 0, sizeof(struct sockaddr_un));
	listen_addr.sun_family = AF_UNIX;
	strlcpy(listen_addr.sun_path, RVD_LISTEN_SOCK_PATH, sizeof(listen_addr.sun_path));

	/* remove socket at first */
	remove(RVD_LISTEN_SOCK_PATH);

	/* bind and listen socket */
	if (bind(listen_sock, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_un)) != 0) {
		RVD_DEBUG_ERR("CMD: Couldn't bind on unix domain socket '%s'(err:%d)", RVD_LISTEN_SOCK_PATH, errno);
		close(listen_sock);

		return -1;
	}

	if (listen(listen_sock, 5) != 0) {
		RVD_DEBUG_ERR("CMD: Couldn't listen on unix domain socket '%s'(err:%d)", RVD_LISTEN_SOCK_PATH, errno);
		close(listen_sock);

		return -1;
	}

	/* set permission of socket */
	if (op->restrict_cmd_sock) {
		chown(RVD_LISTEN_SOCK_PATH, op->allowed_uid, 0);
		chmod(RVD_LISTEN_SOCK_PATH, S_IRUSR | S_IWUSR);
	} else
		chmod(RVD_LISTEN_SOCK_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	return listen_sock;
}

/*
 * send command response
 */

struct rvd_resp_errs {
	enum RVD_RESP_CODE resp_code;
	const char *err_msg;
} g_rvd_resp_errs[] = {
	{RVD_RESP_OK, "Success"},
	{RVD_RESP_INVALID_CMD, "Invalid command"},
	{RVD_RESP_NO_MEMORY, "Insufficient memory"},
	{RVD_RESP_EMPTY_LIST, "Empty List"},
	{RVD_RESP_CONN_NOT_FOUND, "Connection not found"},
	{RVD_RESP_CONN_ALREADY_CONNECTED, "Already connected"},
	{RVD_RESP_CONN_ALREADY_DISCONNECTED, "Already disconnected"},
	{RVD_RESP_CONN_IN_PROGRESS, "Connection/Disconnection is in progress"},
	{RVD_RESP_UNKNOWN_ERR, NULL},
};

static void send_cmd_response(int clnt_sock, int resp_code, const char *buffer, bool use_json)
{
	char *resp_buffer = NULL;

	RVD_DEBUG_MSG("CMD: Sending response");

	if (!use_json) {
		int i;
		const char *err_buf = "Unknown Error";

		/* get error message by errcode */
		for (i = 0; g_rvd_resp_errs[i].err_msg != NULL; i++) {
			if ((int)g_rvd_resp_errs[i].resp_code == resp_code) {
				err_buf = g_rvd_resp_errs[i].err_msg;
				break;
			}
		}

		if (resp_code == RVD_RESP_OK)
			resp_buffer = strdup(buffer ? buffer : err_buf);
		else
			resp_buffer = strdup(err_buf);
	} else {
		rvd_json_object_t resp_jobjs[] = {
			{"code", RVD_JTYPE_INT, &resp_code, 0, false, NULL},
			{"data", RVD_JTYPE_OBJ, (void *)buffer, 0, false, NULL}
		};

		rvd_json_build(resp_jobjs, sizeof(resp_jobjs) / sizeof(rvd_json_object_t), &resp_buffer);
	}

	if (!resp_buffer) {
		RVD_DEBUG_ERR("CMD: Coudln't send response. Out of memory");
	}

	RVD_DEBUG_MSG("CMD: Response string is \n'%s'\n(code: %d)", resp_buffer, resp_code);

	if (send(clnt_sock, resp_buffer, strlen(resp_buffer), 0) <= 0) {
		RVD_DEBUG_ERR("CMD: Failed sending response(err: %d)", errno);
	}

	/* free response buffer */
	free(resp_buffer);
}

/*
 * process 'connect' command
 */

static int process_cmd_connect(rvd_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	RVD_DEBUG_MSG("CMD: Processing 'connect' command");

	/* check connection name */
	if (!conn_name) {
		RVD_DEBUG_ERR("CMD: Missing connection name");
		return RVD_RESP_INVALID_CMD;
	}

	/* check connection status */
	if (strcmp(conn_name, "all") != 0) {
		struct rvd_vpnconn *vpn_conn = rvd_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			RVD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return RVD_RESP_CONN_NOT_FOUND;
		} else if (vpn_conn->conn_state != RVD_CONN_STATE_DISCONNECTED) {
			RVD_DEBUG_ERR("CMD: Connection is already established or is pending", conn_name);
			return (vpn_conn->conn_state == RVD_CONN_STATE_CONNECTED) ? RVD_RESP_CONN_ALREADY_CONNECTED :
				RVD_RESP_CONN_IN_PROGRESS;
		}
	}

	/* connect to rvd servers */
	rvd_vpnconn_connect(&cmd_proc->c->vpnconn_mgr, conn_name);

	/* get connection status */
	rvd_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return RVD_RESP_OK;
}

/*
 * process 'disconnect' command
 */

static int process_cmd_disconnect(rvd_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	RVD_DEBUG_MSG("CMD: Processing 'disconnect' command");

	/* check connection name */
	if (!conn_name) {
		RVD_DEBUG_ERR("CMD: Missing connection name");
		return RVD_RESP_INVALID_CMD;
	}

	/* check connection status */
	if (strcmp(conn_name, "all") != 0) {
		struct rvd_vpnconn *vpn_conn = rvd_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			RVD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return RVD_RESP_CONN_NOT_FOUND;
		} else if (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTED
				|| vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTING) {
			RVD_DEBUG_ERR("CMD: Connection is already disconnected or is pending", conn_name);
			return (vpn_conn->conn_state == RVD_CONN_STATE_DISCONNECTED) ? RVD_RESP_CONN_ALREADY_DISCONNECTED :
				RVD_RESP_CONN_IN_PROGRESS;
		}
	}

	/* disconnect from rvd servers */
	rvd_vpnconn_disconnect(&cmd_proc->c->vpnconn_mgr, conn_name);

	/* get connection status */
	rvd_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return RVD_RESP_OK;
}

/*
 * process 'status' command
 */

static int process_cmd_status(rvd_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	RVD_DEBUG_MSG("CMD: Processing 'status' command");

	/* check connection name */
	if (!conn_name) {
		RVD_DEBUG_ERR("CMD: Missing connection name");
		return RVD_RESP_INVALID_CMD;
	}

	/* check connection is exist */
	if (strcmp(conn_name, "all") != 0) {
		struct rvd_vpnconn *vpn_conn = rvd_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			RVD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return RVD_RESP_CONN_NOT_FOUND;
		}
	}

	/* get status for vpn connection */
	rvd_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return RVD_RESP_OK;
}

/*
 * process 'script-security' command
 */

static int process_cmd_script_security(rvd_cmd_proc_t *cmd_proc, const char *param)
{
	bool enable_script_security = false;

	RVD_DEBUG_MSG("CMD: Processing 'script-security' command");

	if (strcmp(param, "enable") == 0)
		enable_script_security = true;
	else if (strcmp(param, "disable") == 0)
		enable_script_security = false;
	else {
		RVD_DEBUG_ERR("CMD: Unknown command parameter '%s'", param);
		return RVD_RESP_INVALID_CMD;
	}

	/* enable/disable script security */
	rvd_vpnconn_enable_script_sec(&cmd_proc->c->vpnconn_mgr, enable_script_security);

	return RVD_RESP_OK;
}

/*
 * process 'get-configdir' command
 */

static int process_cmd_get_confdir(rvd_cmd_proc_t *cmd_proc, char **conf_dir)
{
	RVD_DEBUG_MSG("CMD: Processing 'get_confdir' command");

	/* set configuration directory path */
	*conf_dir = strdup(cmd_proc->c->opt.vpn_config_dir);

	return RVD_RESP_OK;
}

/*
 * process commands
 */

static int process_cmd(rvd_cmd_proc_t *cmd_proc, const char *cmd,
		char **resp_data, bool *json_format)
{
	int cmd_code = RVD_CMD_UNKNOWN;
	char cmd_param[512];

	int resp_code = RVD_RESP_INVALID_CMD;

	rvd_json_object_t cmd_objs[] = {
		{"cmd", RVD_JTYPE_INT, &cmd_code, 0, true, NULL},
		{"json", RVD_JTYPE_BOOL, json_format, 0, false, NULL},
		{"param", RVD_JTYPE_STR, cmd_param, sizeof(cmd_param), false, NULL}
	};

	RVD_DEBUG_MSG("CMD: Received command '%s'", cmd);

	/* parse json command */
	if (rvd_json_parse(cmd, cmd_objs, sizeof(cmd_objs) / sizeof(rvd_json_object_t)) != 0) {
		RVD_DEBUG_ERR("CMD: Couln't parse command '%s'", cmd);
		return RVD_RESP_INVALID_CMD;
	}

	switch (cmd_code) {
	case RVD_CMD_CONNECT:
		resp_code = process_cmd_connect(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case RVD_CMD_DISCONNECT:
		resp_code = process_cmd_disconnect(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case RVD_CMD_STATUS:
		resp_code = process_cmd_status(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case RVD_CMD_SCRIPT_SECURITY:
		resp_code = process_cmd_script_security(cmd_proc, cmd_param);
		break;

	case RVD_CMD_GET_CONFDIR:
		resp_code = process_cmd_get_confdir(cmd_proc, resp_data);
		break;

	default:
		break;
	}

	return resp_code;
}

/*
 * rvd command proc thread
 */

static void *rvd_cmd_proc(void *p)
{
	rvd_cmd_proc_t *cmd_proc = (rvd_cmd_proc_t *) p;

	fd_set fds;
	int max_fd = cmd_proc->listen_sock;

	RVD_DEBUG_MSG("CMD: Starting rvd command processing thread");

	/* set fdset */
	FD_ZERO(&fds);
	FD_SET(max_fd, &fds);

	while (!cmd_proc->end_flag) {
		fd_set tmp_fds;
		struct timeval tv;

		int i, ret;

		/* set temporary fdset */
		memcpy(&tmp_fds, &fds, sizeof(fd_set));

		/* set timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;

		/* I/O polling */
		ret = select(max_fd + 1, &tmp_fds, NULL, NULL, &tv);
		if (ret < 0) {
			RVD_DEBUG_ERR("CMD: Failed async select I/O multiplexing.(err:%d) Exiting...", errno);
			exit(-1);
		}

		for (i = 0; i <= max_fd; i++) {
			/* check for event */
			if (!FD_ISSET(i, &tmp_fds))
				continue;

			if (i == cmd_proc->listen_sock) {
				int clnt_fd = -1;

				do {
					clnt_fd = accept(cmd_proc->listen_sock, NULL, NULL);
					if (clnt_fd < 0 && errno != EWOULDBLOCK) {
						RVD_DEBUG_ERR("CMD: Failed accepting connection request.(err:%d)", errno);
						break;
					}

					if (clnt_fd > 0) {
						/* add client fd into fdset */
						FD_SET(clnt_fd, &fds);
						if (clnt_fd > max_fd)
							max_fd = clnt_fd;
					}
				} while (clnt_fd == -1);
			} else {
				do {
					char cmd_buf[RVD_MAX_CMD_LEN + 1];
					bool failed = false;

					/* get command */
					memset(cmd_buf, 0, sizeof(cmd_buf));
					ret = recv(i, cmd_buf, RVD_MAX_CMD_LEN, 0);
					if (ret > 0) {
						char *resp_data = NULL;
						int resp_code;

						bool json_format = false;

						/* parse and process command */
						resp_code = process_cmd(cmd_proc, cmd_buf, &resp_data, &json_format);

						/* send response */
						send_cmd_response(i, resp_code, resp_data, json_format);

						/* free response data */
						if (resp_data)
							free(resp_data);

						break;
					}
					else if (ret == 0)
						failed = true;
					else {
						if (errno != EWOULDBLOCK)
							failed = true;
					}

					if (failed) {
						/* remove client socket from fdset and close it */
						FD_CLR(i, &fds);
						close(i);

						if (i == max_fd)
							max_fd = get_max_fd(i, &fds);

						break;
					}
				} while (1);
			}
		}
	}

	RVD_DEBUG_MSG("CMD: rvd command processing thread stopped");

	return 0;
}

/*
 * initialize command proc
 */

int rvd_cmd_proc_init(struct rvd_ctx *c)
{
	rvd_cmd_proc_t *cmd_proc = &c->cmd_proc;
	int listen_sock;

	RVD_DEBUG_MSG("CMD: Initializing rvd command processor");

	/* init command processor object */
	memset(cmd_proc, 0, sizeof(rvd_cmd_proc_t));

	/* create listening unix domain socket */
	listen_sock = create_listen_socket(&c->opt);
	if (listen_sock < 0)
		return -1;

	/* set socket as non blocking mode */
	if (set_non_blocking(listen_sock) != 0) {
		RVD_DEBUG_ERR("CMD: Couldn't set socket in non-blocking mode(err:%d)", errno);
		close(listen_sock);

		return -1;
	}

	/* create thread for command process */
	cmd_proc->c = c;
	if (pthread_create(&cmd_proc->pt_cmd_proc, NULL, rvd_cmd_proc, (void *) cmd_proc) != 0) {
		RVD_DEBUG_ERR("CMD: Couldn't create command processor thread(err:%d)", errno);
		close(listen_sock);

		return -1;
	}

	/* set listen socket */
	cmd_proc->listen_sock = listen_sock;

	/* initialize mutex */
	pthread_mutex_init(&cmd_proc->cmd_mt, NULL);

	/* set init flag */
	cmd_proc->init_flag = true;

	return 0;
}

/*
 * finalize command proc
 */

void rvd_cmd_proc_finalize(rvd_cmd_proc_t *cmd_proc)
{
	/* check init flag */
	if (!cmd_proc->init_flag)
		return;

	RVD_DEBUG_MSG("CMD: Finalizing rvd command processor");

	/* set end flag */
	cmd_proc->end_flag = true;

	/* wait until proc thread has finished */
	pthread_join(cmd_proc->pt_cmd_proc, NULL);

	/* destroy mutex */
	pthread_mutex_destroy(&cmd_proc->cmd_mt);

	/* close listen socket */
	close(cmd_proc->listen_sock);

	/* remove socket */
	remove(RVD_LISTEN_SOCK_PATH);
}
