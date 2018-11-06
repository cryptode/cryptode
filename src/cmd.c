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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#include "cryptoded.h"

/*
 * create listen socket
 */

static int create_listen_socket(cod_options_t *op)
{
	int listen_sock;
	struct sockaddr_un listen_addr;

	int ret = 0;

	/* create unix domain socket */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		COD_DEBUG_ERR("CMD: Couldn't create UNIX domain socket(err:%d)", errno);
		return -1;
	}

	/* set listen address */
	memset(&listen_addr, 0, sizeof(struct sockaddr_un));
	listen_addr.sun_family = AF_UNIX;
	strlcpy(listen_addr.sun_path, COD_LISTEN_SOCK_PATH, sizeof(listen_addr.sun_path));

	/* remove socket at first */
	unlink(COD_LISTEN_SOCK_PATH);

	/* bind and listen socket */
	if (bind(listen_sock, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_un)) != 0) {
		COD_DEBUG_ERR("CMD: Couldn't bind on unix domain socket '%s'(err:%d)", COD_LISTEN_SOCK_PATH, errno);
		close(listen_sock);

		return -1;
	}

	if (listen(listen_sock, 5) != 0) {
		COD_DEBUG_ERR("CMD: Couldn't listen on unix domain socket '%s'(err:%d)", COD_LISTEN_SOCK_PATH, errno);
		close(listen_sock);

		return -1;
	}

	/* set permission of socket */
	if (op->restrict_cmd_sock && op->allowed_uid > 0) {
		if ((chown(COD_LISTEN_SOCK_PATH, op->allowed_uid, 0) != 0 ||
			 chmod(COD_LISTEN_SOCK_PATH, S_IRUSR | S_IWUSR) != 0))
			ret = -1;
	} else {
		if (chmod(COD_LISTEN_SOCK_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0)
			ret = -1;
	}

	if (ret == -1) {
		COD_DEBUG_ERR("CMD: Couldn't set the permissions for unix domain socket '%s'(err:%d)",
				COD_LISTEN_SOCK_PATH, errno);
		close(listen_sock);
		return -1;
	}

	return listen_sock;
}

/*
 * send command response
 */

struct cod_resp_errs {
	enum COD_RESP_CODE resp_code;
	const char *err_msg;
} g_cod_resp_errs[] = {
	{COD_RESP_OK, "Success"},
	{COD_RESP_INVALID_CMD, "Invalid command"},
	{COD_RESP_NO_MEMORY, "Insufficient memory"},
	{COD_RESP_EMPTY_LIST, "Empty List"},
	{COD_RESP_CONN_NOT_FOUND, "Connection not found"},
	{COD_RESP_CONN_ALREADY_CONNECTED, "Already connected"},
	{COD_RESP_CONN_ALREADY_DISCONNECTED, "Already disconnected"},
	{COD_RESP_CONN_IN_PROGRESS, "Connection/Disconnection is in progress"},
	{COD_RESP_WRONG_PERMISSION, "Wrong permission"},
	{COD_RESP_UNKNOWN_ERR, NULL},
};

static void send_cmd_response(int clnt_sock, int resp_code, const char *buffer, bool use_json)
{
	char *resp_buffer = NULL;
	const char *err_buf = "Unknown Error";
	int i;

	COD_DEBUG_MSG("CMD: Sending response");

	/* get error message by errcode */
	for (i = 0; g_cod_resp_errs[i].err_msg != NULL; i++) {
		if ((int)g_cod_resp_errs[i].resp_code == resp_code) {
			err_buf = g_cod_resp_errs[i].err_msg;
			break;
		}
	}

	if (!use_json) {
		cod_json_object_t resp_jobjs[] = {
			{"code", COD_JTYPE_INT, &resp_code, 0, false, NULL},
			{"data", COD_JTYPE_STR, (void *)(buffer ? buffer : err_buf), 0, false, NULL}
		};

		cod_json_build(resp_jobjs, sizeof(resp_jobjs) / sizeof(cod_json_object_t), &resp_buffer);
	} else {
		cod_json_object_t resp_jobjs[] = {
			{"code", COD_JTYPE_INT, &resp_code, 0, false, NULL},
			{"data", COD_JTYPE_OBJ, (void *)buffer, 0, false, NULL}
		};

		cod_json_build(resp_jobjs, sizeof(resp_jobjs) / sizeof(cod_json_object_t), &resp_buffer);
	}

	if (!resp_buffer) {
		COD_DEBUG_ERR("CMD: Coudln't send response. Out of memory");
		return;
	}

	COD_DEBUG_MSG("CMD: Response string is\n'%s'\n(code: %d)", resp_buffer, resp_code);

	if (send(clnt_sock, resp_buffer, strlen(resp_buffer), 0) <= 0) {
		COD_DEBUG_ERR("CMD: Failed sending response(err: %d)", errno);
	}

	/* free response buffer */
	free(resp_buffer);
}

/*
 * process 'connect' command
 */

static int process_cmd_connect(cod_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	int ret;

	COD_DEBUG_MSG("CMD: Processing 'connect' command");

	/* check connection name */
	if (!conn_name) {
		COD_DEBUG_ERR("CMD: Missing connection name");
		return COD_RESP_INVALID_CMD;
	}

	/* check connection status */
	if (strcmp(conn_name, "all") != 0) {
		struct coc_vpn_conn *vpn_conn = cod_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			COD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return COD_RESP_CONN_NOT_FOUND;
		} else if (vpn_conn->conn_state != COD_CONN_STATE_DISCONNECTED) {
			COD_DEBUG_ERR("CMD: Connection is already established or is pending", conn_name);
			return (vpn_conn->conn_state == COD_CONN_STATE_CONNECTED) ? COD_RESP_CONN_ALREADY_CONNECTED :
				COD_RESP_CONN_IN_PROGRESS;
		}
	}

	/* connect to cod servers */
	ret = cod_vpnconn_connect(&cmd_proc->c->vpnconn_mgr, conn_name);

	/* get connection status */
	cod_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return ret;
}

/*
 * process 'disconnect' command
 */

static int process_cmd_disconnect(cod_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	COD_DEBUG_MSG("CMD: Processing 'disconnect' command");

	/* check connection name */
	if (!conn_name) {
		COD_DEBUG_ERR("CMD: Missing connection name");
		return COD_RESP_INVALID_CMD;
	}

	/* check connection status */
	if (strcmp(conn_name, "all") != 0) {
		struct coc_vpn_conn *vpn_conn = cod_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			COD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return COD_RESP_CONN_NOT_FOUND;
		} else if (vpn_conn->conn_state == COD_CONN_STATE_DISCONNECTED
				|| vpn_conn->conn_state == COD_CONN_STATE_DISCONNECTING) {
			COD_DEBUG_ERR("CMD: Connection is already disconnected or is pending", conn_name);
			return (vpn_conn->conn_state == COD_CONN_STATE_DISCONNECTED) ? COD_RESP_CONN_ALREADY_DISCONNECTED :
				COD_RESP_CONN_IN_PROGRESS;
		}
	}

	/* disconnect from cod servers */
	cod_vpnconn_disconnect(&cmd_proc->c->vpnconn_mgr, conn_name);

	/* get connection status */
	cod_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return COD_RESP_OK;
}

/*
 * process 'reconnect' command
 */

static int process_cmd_reconnect(cod_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	COD_DEBUG_MSG("CMD: Processing 'reconnect' command");

	/* check connection name */
	if (!conn_name) {
		COD_DEBUG_ERR("CMD: Missing connection name");
		return COD_RESP_INVALID_CMD;
	}

	/* check connection status */
	if (strcmp(conn_name, "all") != 0) {
		struct coc_vpn_conn *vpn_conn = cod_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			COD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return COD_RESP_CONN_NOT_FOUND;
		}
	}

	/* reconnect to cryptoded servers */
	cod_vpnconn_reconnect(&cmd_proc->c->vpnconn_mgr, conn_name);

	/* get connection status */
	cod_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return COD_RESP_OK;
}

/*
 * process 'status' command
 */

static int process_cmd_status(cod_cmd_proc_t *cmd_proc, const char *conn_name, bool json_format, char **status_jstr)
{
	COD_DEBUG_MSG("CMD: Processing 'status' command");

	/* check connection name */
	if (!conn_name) {
		COD_DEBUG_ERR("CMD: Missing connection name");
		return COD_RESP_INVALID_CMD;
	}

	/* check connection is exist */
	if (strcmp(conn_name, "all") != 0) {
		struct coc_vpn_conn *vpn_conn = cod_vpnconn_get_byname(&cmd_proc->c->vpnconn_mgr, conn_name);

		if (!vpn_conn) {
			COD_DEBUG_ERR("CMD: Couldn't find VPN connection with name '%s'", conn_name);
			return COD_RESP_CONN_NOT_FOUND;
		}
	}

	/* get status for vpn connection */
	cod_vpnconn_getstatus(&cmd_proc->c->vpnconn_mgr, conn_name, json_format, status_jstr);

	return COD_RESP_OK;
}

/*
 * process 'script-security' command
 */

static int process_cmd_script_security(cod_cmd_proc_t *cmd_proc, const char *param)
{
	bool enable_script_security = false;

	COD_DEBUG_MSG("CMD: Processing 'script-security' command");

	if (strcmp(param, "enable") == 0)
		enable_script_security = true;
	else if (strcmp(param, "disable") == 0)
		enable_script_security = false;
	else {
		COD_DEBUG_ERR("CMD: Unknown command parameter '%s'", param);
		return COD_RESP_INVALID_CMD;
	}

	/* enable/disable script security */
	cod_vpnconn_enable_script_sec(&cmd_proc->c->vpnconn_mgr, enable_script_security);

	return COD_RESP_OK;
}

/*
 * process 'get-configdir' command
 */

static int process_cmd_get_confdir(cod_cmd_proc_t *cmd_proc, char **conf_dir)
{
	COD_DEBUG_MSG("CMD: Processing 'get_confdir' command");

	/* set configuration directory path */
	*conf_dir = strdup(cmd_proc->c->opt.vpn_config_dir);

	return COD_RESP_OK;
}

/*
 * process commands
 */

static int process_cmd(cod_cmd_proc_t *cmd_proc, const char *cmd,
		char **resp_data, bool *json_format)
{
	int cmd_code = COD_CMD_UNKNOWN;
	char cmd_param[512];

	int resp_code = COD_RESP_INVALID_CMD;

	cod_json_object_t cmd_objs[] = {
		{"cmd", COD_JTYPE_INT, &cmd_code, 0, true, NULL},
		{"json", COD_JTYPE_BOOL, json_format, 0, false, NULL},
		{"param", COD_JTYPE_STR, cmd_param, sizeof(cmd_param), false, NULL}
	};

	COD_DEBUG_MSG("CMD: Received command '%s'", cmd);

	/* parse json command */
	if (cod_json_parse(cmd, cmd_objs, sizeof(cmd_objs) / sizeof(cod_json_object_t)) != 0) {
		COD_DEBUG_ERR("CMD: Couln't parse command '%s'", cmd);
		return COD_RESP_INVALID_CMD;
	}

	switch (cmd_code) {
	case COD_CMD_CONNECT:
		resp_code = process_cmd_connect(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case COD_CMD_DISCONNECT:
		resp_code = process_cmd_disconnect(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case COD_CMD_RECONNECT:
		resp_code = process_cmd_reconnect(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case COD_CMD_STATUS:
		resp_code = process_cmd_status(cmd_proc, cmd_param, *json_format, resp_data);
		break;

	case COD_CMD_SCRIPT_SECURITY:
		resp_code = process_cmd_script_security(cmd_proc, cmd_param);
		break;

	case COD_CMD_GET_CONFDIR:
		resp_code = process_cmd_get_confdir(cmd_proc, resp_data);
		break;

	default:
		break;
	}

	return resp_code;
}

/*
 * cryptoded command proc thread
 */

static void *cod_cmd_proc(void *p)
{
	cod_cmd_proc_t *cmd_proc = (cod_cmd_proc_t *) p;

	fd_set fds;
	int max_fd = cmd_proc->listen_sock;

	COD_DEBUG_MSG("CMD: Starting cryptoded command processing thread");

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
			COD_DEBUG_ERR("CMD: Failed async select I/O multiplexing.(err:%d) Exiting...", errno);
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
						COD_DEBUG_ERR("CMD: Failed accepting connection request.(err:%d)", errno);
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
					char cmd_buf[COD_MAX_CMD_LEN + 1];
					bool failed = false;

					/* get command */
					memset(cmd_buf, 0, sizeof(cmd_buf));
					ret = recv(i, cmd_buf, COD_MAX_CMD_LEN, 0);
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

	COD_DEBUG_MSG("CMD: cryptoded command processing thread stopped");

	return 0;
}

/*
 * initialize command proc
 */

int cod_cmd_proc_init(struct cod_ctx *c)
{
	cod_cmd_proc_t *cmd_proc = &c->cmd_proc;
	int listen_sock;

	COD_DEBUG_MSG("CMD: Initializing cryptoded command processor");

	/* init command processor object */
	memset(cmd_proc, 0, sizeof(cod_cmd_proc_t));

	/* create listening unix domain socket */
	listen_sock = create_listen_socket(&c->opt);
	if (listen_sock < 0)
		return -1;

	/* set socket as non blocking mode */
	if (set_non_blocking(listen_sock) != 0) {
		COD_DEBUG_ERR("CMD: Couldn't set socket in non-blocking mode(err:%d)", errno);
		close(listen_sock);

		return -1;
	}

	/* create thread for command process */
	cmd_proc->c = c;
	if (pthread_create(&cmd_proc->pt_cmd_proc, NULL, cod_cmd_proc, (void *) cmd_proc) != 0) {
		COD_DEBUG_ERR("CMD: Couldn't create command processor thread(err:%d)", errno);
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

void cod_cmd_proc_finalize(cod_cmd_proc_t *cmd_proc)
{
	/* check init flag */
	if (!cmd_proc->init_flag)
		return;

	COD_DEBUG_MSG("CMD: Finalizing cryptoded command processor");

	/* set end flag */
	cmd_proc->end_flag = true;

	/* wait until proc thread has finished */
	pthread_join(cmd_proc->pt_cmd_proc, NULL);

	/* destroy mutex */
	pthread_mutex_destroy(&cmd_proc->cmd_mt);

	/* close listen socket */
	close(cmd_proc->listen_sock);

	/* remove socket */
	unlink(COD_LISTEN_SOCK_PATH);
}
