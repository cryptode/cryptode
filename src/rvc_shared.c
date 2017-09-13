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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <json-c/json.h>

#include "common.h"
#include "util.h"

#include "rvc_shared.h"

/* static global variables */
static int g_sock;

static char g_cmd[RVD_MAX_CMD_LEN + 1];
static char g_resp[RVD_MAX_RESP_LEN + 1];

/*
 * print help message
 */

void print_help(void)
{
	printf("usage: rvc <options>\n"
		"  options:\n"
		"    list [--json]\t\t\t\tshow list of VPN connections\n"
		"    connect <all|connection name> [--json]\tconnect to a VPN with given name\n"
		"    disconnect <all|connection name> [--json]\tdisconnect from VPN with given name\n"
		"    status [all|connection name] [--json]\tget status of VPN connection with given name\n"
		"    script-security <enable|disable>\t\tenable/disable script security\n"
		"    help\t\t\t\t\tshow help message\n"
		"    reload\t\t\t\t\treload configuration(sudo required)\n"
		"    import <new-from-tblk|new-from-ovpn> <path>\timport VPN connection(sudo required)\n"
		);
}

/*
 * get process ID of rvd process
 */

pid_t
get_pid_of_rvd()
{
	FILE *pid_fp;
	char buf[128];

	pid_t pid = 0;

	/* open pid file */
	pid_fp = fopen(RVD_PID_FPATH, "r");
	if (!pid_fp)
		return 0;

	/* get pid */
	while (fgets(buf, sizeof(buf), pid_fp) != NULL) {
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if (strlen(buf) == 0)
			continue;

		pid = atoi(buf);
		if (pid > 0)
			break;
	}

	/* close pid file */
	fclose(pid_fp);

	/* check if pid is valid */
	if (pid < 1)
		return 0;

	return pid;
}

/*
 * reload rvd daemon
 */

int reload_rvd()
{
	pid_t pid_rvd;

	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* get process ID of rvd */
	pid_rvd = get_pid_of_rvd();
	if (pid_rvd <= 0) {
		fprintf(stderr, "The rvd process isn't running.\n");
		return RVD_RESP_RVD_NOT_RUNNING;
	}

	/* send SIGUSR1 signal */
	if (kill(pid_rvd, SIGUSR1) < 0) {
		fprintf(stderr, "Couldn't to send SIGUSR1 signal to rvd process.(err:%d)\n", errno);
		return RVD_RESP_SEND_SIG;
	} else
		fprintf(stderr, "Sending reload signal to rvd process '%d' has succeeded.\n", pid_rvd);

	return RVD_RESP_OK;
}

/*
 * import VPN connection
 */

int import_vpn_connection(int import_type, const char *import_path)
{
	size_t fsize;

	/* check UID */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* checks whether import_path has valid extension */
	if (!is_valid_extension(import_path, import_type == RVC_VPN_PROFILE_TBLK ? ".tblk" : ".ovpn")) {
		fprintf(stderr, "Invalid extension of file '%s'\n", import_path);
		return RVD_RESP_INVALID_PROFILE_TYPE;
	}

	/* checks whether size of imported profile */
	fsize = get_file_size(import_path);
	if (fsize <= 0 || fsize >= RVC_MAX_IMPORT_SIZE) {
		fprintf(stderr, "Invalid size or too large file '%s'\n", import_path);
		return RVD_RESP_IMPORT_TOO_LARGE;
	}

	/* copy files into rvd config directory */
	if (copy_file_into_dir(import_path, RVD_DEFAULT_VPN_CONFIG_DIR, S_IRUSR | S_IWUSR) != 0) {
		fprintf(stderr, "Couldn't copy file '%s' into '%s'\n", import_path, RVD_DEFAULT_VPN_CONFIG_DIR);
		return RVD_RESP_UNKNOWN_ERR;
	}

	fprintf(stderr, "Success to import VPN configuration from '%s'\n", import_path);

	return reload_rvd();
}

/*
 * send command and print response
 */

int send_cmd(enum RVD_CMD_CODE cmd_code, const char *cmd_param, bool use_json)
{
	json_object *j_obj;

	/* create json object */
	j_obj = json_object_new_object();
	if (!j_obj) {
		fprintf(stderr, "Couldn't create JSON object\n");
		return RVD_RESP_NO_MEMORY;
	}

	json_object_object_add(j_obj, "cmd", json_object_new_int(cmd_code));

	if (cmd_param)
		json_object_object_add(j_obj, "param", json_object_new_string(cmd_param));

	json_object_object_add(j_obj, "json", json_object_new_boolean(use_json ? 1 : 0));

	snprintf(g_cmd, sizeof(g_cmd), "%s", json_object_get_string(j_obj));

	/* free json object */
	json_object_put(j_obj);

	/* send command */
	if (send(g_sock, g_cmd, strlen(g_cmd), 0) <= 0) {
		fprintf(stderr, "Couldn't send command %s\n", g_cmd);
		return RVD_RESP_SOCK_CONN;
	}

	/* receive response */
	memset(g_resp, 0, sizeof(g_resp));
	if (recv(g_sock, g_resp, sizeof(g_resp), 0) <= 0) {
		fprintf(stderr, "Couldn't receive response\n");
		return RVD_RESP_SOCK_CONN;
	}

	printf("%s\n", g_resp);

	return RVD_RESP_OK;
}

/*
 * parse response from rvd
 */

static int parse_resp(char **resp_data)
{
	json_object *j_obj, *j_sub_obj;
	int ret = RVD_RESP_OK;

	/* parse JSON response */
	j_obj = json_tokener_parse(g_resp);
	if (!j_obj)
		return RVD_RESP_JSON_INVALID;

	/* get code */
	if (!json_object_object_get_ex(j_obj, "code", &j_sub_obj) ||
		json_object_get_type(j_obj) != json_type_int) {
		ret = RVD_RESP_JSON_INVALID;
		goto end;
	}

	ret = json_object_get_int(j_sub_obj);

	/* get response */
	if (json_object_object_get_ex(j_obj, "data", &j_sub_obj)) {
		const char *p = json_object_get_string(j_sub_obj);

		/* allocate and set response data */
		*resp_data = (char *) malloc(strlen(p) + 1);
		if (*resp_data == NULL) {
			ret = RVD_RESP_NO_MEMORY;
			goto end;
		}

		strcpy(*resp_data, p);
		(*resp_data)[strlen(p)] = '\0';
	}

end:
	/* free json object */
	json_object_put(j_obj);

	return ret;
}

/*
 * connect to rvd
 */

static int connect_to_rvd(void)
{
	struct sockaddr_un addr;

	/* create unix domain socket */
	g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_sock < 0)
		return -1;

	/* set server address */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, RVD_LISTEN_SOCK_PATH);

	/* connect to rvd */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

/*
 * send command to rvd daemon
 */

int send_cmd_to_rvd(int cmd_code, const char *param, bool json_format, char **resp_data)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0) {
		fprintf(stderr, "Couldn't to connect to rvd(err:%d)\n", errno);
		return RVD_RESP_SOCK_CONN;
	}

	/* send command to core */
	ret = send_cmd(cmd_code, param, json_format);
	if (ret == 0 && resp_data)
		ret = parse_resp(resp_data);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * List RVC connections
 */

int rvc_list_connections(char **connections)
{
	return send_cmd_to_rvd(RVD_CMD_LIST, NULL, true, connections);
}

/*
 * Try to connect VPN server
 */

int rvc_connect(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_CONNECT, name, true, conn_status);
}

/*
 * Try to disconnect from VPN server
 */

int rvc_disconnect(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_DISCONNECT, name, true, conn_status);
}

/*
 * Get connection status
 */

int rvc_get_status(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_STATUS, name, true, conn_status);
}

/*
 * reload VPN connections
 */

int rvc_reload()
{
	return reload_rvd();
}

/*
 * import VPN profiles
 */

int rvc_import(int import_type, const char *import_path)
{
	return import_vpn_connection(import_type, import_path);
}
