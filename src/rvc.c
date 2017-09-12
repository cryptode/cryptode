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

#include "rvc.h"

/* static global variables */
static int g_sock;

static char g_cmd[RVD_MAX_CMD_LEN + 1];
static char g_resp[RVD_MAX_RESP_LEN + 1];

/*
 * print help message
 */

static void print_help(void)
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

static pid_t
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

static int reload_rvd()
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

static int import_vpn_connection(int import_type, const char *import_path)
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

static struct {
	enum RVD_CMD_CODE code;
	const char *name;
} g_cmd_names[] = {
	{RVD_CMD_LIST, "list"},
	{RVD_CMD_CONNECT, "connect"},
	{RVD_CMD_DISCONNECT, "disconnect"},
	{RVD_CMD_STATUS, "status"},
	{RVD_CMD_SCRIPT_SECURITY, "script-security"},
	{RVD_CMD_RELOAD, "reload"},
	{RVD_CMD_IMPORT, "import"},
	{RVD_CMD_UNKNOWN, NULL}
};

static int send_cmd(enum RVD_CMD_CODE cmd_code, const char *cmd_param, bool use_json)
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
 * List RVC connections
 */

int rvc_list_connections(char **connections)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0)
		return RVD_RESP_SOCK_CONN;

	/* send command to core */
	ret = send_cmd(RVD_CMD_LIST, NULL, true);
	if (ret == 0)
		ret = parse_resp(connections);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * Try to connect VPN server
 */

int rvc_connect(const char *name, char **conn_status)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0)
		return RVD_RESP_SOCK_CONN;

	/* send command to core */
	ret = send_cmd(RVD_CMD_CONNECT, name, true);
	if (ret == 0)
		ret = parse_resp(conn_status);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * Try to disconnect from VPN server
 */

int rvc_disconnect(const char *name, char **conn_status)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0)
		return RVD_RESP_SOCK_CONN;

	/* send command to core */
	ret = send_cmd(RVD_CMD_DISCONNECT, name, true);
	if (ret == 0)
		ret = parse_resp(conn_status);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * Get connection status
 */

int rvc_get_status(const char *name, char **conn_status)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0)
		return RVD_RESP_SOCK_CONN;

	/* send command to core */
	ret = send_cmd(RVD_CMD_STATUS, name, true);
	if (ret == 0)
		ret = parse_resp(conn_status);

	/* close socket */
	close(g_sock);

	return ret;
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

#if RVC_USE_MAIN

/*
 * main function
 */

int main(int argc, char *argv[])
{
	enum RVD_CMD_CODE cmd_code = RVD_CMD_UNKNOWN;
	bool use_json = false;
	bool opt_invalid = false;

	int i;

	const char *cmd_param = NULL;

	/* check argument */
	if (argc < 2) {
		print_help();
		exit(1);
	}

	if (argc == 2 && strcmp(argv[1], "help") == 0) {
		print_help();
		exit(0);
	}

	/* get command code */
	for (i = 0; g_cmd_names[i].name != NULL; i++) {
		if (strcmp(argv[1], g_cmd_names[i].name) == 0) {
			cmd_code = g_cmd_names[i].code;
			break;
		}
	}

	/* check command code */
	if (cmd_code == RVD_CMD_UNKNOWN) {
		fprintf(stderr, "Invalid command '%s'\n", argv[1]);
		print_help();

		exit(1);
	}

	switch (cmd_code) {
	case RVD_CMD_LIST:
		if (argc == 3 && strcmp(argv[2], "--json") == 0)
			use_json = true;
		else if (argc != 2)
			opt_invalid = true;

		break;

	case RVD_CMD_CONNECT:
	case RVD_CMD_DISCONNECT:
		if (argc == 3)
			cmd_param = argv[2];
		else if (argc == 4 && strcmp(argv[3], "--json") == 0) {
			cmd_param = argv[2];
			use_json = true;
		} else
			opt_invalid = true;

		break;

	case RVD_CMD_STATUS:
		if (argc == 2)
			cmd_param = "all";
		else if (argc == 3) {
			if (strcmp(argv[2], "--json") == 0) {
				use_json = true;
				cmd_param = "all";
			} else
				cmd_param = argv[2];
		} else if (argc == 4 && strcmp(argv[3], "--json") == 0) {
			use_json = true;
			cmd_param = argv[2];
		} else
			opt_invalid = true;

		break;

	case RVD_CMD_SCRIPT_SECURITY:
		if (argc == 3 && (strcmp(argv[2], "enable") == 0 ||
			(strcmp(argv[2], "disable")) == 0))
			cmd_param = argv[2];
		else
			opt_invalid = true;

		break;

	case RVD_CMD_RELOAD:
		if (argc != 2)
			opt_invalid = true;
		else {
			int ret;

			ret = reload_rvd();
			exit(ret);
		}

		break;

	case RVD_CMD_IMPORT:
		if (argc != 4)
			opt_invalid = true;
		else {
			int ret;
			int import_type;

			/* get import type */
			if (strcmp(argv[2], "new-from-tblk") == 0)
				import_type = RVC_VPN_PROFILE_TBLK;
			else if (strcmp(argv[2], "new-from-ovpn") == 0)
				import_type = RVC_VPN_PROFILE_OVPN;
			else {
				fprintf(stderr, "Invalid import type paramter '%s'\n", argv[2]);
				exit(-1);
			}

			ret = import_vpn_connection(import_type, argv[3]);
			exit(ret);
		}

		break;

	default:
		break;
	}

	if (opt_invalid) {
		fprintf(stderr, "Invalid options\n");
		print_help();

		exit(1);
	}

	/* connect to rvd */
	if (connect_to_rvd() != 0) {
		fprintf(stderr, "Couldn't connect to rvd process.\n");
		exit(1);
	}

	/* send command to core */
	send_cmd(cmd_code, cmd_param, use_json);

	/* close socket */
	close(g_sock);

	return 0;
}

#endif
