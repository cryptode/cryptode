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

#include <json-c/json.h>

#include "common.h"

static int g_sock;

static char g_cmd[RVD_MAX_CMD_LEN + 1];
static char g_resp[RVD_MAX_RESP_LEN + 1];

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
	{RVD_CMD_UNKNOWN, NULL}
};

static void send_cmd(enum RVD_CMD_CODE cmd_code, const char *cmd_param, bool use_json)
{
	json_object *j_obj;

	/* create json object */
	j_obj = json_object_new_object();
	if (!j_obj) {
		fprintf(stderr, "Couldn't create JSON object\n");
		return;
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
		return;
	}

	/* receive response */
	memset(g_resp, 0, sizeof(g_resp));
	if (recv(g_sock, g_resp, sizeof(g_resp), 0) <= 0) {
		fprintf(stderr, "Couldn't receive response\n");
		return;
	}

	printf("%s\n", g_resp);
}

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
		);
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
	strcpy(addr.sun_path, RVD_DEFAULT_LISTEN_SOCK);

	/* connect to rvd */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

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
