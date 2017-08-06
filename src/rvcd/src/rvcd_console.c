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

static char g_cmd[RVCD_MAX_CMD_LEN + 1];
static char g_resp[RVCD_MAX_RESP_LEN + 1];

/*
 * send command and print response
 */

static const char *g_cmd_strs[] = {
	"list",
	"connect",
	"disconnect",
	"status",
	NULL
};

static void send_cmd(enum RVCD_CMD_CODE cmd_code, const char *cmd_param, bool use_json)
{
	json_object *j_obj;

	/* create json object */
	j_obj = json_object_new_object();
	if (!j_obj) {
		fprintf(stderr, "Couldn't create JSON object");
		return;
	}

	json_object_object_add(j_obj, "cmd", json_object_new_string(g_cmd_strs[cmd_code]));

	if (cmd_param)
		json_object_object_add(j_obj, "name", json_object_new_string(cmd_param));

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
	printf("Usage: rvcd_console [options]\n"
		"\tOptions:\n"
		"\t\t-l\t\t\t\tshow list of VPN connections\n"
		"\t\t-c [all|connection name]\tconnect to VPN server with given name\n"
		"\t\t-d [all|connection name]\tdisconnect from VPN server with given name\n"
		"\t\t-s [all|connection name]\tget status of VPN connection with given name\n"
		"\t\t-j\t\t\t\tprint result using JSON format\n"
		);
}

/*
 * connect to rvcd
 */

static int connect_to_rvcd(void)
{
	struct sockaddr_un addr;

	/* create unix domain socket */
	g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_sock < 0)
		return -1;

	/* set server address */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, RVCD_CMD_LISTEN_SOCK);

	/* connect to rvcd */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

/*
 * main function
 */

int main(int argc, char *argv[])
{
	enum RVCD_CMD_CODE cmd_code = RVCD_CMD_UNKNOWN;
	bool use_json = false;

	int opt;

	const char *cmd_param = NULL;

	/* check argument */
	if (argc < 2) {
		print_help();
		exit(1);
	}

	/* connect to rvcd */
	if (connect_to_rvcd() != 0) {
		fprintf(stderr, "Could't connect to rvcd process.\n");
		exit(1);
	}

	/* process commands */
	while ((opt = getopt(argc, argv, "lc:d:s:j")) != -1) {
		switch (opt) {
			case 'l':
				cmd_code = RVCD_CMD_LIST;
				break;

			case 'c':
				cmd_code = RVCD_CMD_CONNECT;
				cmd_param = optarg;
				break;

			case 'd':
				cmd_code = RVCD_CMD_DISCONNECT;
				cmd_param = optarg;
				break;

			case 's':
				cmd_code = RVCD_CMD_STATUS;
				cmd_param = optarg;
				break;

			case 'j':
				use_json = true;
				break;

			default:
				break;
		}
	}

	/* send command to core */
	if (cmd_code != RVCD_CMD_UNKNOWN)
		send_cmd(cmd_code, cmd_param, use_json);

	/* close socket */
	close(g_sock);

	return 0;
}
