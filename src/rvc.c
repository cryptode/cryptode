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

	send_cmd_to_rvd(cmd_code, cmd_param, use_json, NULL);

	return 0;
}
