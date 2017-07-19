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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"

static int g_sock;

/*
 * show vpn profile list
 */

static void show_vpn_list(void)
{
	const char *cmd = "{\"cmd\": \"list\"}";

	/* send command */
	if (send(g_sock, cmd, strlen(cmd), 0) <= 0) {
		fprintf(stderr, "Couldn't send command %s\n", cmd);
		return;
	}
}

/*
 * print help message
 */

static void print_help(void)
{
	printf("Usage: rvcd_console [options]\n"
		"\tOptions:\n"
		"\t\t--list\t\tshow list of VPN connections\n"
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
	if (strcmp(argv[1], "--list") == 0)
		show_vpn_list();
	else
		print_help();

	/* close socket */
	close(g_sock);

	return 0;
}
