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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

/*
 * get maximum fd from fd_set
 */

int get_max_fd(int orig_max_fd, fd_set *fds)
{
	int i, max_fd = -1;

	for (i = 0; i <= orig_max_fd; i++) {
		if (!FD_ISSET(i, fds))
			continue;

		if (i > max_fd)
			max_fd = i;
	}

	return max_fd;
}

/*
 * get free listen port
 */

int get_free_listen_port(int start_port)
{
	int sock;
	int listen_port = start_port;

	int ret;

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;

	while (1) {
		struct sockaddr_in listen_addr;

		/* set listen address */
		memset(&listen_addr, 0, sizeof(listen_addr));

		listen_addr.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &listen_addr.sin_addr);
		listen_addr.sin_port = htons(listen_port);

		/* try bind */
		ret = bind(sock, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_in));
		if (ret == 0)
			break;

		/* check errno has in-use value */
		if (errno != EADDRINUSE)
			continue;

		/* check maximum listening port number */
		if (listen_port == 65535)
			break;

		listen_port++;
	}

	/* close socket */
	close(sock);

	return (ret == 0) ? listen_port : -1;
}

/* get token by comma */
void get_token_by_comma(char **pp, char *token, size_t size)
{
	char *p = *pp;
	int i = 0;

	/* set buffer until comma is exist */
	while (*p != ',' && *p != '\0' && *p != '\n' && !isspace(*p)) {
		if (i == (size - 1))
			break;

		token[i++] = *p;
		p++;
	}

	token[i] = '\0';

	if (*p != '\0')
		*pp = p + 1;
}

/*
 * set socket as non-blocking mode
 */

int set_non_blocking(int sock)
{
	int ret, on = 1;

	/* set socket option as reusable */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
		return -1;

	/* set non-blocking mode */
	if (ioctl(sock, FIONBIO, (char *) &on) < 0)
		return -1;

	return 0;
}

/* check whether connection name is valid */
int is_valid_conn_name(const char *conn_name)
{
	int i;

	while (conn_name[i] != '\0') {
		char p = conn_name[i++];

		/* check whether first character has alphabetic or digit */
		if (i == 0 && !isalpha(p) && !isdigit(p))
			return 0;

		if (!isalpha(p) && !isdigit(p) &&
			p != '-' && p != '_' && p != '.')
			return 0;
	}

	return 1;
}
