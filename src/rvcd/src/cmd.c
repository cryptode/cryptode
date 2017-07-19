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

#include "rvcd.h"

/*
 * create listen socket
 */

static int create_listen_socket()
{
	int listen_sock;
	struct sockaddr_un listen_addr;

	/* create unix domain socket */
	listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		RVCD_DEBUG_ERR("CMD: Could not create UNIX domain socket(err:%d)", errno);
		return -1;
	}

	/* set listen address */
	memset(&listen_addr, 0, sizeof(struct sockaddr_un));
	listen_addr.sun_family = AF_UNIX;
	strcpy(listen_addr.sun_path, RVCD_CMD_LISTEN_SOCK);

	/* remove socket at first */
	remove(RVCD_CMD_LISTEN_SOCK);

	/* bind and listen socket */
	if (bind(listen_sock, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_un)) != 0) {
		RVCD_DEBUG_ERR("CMD: Could not bind on unix domain socket '%s'(err:%d)", RVCD_CMD_LISTEN_SOCK, errno);
		close(listen_sock);

		return -1;
	}

	if (listen(listen_sock, 5) != 0) {
		RVCD_DEBUG_ERR("CMD: Could not listen on unix domain socket '%s'(err:%d)", RVCD_CMD_LISTEN_SOCK, errno);
		close(listen_sock);

		return -1;
	}

	/* set permission of socket */
	chmod(RVCD_CMD_LISTEN_SOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	return listen_sock;
}

/*
 * set socket as non-blocking mode
 */

static int set_non_blocking(int sock)
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

/*
 * process list command
 */

static void process_cmd_list(rvcd_cmd_proc_t *cmd_proc, const json_object *j_obj)
{
	RVCD_DEBUG_MSG("CMD: Processing 'list' command");
}

/*
 * process commands
 */

struct rvcd_cmd {
	enum RVCD_CMD_CODE code;
	const char *name;
} g_rvcd_cmds[] = {
	{RVCD_CMD_LIST, "list"},
	{RVCD_CMD_UNKNOWN, NULL}
};

static void process_cmd(rvcd_cmd_proc_t *cmd_proc, const char *cmd)
{
	json_object *j_obj, *j_cmd_obj;

	enum RVCD_CMD_CODE cmd_code = RVCD_CMD_UNKNOWN;
	const char *cmd_name;

	int i;

	RVCD_DEBUG_MSG("CMD: Received command '%s'", cmd);

	/* parse command json string */
	j_obj = json_tokener_parse(cmd);
	if (!j_obj) {
		RVCD_DEBUG_ERR("CMD: Couln't parse command '%s'", cmd);
		return;
	}

	/* get command string */
	if (!json_object_object_get_ex(j_obj, "cmd", &j_cmd_obj)) {
		RVCD_DEBUG_ERR("CMD: Couldn't find 'cmd' key from command '%s'", cmd);
		return;
	}

	cmd_name = json_object_get_string(j_cmd_obj);

	/* get command code */
	for (i = 0; g_rvcd_cmds[i].name != NULL; i++) {
		if (strcmp(cmd_name, g_rvcd_cmds[i].name) == 0) {
			cmd_code = g_rvcd_cmds[i].code;
			break;
		}
	}

	if (cmd_code == RVCD_CMD_UNKNOWN) {
		RVCD_DEBUG_ERR("CMD: Unknown command '%s'", cmd);

		/* free json object */
		json_object_put(j_obj);

		return;
	}

	switch (cmd_code) {
		case RVCD_CMD_LIST:
			process_cmd_list(cmd_proc, j_obj);
			break;

		default:
			break;
	}

	/* free json object */
	json_object_put(j_obj);
}

/*
 * rvcd command proc thread
 */

static void *rvcd_cmd_proc(void *p)
{
	rvcd_cmd_proc_t *cmd_proc = (rvcd_cmd_proc_t *) p;

	fd_set fds;
	struct timeval tv;
	int max_fd = cmd_proc->listen_sock;

	RVCD_DEBUG_MSG("CMD: Starting rvcd command processing thread");

	/* set fdset */
	FD_ZERO(&fds);
	FD_SET(max_fd, &fds);

	while (!cmd_proc->end_flag) {
		fd_set tmp_fds;
		struct timeval tv;

		int i, ret;

		/* set temporary fdset */
		FD_COPY(&fds, &tmp_fds);

		/* set timeout */
		tv.tv_sec = 0;
		tv.tv_usec = 50 * 1000;

		/* I/O polling */
		ret = select(max_fd + 1, &tmp_fds, NULL, NULL, &tv);
		if (ret < 0) {
			RVCD_DEBUG_ERR("CMD: Async select I/O multiplexing has failed.(err:%d) Exiting...", errno);
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
						RVCD_DEBUG_ERR("CMD: Accepting connection has failed.(err:%d)", errno);
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
					char cmd_buf[RVCD_MAX_CMD_LEN + 1];
					bool failed = false;

					/* get command */
					memset(cmd_buf, 0, sizeof(cmd_buf));
					ret = recv(i, cmd_buf, RVCD_MAX_CMD_LEN, 0);
					if (ret > 0) {
						process_cmd(cmd_proc, cmd_buf);
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

	RVCD_DEBUG_MSG("CMD: Stopped rvcd command processing thread");

	return 0;
}

/*
 * initialize command proc
 */

int rvcd_cmd_proc_init(struct rvcd_ctx *c)
{
	rvcd_cmd_proc_t *cmd_proc = &c->cmd_proc;
	int listen_sock;

	RVCD_DEBUG_MSG("CMD: Initializing rvcd command processor");

	/* create listening unix domain socket */
	listen_sock = create_listen_socket();
	if (listen_sock < 0)
		return -1;

	/* set socket as non blocking mode */
	if (set_non_blocking(listen_sock) != 0) {
		RVCD_DEBUG_ERR("CMD: Could not set as non-blocking mode(err:%d)", errno);
		close(listen_sock);

		return -1;
	}

	/* create thread for command process */
	cmd_proc->c = c;
	if (pthread_create(&cmd_proc->pt_cmd_proc, NULL, rvcd_cmd_proc, (void *) cmd_proc) != 0) {
		RVCD_DEBUG_ERR("CMD: Could not create command processor thread(err:%d)", errno);
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

void rvcd_cmd_proc_finalize(rvcd_cmd_proc_t *cmd_proc)
{
	/* check init flag */
	if (!cmd_proc->init_flag)
		return;

	RVCD_DEBUG_MSG("CMD: Finalizing rvcd command processor");

	/* set end flag */
	cmd_proc->end_flag = true;

	/* wait until proc thread has finished */
	pthread_join(cmd_proc->pt_cmd_proc, NULL);

	/* close listen socket */
	close(cmd_proc->listen_sock);

	/* remove socket */
	remove(RVCD_CMD_LISTEN_SOCK);
}
