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
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "rvcd.h"

static bool g_end_flag;

/*
 * signal handler
 */

static void
signal_handler(const int signum)
{
	RVCD_DEBUG_MSG("Main: Received signal %d", signum);

	/* set end flag */
	g_end_flag = true;
}

/*
 * initialize signal handler
 */

static void
init_signal()
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);
}

/*
 * check if rvcd process is running
 */

static pid_t
check_process_running()
{
	FILE *pid_fp;
	char buf[512];

	pid_t pid = 0;

	/* open pid file */
	pid_fp = fopen(RVCD_PID_FPATH, "r");
	if (!pid_fp)
		return 0;

	/* get pid */
	while (fgets(buf, sizeof(buf), pid_fp) != NULL) {
		/* remove endline */
		buf[strlen(buf) - 1] = '\0';

		if (strlen(buf) == 0)
			continue;

		pid = atoi(buf);
		if (pid > 0)
			break;
	}

	// close pid file
	fclose(pid_fp);

	// check if pid is valid
	if (pid < 1)
		return 0;

	// check if the process is running with given pid
	if (kill(pid, 0) == 0)
		return pid;

	return 0;
}

/*
 * write PID file
 */

static void
write_pid_file()
{
	FILE *pid_fp;
	pid_t pid;

	/* get process ID of current process */
	pid = getpid();

	/* open pid file and write */
	pid_fp = fopen(RVCD_PID_FPATH, "w");
	if (!pid_fp)
		return;

	fprintf(pid_fp, "%d\n", pid);

	// close pid file
	fclose(pid_fp);
}

/*
 * remove pid file
 */

static void
remove_pid_file()
{
	remove(RVCD_PID_FPATH);
}

/*
 * initialize rvcd context
 */

static int
rvcd_ctx_init(rvcd_ctx_t *c)
{
	RVCD_DEBUG_MSG("Main: Initializing rvcd context");

	/* initialize command manager */
	if (rvcd_cmd_proc_init(c) != 0) {
		RVCD_DEBUG_ERR("Main: Could not initialize command processor");
		return -1;
	}

	/* initialize VPN connection manager */

	return 0;
}

/*
 * finalize rvcd context
 */

static void
rvcd_ctx_finalize(rvcd_ctx_t *c)
{
	RVCD_DEBUG_MSG("Main: Finalizing rvcd context");

	/* finalize VPN connection manager */

	/* finalize command manager */
	rvcd_cmd_proc_finalize(&c->cmd_proc);
}

/*
 * main function
 */

int
main(int argc, char *argv[])
{
	rvcd_ctx_t ctx;
	pid_t pid;

	/* initialize rvcd context */
	memset(&ctx, 0, sizeof(rvcd_ctx_t));

	/* check UID */
	if (getuid() != 0) {
		fprintf(stderr, "Please run as root privilege\n");
		exit(-1);
	}

	/* check if the process is already running */
	if ((pid = check_process_running()) > 0) {
		fprintf(stderr, "The rvcd process is already running with PID %d. Existing...\n", pid);
		exit(-1);
	}

	/* write PID file */
	write_pid_file();

	/* init signal */
	init_signal();

	/* initialize logging */
	if (rvcd_log_init() != 0) {
		fprintf(stderr, "Could not initialize logging.\n");
		exit(-1);
	}

	/* initialize rvcd context */
	if (rvcd_ctx_init(&ctx) != 0) {
		RVCD_DEBUG_ERR("Main: Initializing rvcd context has failed.");

		rvcd_ctx_finalize(&ctx);
		exit(-1);
	}

	while (!g_end_flag) {
		sleep(1);
	}

	/* finalize rvcd context */
	rvcd_ctx_finalize(&ctx);

	/* remove PID file */
	remove_pid_file();

	return 0;
}
