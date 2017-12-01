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

#include "../config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#define RVD_SBIN_PATH                 "/opt/rvc/bin/rvd"

#define RVD_CONF_VALID_PERMISSION     (S_IRUSR | S_IWUSR)
#define RVD_CONF_WRONG_PERMISSION     (S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH)

static pid_t rvd_pid;

/*
 * set the permission for RVC configuration
 */

static void
set_rvd_conf_permission(int permission)
{
	if (chmod(RVD_CONFIG_PATH, permission) != 0) {
		fprintf(stderr, "Couldn't set permission for the configuration '%s'\n", RVD_CONFIG_PATH);
		exit(1);
	}
}

/*
 * start RVD process
 */

static int
start_rvd(void)
{
	int timeout = 0;
	int exit_code = 0;

	rvd_pid = fork();
	if (rvd_pid < 0) {
		fprintf(stderr, "fork() failed(err:%d).\n", errno);
		return -1;
	}

	if (rvd_pid == 0) {
		char *const args[] = {RVD_SBIN_PATH, RVD_SBIN_PATH, NULL};

		execvp(args[0], args);
		exit(1);
	}

	do {
		int w, status;

		w = waitpid(-1, &status, WNOHANG);
		if (w < 0)
			return -1;
		else if (w == 0) {
			if (timeout == 5) {
				kill(rvd_pid, SIGTERM);
				break;
			}

			timeout++;
			sleep(1);
			continue;
		}

		if (WIFEXITED(status)) {
			exit_code = WEXITSTATUS(status);
			break;
		}
	} while (1);

	return exit_code;
}

/*
 * main function
 */

int
main(int argc, char *argv[])
{
	int exit_code;

	/* check for wrong persmission */
	set_rvd_conf_permission(RVD_CONF_WRONG_PERMISSION);
	exit_code = start_rvd();
	if (exit_code == 0) {
		fprintf(stderr, "RVD is starting with the configuration with wrong permission.\n");
		exit(1);
	}

	/* check for valid permission */
	set_rvd_conf_permission(RVD_CONF_VALID_PERMISSION);
	exit_code = start_rvd();
	if (exit_code != 0) {
		fprintf(stderr, "RVD isn't started with the configuration with valid persmission.\n");
		exit(1);
	}

	return 0;
}
