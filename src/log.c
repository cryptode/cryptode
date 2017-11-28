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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"
#include "util.h"
#include "log.h"

static FILE *g_log_fp = NULL;
static char g_log_path[RVD_MAX_PATH];
static int g_log_fsize;
static pthread_mutex_t g_log_mt = PTHREAD_MUTEX_INITIALIZER;

/*
 * create log file
 */

static int create_log_file()
{
	int fd;
	char backup_log_path[RVD_MAX_PATH];

	/* check whether log path is set */
	if (strlen(g_log_path) == 0)
		return -1;

	/* check whether file pointer is exist */
	if (g_log_fp) {
		fclose(g_log_fp);
		g_log_fp = NULL;
	}

	/* backup old log file */
	snprintf(backup_log_path, sizeof(backup_log_path), "%s.0", g_log_path);
	rename(g_log_path, backup_log_path);

	/* open log file */
	fd = open(g_log_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd > 0)
		g_log_fp = fdopen(fd, "w");

	if (fd < 0 || !g_log_fp) {
		fprintf(stderr, "Couldn't open log file '%s' for writing.\n", g_log_path);

		if (fd > 0)
			close(fd);

		return -1;
	}

	/* set permission */
	chmod(g_log_path, S_IRUSR | S_IWUSR);

	return 0;
}

/*
 * initialize rvd logging
 */

int rvd_log_init(const char *log_dir_path)
{
	/* create log directory */
	if (create_dir(log_dir_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0)
		return -1;

	/* set path of log file */
	get_full_path(log_dir_path, RVD_LOG_FILE_NAME, g_log_path, sizeof(g_log_path));

	/* open log file */
	if (create_log_file() != 0)
		return -1;

	/* open syslog */
	openlog(NULL, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

	/* init logging mutex */
	pthread_mutex_init(&g_log_mt, NULL);

	return 0;
}

/*
 * finalize rvd logging
 */

void rvd_log_finalize()
{
	/* close syslog */
	closelog();

	/* close log file */
	if (g_log_fp) {
		fclose(g_log_fp);
		g_log_fp = NULL;
	}

	/* destroy mutex */
	pthread_mutex_destroy(&g_log_mt);
}

/*
 * write log into file
 */

static const char *log_type_str[] = {
	"INFO", "ERR", "WARN"
};

void rvd_debug_log(enum LOG_TYPE log_type, const char *file_name, int file_line, const char *format, ...)
{
	va_list va_args;

	time_t tt;
	struct tm *tm;
	char time_str[64];

	char *msg;
	size_t msg_size;

	/* build log string */
	va_start(va_args, format);
	msg_size = vsnprintf(NULL, 0, format, va_args);
	va_end(va_args);

	msg = (char *) malloc(msg_size + 1);
	if (!msg)
		return;

	va_start(va_args, format);
	vsnprintf(msg, msg_size + 1, format, va_args);
	va_end(va_args);

	time(&tt);
	tm = localtime(&tt);

	strftime(time_str, sizeof(time_str), "%FT%T%Z", tm);

	/* mutex lock */
	pthread_mutex_lock(&g_log_mt);

	/* check log file size */
	if (!g_log_fp || g_log_fsize > RVD_MAX_LOG_FSIZE) {
		create_log_file();
		g_log_fsize = 0;
	}

	/* write log */
	if (g_log_fp) {
		int written_log_bytes;

		written_log_bytes = fprintf(g_log_fp, "%s\t%s : %s(at %s:%d)\n", time_str, log_type_str[log_type], msg,
						file_name, file_line);
		if (written_log_bytes > 0)
			g_log_fsize += written_log_bytes;
		fflush(g_log_fp);

		/* write syslog */
		syslog(LOG_INFO, "%s\t%s : %s\n", time_str, log_type_str[log_type], msg);
	}

	fprintf(stderr, "%s\t%s : %s(at %s:%d)\n", time_str, log_type_str[log_type], msg, file_name, file_line);

	/* unlock mutex */
	pthread_mutex_unlock(&g_log_mt);

	free(msg);
}
