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
#include <stdarg.h>
#include <pthread.h>
#include <syslog.h>

#include "common.h"
#include "log.h"

static FILE *g_log_fp;
static pthread_mutex_t g_log_mt = PTHREAD_MUTEX_INITIALIZER;

/*
 * initialize rvcd logging
 */

int rvcd_log_init()
{
	/* open log file */
	g_log_fp = fopen(RVCD_LOG_FPATH, "w");
	if (!g_log_fp) {
		fprintf(stderr, "Could not open log file '%s' for writting.\n", RVCD_LOG_FPATH);
		return -1;
	}

	/* open syslog */
	openlog(NULL, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

	/* init logging mutex */
	pthread_mutex_init(&g_log_mt, NULL);

	return 0;
}

/*
 * finalize rvcd logging
 */

void rvcd_log_finalize()
{
	/* close syslog */
	closelog();

	/* close log file */
	if (g_log_fp)
		fclose(g_log_fp);

	/* destroy mutex */
	pthread_mutex_destroy(&g_log_mt);
}

/*
 * write log into file
 */

static const char *log_type_str[] = {
	"INFO", "WARN", "ERR"
};

void rvcd_debug_log(enum LOG_TYPE log_type, const char *file_name, int file_line, const char *format, ...)
{
	va_list va_args;

	time_t tt;
	struct tm *tm;
	char time_str[64];

	char msg[RVCD_MAX_LOGMSG_LEN + 1];

	/* check log file pointer */
	if (!g_log_fp)
		return;

	/* mutex lock */
	pthread_mutex_lock(&g_log_mt);

	/* build log string */
	va_start(va_args, format);
	vsnprintf(msg, sizeof(msg), format, va_args);
	va_end(va_args);

	time(&tt);
	tm = localtime(&tt);

	strftime(time_str, sizeof(time_str), "%a %d %b %Y %T", tm);

	/* write log */
	fprintf(g_log_fp, "%s\t%s : %s(at %s:%d)\n", time_str, log_type_str[log_type], msg, file_name, file_line);
	fflush(g_log_fp);

	fprintf(stderr, "%s\t%s : %s(at %s:%d)\n", time_str, log_type_str[log_type], msg, file_name, file_line);

	/* write syslog */
	syslog(LOG_INFO, "%s\t%s : %s\n", time_str, log_type_str[log_type], msg);

	/* unlock mutex */
	pthread_mutex_unlock(&g_log_mt);
}
