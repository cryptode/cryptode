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
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include <sys/stat.h>
#include <json-c/json.h>

#include "rvd.h"

static bool g_end_flag;
static bool g_reload_config;

/* rvd default configuration */
static rvd_ctx_opt_t g_default_opts = {
	OPENVPN_BINARY_PATH,
	true,
	false,
	RVD_DEFAULT_UID,
	true,
	RVD_DEFAULT_LOGDIR_PATH,
	RVC_CONFDIR_PATH,
};

/*
 * print help message
 */

static void
print_help(void)
{
	printf("usage: rvd <options>\n"
		"  Options:\n"
		"    -f <config file>\tset configuration file\n"
		"    -D\t\t\tgoes daemon\n"
		"    -c\t\t\tonly check config and exit\n"
		"    -v\t\t\tprint version\n"
		"    -h\t\t\tprint help message\n");

	exit(0);
}

/*
 * print version
 */

static void
print_version(void)
{
	static const char build_time[] = { __DATE__ " " __TIME__ };

	printf("Relaxed VPN client daemon - %s (built on %s)\n%s\n",
			PACKAGE_VERSION,
			build_time,
			RVC_COPYRIGHT_MSG);

	exit(0);
}

/*
 * signal handler
 */

static void
signal_handler(const int signum)
{
	RVD_DEBUG_MSG("Main: Received signal %d", signum);

	/* if signal is SIGUSR1, then reload a config */
	if (signum == SIGUSR1) {
		g_reload_config = true;
		return;
	}

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
	signal(SIGUSR1, signal_handler);
}

/*
 * check if rvd process is running
 */

static pid_t
check_process_running()
{
	FILE *pid_fp;
	char buf[512];

	pid_t pid = 0;

	/* open pid file */
	pid_fp = fopen(RVD_PID_FPATH, "r");
	if (!pid_fp)
		return 0;

	/* get pid */
	while (fgets(buf, sizeof(buf) - 1, pid_fp) != NULL) {
		/* remove endline */
		buf[strlen(buf) - 1] = '\0';

		if (strlen(buf) == 0)
			continue;

		pid = atoi(buf);
		if (pid > 0)
			break;
	}

	/* close pid file */
	fclose(pid_fp);

	/* check if pid is valid */
	if (pid < 1)
		return 0;

	/* check if the process is running with given pid */
	if (kill(pid, 0) == 0)
		return pid;

	return 0;
}

/*
 * daemonize the process
 */

static void
daemonize(void)
{
	pid_t pid = 0;
	int fd;

	/* fork off the parent process */
	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid > 0)
		exit(0);

	/* set child process to session leader */
	if (setsid() < 0)
		exit(1);

	/* ignore signal sent from child to parent */
	signal(SIGCHLD, SIG_IGN);

	/* fork for the second time */
	pid = fork();
	if (pid < 0)
		exit(1);
	else if (pid > 0)
		exit(0);

	/* set new file permissions */
	umask(0);

	/* change working directory to root */
	if (chdir("/") < 0)
		exit(1);

	/* close all open file descriptors */
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
		close(fd);

	/* reopen stdin, stdout, stderr */
	stdin = fopen("/dev/null", "r");
	stdout = fopen("/dev/null", "w+");
	stderr = fopen("/dev/null", "w+");
}

/*
 * write PID file
 */

static void
write_pid_file(void)
{
	FILE *pid_fp = NULL;
	int fd;

	/* remove old pid file */
	mkdir(RVD_PID_DPATH, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	remove(RVD_PID_FPATH);

	/* open pid file and write */
	fd = open(RVD_PID_FPATH, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd > 0)
		pid_fp = fdopen(fd, "w");

	if (fd < 0 || !pid_fp) {
		if (fd > 0)
			close(fd);

		return;
	}

	fprintf(pid_fp, "%d\n", getpid());

	/* close pid file */
	fclose(pid_fp);
}

/*
 * remove pid file
 */

static void
remove_pid_file(void)
{
	remove(RVD_PID_FPATH);
}

/*
 * read configuration
 */

static int
parse_config(rvd_ctx_opt_t *opt, const char *config_path)
{
	int fd;

	char buf[2048];
	ssize_t buf_len = 0;

	struct stat st;

	struct rvd_json_object config_jobjs[] = {
		{"openvpn_bin", RVD_JTYPE_STR, opt->ovpn_bin_path, sizeof(opt->ovpn_bin_path), false, NULL},
		{"openvpn_root_check", RVD_JTYPE_BOOL, &opt->ovpn_root_check, 0, false, NULL},
		{"openvpn_up_down_scripts", RVD_JTYPE_BOOL, &opt->ovpn_use_scripts, 0, false, NULL},
		{"user_id", RVD_JTYPE_UID, &opt->allowed_uid, 0, false, NULL},
		{"restrict_socket", RVD_JTYPE_BOOL, &opt->restrict_cmd_sock, 0, false, NULL},
		{"log_directory", RVD_JTYPE_STR, opt->log_dir_path, sizeof(opt->log_dir_path), false, NULL},
		{"vpn_config_dir", RVD_JTYPE_STR, &opt->vpn_config_dir, sizeof(opt->vpn_config_dir), false, NULL}
	};

	/* check whether configuration file has valid permission */
	if (stat(config_path, &st) != 0 || st.st_size <= 0) {
		fprintf(stderr, "Invalid configuration file '%s'\n", config_path);
		return -1;
	}

	if (!is_owned_by_user(config_path, "root") ||
	    !is_valid_permission(config_path, S_IRUSR | S_IWUSR)) {
		fprintf(stderr, "The configuration file '%s' isn't owned by root or has the leak permission\n",
			config_path);
		return -1;
	}

	/* open configuration file */
	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open configuration file '%s' for reading(err:%d)\n", config_path, errno);
		return -1;
	}

	/* read buffer */
	while (buf_len < st.st_size) {
		ssize_t read_len;

		read_len = read(fd, &buf[buf_len], sizeof(buf) - buf_len);
		if (read_len <= 0) {
			close(fd);
			return -1;
		}

		buf_len += read_len;
	}

	buf[buf_len] = '\0';

	/* close file */
	close(fd);

	/* set default options */
	memcpy(opt, &g_default_opts, sizeof(rvd_ctx_opt_t));

	/* parse configuration json */
	if (rvd_json_parse(buf, config_jobjs, sizeof(config_jobjs) / sizeof(struct rvd_json_object)) != 0) {
		fprintf(stderr, "Couldn't parse json configuration '%s' from config file\n", buf);
		return -1;
	}

	return 0;
}

/*
 * initialize rvd context
 */

static int
rvd_ctx_init(rvd_ctx_t *c, const char *config_path)
{
	/* initialize context object */
	memset(c, 0, sizeof(rvd_ctx_t));

	/* read configruation */
	if (parse_config(&c->opt, config_path ? config_path : RVD_CONFIG_PATH) != 0)
		exit(-1);

	/* initialize logging */
	if (rvd_log_init(c->opt.log_dir_path) != 0) {
		fprintf(stderr, "Couldn't create log file in directory '%s'\n", c->opt.log_dir_path);
		return -1;
	}

	RVD_DEBUG_MSG("Main: Initializing rvd context");

	/* initialize command manager */
	if (rvd_cmd_proc_init(c) != 0) {
		RVD_DEBUG_ERR("Main: Couldn't initialize command processor");
		return -1;
	}

	/* initialize VPN connection manager */
	if (rvd_vpnconn_mgr_init(c) != 0) {
		RVD_DEBUG_ERR("Main: Couldn't initialize VPN connection manager");
		return -1;
	}

	return 0;
}

/*
 * finalize rvd context
 */

static void
rvd_ctx_finalize(rvd_ctx_t *c)
{
	RVD_DEBUG_MSG("Main: Finalizing rvd context");

	/* finalize VPN connection manager */
	rvd_vpnconn_mgr_finalize(&c->vpnconn_mgr);

	/* finalize command manager */
	rvd_cmd_proc_finalize(&c->cmd_proc);

	/* finalize logging */
	rvd_log_finalize(&c);
}

/*
 * reload rvd context
 */

static void
rvd_ctx_reload(rvd_ctx_t *c, const char *config_path)
{
	RVD_DEBUG_MSG("Main: Reloading rvd context");

	/* finalize rvd context */
	rvd_ctx_finalize(c);

	/* init context object */
	memset(c, 0, sizeof(rvd_ctx_t));

	/* init rvd context */
	if (rvd_ctx_init(c, config_path) != 0) {
		RVD_DEBUG_ERR("Main: Couldn't reload rvd context");
		rvd_ctx_finalize(c);
	}
}

/*
 * main function
 */

int
main(int argc, char *argv[])
{
	rvd_ctx_t ctx;
	pid_t pid;

	const char *config_path = NULL;

	bool go_daemon = false;
	bool check_mode = false;

	/* initialize rvd context */
	memset(&ctx, 0, sizeof(rvd_ctx_t));

	/* check UID */
	if (getuid() != 0) {
		fprintf(stderr, "Please run as root\n");
		exit(-1);
	}

	/* parse command line options */
	if (argc > 1) {
		int opt;
		while ((opt = getopt(argc, argv, "Df:chv")) != -1) {
			switch (opt) {
				case 'f':
					config_path = optarg;
					break;

				case 'D':
					go_daemon = true;
					break;

				case 'c':
					check_mode = true;
					break;

				case 'v':
					print_version();
					break;

				default:
					print_help();
					break;
			}
		}
	}

	/* if check mode is enabled, then check configuration file and exit */
	if (check_mode) {
		rvd_ctx_opt_t opt;

		if (parse_config(&opt, config_path ? config_path : RVD_CONFIG_PATH) != 0)
			exit(-1);

		printf("Success to parse the configuration file '%s'\n", config_path ? config_path : RVD_CONFIG_PATH);
		exit(0);
	}

	/* check if the process is already running */
	if ((pid = check_process_running()) > 0) {
		fprintf(stderr, "The rvd process is already running with PID %d. Exiting...\n", pid);
		exit(-1);
	}

	/* if daemon mode is enabled, then daemonize the process */
	if (go_daemon)
		daemonize();

	/* write PID file */
	write_pid_file();

	/* init signal */
	init_signal();

	/* initialize rvd context */
	if (rvd_ctx_init(&ctx, config_path) != 0) {
		RVD_DEBUG_ERR("Main: Failed initializing rvd context.");

		rvd_ctx_finalize(&ctx);
		exit(-1);
	}

	while (!g_end_flag) {
		if (g_reload_config) {
			rvd_ctx_reload(&ctx, config_path);
			g_reload_config = false;
		}

		sleep(1);
	}

	/* finalize rvc context */
	rvd_ctx_finalize(&ctx);

	/* remove PID file */
	remove_pid_file();

	return 0;
}
