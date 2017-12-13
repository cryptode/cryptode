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
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include "../src/common.h"
#include "../src/conf.h"

#ifdef __APPLE__
#define RVD_BIN_PATH                 "/opt/rvc/bin/rvd"
#define RVC_BIN_PATH                 "/opt/rvc/bin/rvc"
#else
#define RVD_BIN_PATH                 "/usr/sbin/rvd"
#define RVC_BIN_PATH                 "/usr/bin/rvc"
#endif

#define RVD_CONF_VALID_PERMISSION     (S_IRUSR | S_IWUSR)
#define RVD_CONF_WRONG_PERMISSION     (S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH)

#define OVPN_BIN_VALID_PERMISSION     (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define OVPN_BIN_WRONG_PERMISSION     (S_IRUSR | S_IXUSR | S_IROTH | S_IWOTH)

#define RVD_MAX_STOP_TIMEOUT          10

/*
 * print usage
 */

static void
usage(void)
{
	fprintf(stderr, "Usage: rvd_tests [options]\n"
					"options:\n"
					"  --check-rvd-json       Tests for checking rvd.json permission\n"
					"  --check-ovpn-bin       Tests for checking OpenVPN binary permission\n"
					"  --check-ovpn-profile   Tests for checking OpenVPN profile permission\n"
					"  --check-missing-json   Tests for checking missing JSON configuration\n"
					"  --check-missing-ovpn   Tests for checking missing OpenVPN configuration\n"
					"  --check-connect        Tests for checking OpenVPN connection to local OpenVPN server\n"
					"  --check-preconn-cmd    Tests for checking pre-connection command execution\n"
					"  --check-reload         Tests for reloading\n"
					"  --check-kill-ovpn      Tests for detecting status after killing openvpn process\n"
					"  --check-auto-connect   Tests for checking auto starting of VPN connection\n"
					"  --check-dup-config     Tests for checking duplicate configurations\n"
					);
	exit(1);
}

/*
 * set the permission for RVC configuration
 */

static void
set_file_permission(const char *path, int permission)
{
	if (chmod(path, permission) != 0) {
		fprintf(stderr, "Couldn't set permission for the configuration '%s'\n", path);
		exit(1);
	}
}

/*
 * print openvpn log file
 */

static void
print_ovpn_log(const char *ovpn_profile_name)
{
	FILE *fp;
	struct stat st;

	char ovpn_log_path[128];
	char *buf;

	/* allocate logging buffer */
	snprintf(ovpn_log_path, sizeof(ovpn_log_path), "/var/log/rvd/%s.ovpn.log", ovpn_profile_name);
	if (stat(ovpn_log_path, &st) != 0 || st.st_size == 0) {
		fprintf(stderr, "Couldn't get stat of log file '%s'\n", ovpn_log_path);
		return;
	}

	buf = (char *)malloc(st.st_size + 1);
	if (!buf) {
		fprintf(stderr, "Log file '%s' is too big. Out of memory.\n", ovpn_log_path);
		return;
	}

	/* read buffer from file */
	fp = fopen(ovpn_log_path, "r");
	if (!fp) {
		fprintf(stderr, "fopen() failed for log file '%s'.\n", ovpn_log_path);
		free(buf);
		return;
	}

	fread(buf, 1, st.st_size, fp);
	fclose(fp);

	fprintf(stderr, "\n\nOpenVPN log:\n\n%s\n\n", buf);
	free(buf);
}

/*
 * start RVD process
 */

static pid_t
start_rvd(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork() failed(err:%d).\n", errno);
		exit(1);
	}

	if (pid == 0) {
		char *const args[] = {RVD_BIN_PATH, NULL};

		execv(args[0], args);
		exit(1);
	}

	return pid;
}

/*
 * stop RVD process
 */

static int
stop_rvd(pid_t pid)
{
	int w, status;
	int timeout = 0;
	int ret = -1;

	kill(pid, SIGTERM);
	do {
		w = waitpid(pid, &status, 0);
		if (w < 0)
			return -1;
		else if (w == 0) {
			if (timeout == RVD_MAX_STOP_TIMEOUT) {
				fprintf(stderr, "RVD process isn't responding for SIGTERM signal\n");
				kill(pid, SIGKILL);
				exit(1);
			}
			timeout++;
			sleep(1);
			continue;
		}

		if (WIFEXITED(status)) {
			ret = WEXITSTATUS(status);
			break;
		}
	} while (1);

	return ret;
}

/*
 * install openvpn profile
 */

static void
install_ovpn_profile(const char *ovpn_profile_name, const char *dst_profile_name, int wrong_permission)
{
	char cmd[512];
	int status;

	/* install openvpn profile */
	snprintf(cmd, sizeof(cmd), "install -m %s profile/%s.ovpn %s/%s.ovpn",
			wrong_permission ? "0644" : "0600", ovpn_profile_name, RVC_CONFDIR_PATH, dst_profile_name);
	status = system(cmd);
	if (status) {
		fprintf(stderr, "Failed to run command '%s'(exit:%d)\n", cmd, status);
		exit(status);
	}
}

/*
 * uninstall openvpn profile
 */

static void
uninstall_ovpn_profile(const char *ovpn_profile_name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s.ovpn", RVC_CONFDIR_PATH, ovpn_profile_name);
	remove(path);
}

/*
 * install JSON config
 */

static void
install_json_config(const char *json_config_name, const char *dst_config_name)
{
	char cmd[512];
	int status;

	snprintf(cmd, sizeof(cmd), "install -m 0600 profile/%s.json %s/%s.json",
			json_config_name, RVC_CONFDIR_PATH, dst_config_name);
	status = system(cmd);
	if (status) {
		fprintf(stderr, "Failed to run command '%s'(exit:%d)\n", cmd, status);
		exit(status);
	}
}

/*
 * uninstall JSON config
 */

static void
uninstall_json_config(const char *json_config_name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s.json", RVC_CONFDIR_PATH, json_config_name);
	remove(path);
}

/*
 * read file contents
 */

static char*
read_file_contents(int fd)
{
	char buffer[256];
	ssize_t read_bytes, buf_size = 0;

	char *buf = NULL;

	while ((read_bytes = read(fd, buffer, sizeof(buffer) - 1)) != 0) {
		ssize_t total_size = read_bytes + buf_size + 1;

		buf = realloc(buf, total_size);
		if (!buf)
			break;

		strncpy(buf + buf_size, buffer, read_bytes);
		buf[total_size - 1] = '\0';

		buf_size += read_bytes;
	}

	return buf;
}

/*
 * kill openvpn process
 */

static int
kill_ovpn(const char *ovpn_profile_name)
{
	char pid_fpath[256];
	FILE *pid_fp;

	char buf[64];
	pid_t pid;

	/* get pid of openvpn process */
	snprintf(pid_fpath, sizeof(pid_fpath), "%s/%s.ovpn.pid", RVD_PID_DPATH, ovpn_profile_name);
	pid_fp = fopen(pid_fpath, "r");
	if (!pid_fp) {
		fprintf(stderr, "Couldn't open PID file of openvpn process '%s'\n", ovpn_profile_name);
		return -1;
	}

	if (fgets(buf, sizeof(buf), pid_fp) == NULL) {
		fprintf(stderr, "Couldn't read PID from '%s'\n", pid_fpath);
		fclose(pid_fp);
		return -1;
	}
	fclose(pid_fp);

	pid = atoi(buf);
	if (kill(pid, SIGKILL) != 0) {
		fprintf(stderr, "Couldn't kill OpenVPN process with pid '%d'\n", pid);
		return -1;
	}

	return 0;
}

/*
 * start connection
 */

static int
run_rvc(char **args, char **json_resp)
{
	pid_t pid;
	int w, status;

	int pipeout[2];
	int ret;

	/* create pipe to redirect stdout */
	if (pipe(pipeout) != 0) {
		fprintf(stderr, "pipe() function failed.(err:%d)\n", errno);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork() failed.(err:%d)\n", errno);
		close(pipeout[0]);
		close(pipeout[1]);
		exit(1);
	} else if (pid == 0) {
		close(pipeout[0]);
		dup2(pipeout[1], STDOUT_FILENO);

		execv(args[0], args);
	}

	close(pipeout[1]);

	w = waitpid(pid, &status, 0);
	if (w < 0) {
		fprintf(stderr, "waitpid() failed.(err:%d)\n", errno);
		close(pipeout[0]);
		return -1;
	}

	ret = WEXITSTATUS(status);
	if (ret == 0 && json_resp)
		*json_resp = read_file_contents(pipeout[0]);

	return ret;
}

/*
 * check for rvd_json permission
 */

static void
permission_check_rvd_json(void)
{
	pid_t rvd_pid;
	int exit_code;

	printf("\n\n################## Checking for permission of rvd JSON configuration ######################\n\n");

	/* check for wrong persmission */
	set_file_permission(RVD_CONFIG_PATH, RVD_CONF_WRONG_PERMISSION);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = stop_rvd(rvd_pid);
	if (exit_code == 0) {
		fprintf(stderr, "RVD is starting with the configuration with wrong permission.\n");
		exit(1);
	}

	/* check for valid permission */
	set_file_permission(RVD_CONFIG_PATH, RVD_CONF_VALID_PERMISSION);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = stop_rvd(rvd_pid);
	if (exit_code != 0) {
		fprintf(stderr, "Failed test the case 'CHECK-RVD-JSON'"
				"RVD isn't started with the configuration with valid persmission.\n");
		exit(1);
	}

	printf("Success to test the case 'CHECK-RVD-JSON'\n");
}

/*
 * check for ovpn binary permission
 */

static void
permission_check_ovpn_bin(void)
{
	pid_t rvd_pid;
	int exit_code;

	char *args[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};

	printf("\n\n################## Checking for permission of OpenVPN binary ######################\n\n");

	/* install ovpn profile and set the permission for it */
	install_ovpn_profile("test", "test", 0);
	set_file_permission(OPENVPN_BINARY_PATH, OVPN_BIN_WRONG_PERMISSION);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, NULL);
	stop_rvd(rvd_pid);
	set_file_permission(OPENVPN_BINARY_PATH, OVPN_BIN_VALID_PERMISSION);
	uninstall_ovpn_profile("test");
	if (exit_code == 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-BIN'"
				"-- Connected with OpenVPN binary with wrong permission.\n");
		exit(1);
	}

	printf("Success to test the case 'CHECK-OVPN-BIN'\n");
}

/*
 * check for ovpn profile permission
 */

static void
permission_check_ovpn_profile(void)
{
	pid_t rvd_pid;
	int exit_code;

	char *args[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};

	printf("\n\n################## Checking for permission of OpenVPN configuration ######################\n\n");

	/* install ovpn profile and set the permission for it */
	install_ovpn_profile("test", "test", 1);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, NULL);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");
	if (exit_code == 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-PROFILE'."
				"Connected using OpenVPN profile with wrong permission.\n");
		exit(1);
	}

	/* install ovpn profile and set the permission for it */
	install_ovpn_profile("test", "test", 0);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, NULL);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");
	if (exit_code != 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-PROFILE'."
				"Not connected using OpenVPN profile with valid permission.(exit_code:%d)\n", exit_code);
		exit(exit_code);
	}

	printf("Success to test the case 'CHECK-OVPN-PROFILE'\n");
}

/*
 * check for missing JSON config
 */

static void
check_missing_json(void)
{
	pid_t rvd_pid;
	int exit_code;
	char *resp_buf = NULL;

	json_object *j_obj, *j_sub_obj;
	int config_status = -1;

	char *args[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};

	printf("\n\n################## Checking for missing JSON configuration ######################\n\n");

	install_ovpn_profile("test", "test", 0);
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, &resp_buf);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");
	if (exit_code != 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-JSON-CONFIG'."
				"Faied to connect.(exit_code:%d)\n", exit_code);
		exit(exit_code);
	}

	if (!resp_buf) {
		fprintf(stderr, "Failed to test the case 'CHECK-JSON-CONFIG'."
				"Empty response buffer.\n");
		exit(1);
	}

	j_obj = json_tokener_parse(resp_buf);
	if (!j_obj) {
		free(resp_buf);
		fprintf(stderr, "Failed to test the case 'CHECK-JSON-CONFIG'."
				"Invalid JSON response buffer '%s'\n", resp_buf);
		exit(1);
	}

	printf("response JSON buffer is %s\n", resp_buf);
	if (json_object_object_get_ex(j_obj, "config-status", &j_sub_obj))
		config_status = json_object_get_int(j_sub_obj);
	else
		fprintf(stderr, "Couldn't get config-status field from json buffer '%s'\n", resp_buf);

	free(resp_buf);
	json_object_put(j_obj);

	if (config_status != OVPN_STATUS_LOADED) {
		fprintf(stderr, "Failed to test the case 'CHECK-JSON-CONFIG'"
				"Wrong 'config-status' value:%d\n", config_status);
		exit(1);
	}

	printf("Success to test the case 'CHECK-JSON-CONFIG'\n");
}

/*
 * check for missing OpenVPN profile
 */

static void
check_missing_ovpn(void)
{
	pid_t rvd_pid;
	int exit_code;

	char *args[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};

	printf("\n\n################## Checking for missing OpenVPN configuration ######################\n\n");

	uninstall_ovpn_profile("test");
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, NULL);
	stop_rvd(rvd_pid);
	if (exit_code == 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-MISSING-OVPN'"
				"Connected by missing OpenVPN profile\n");
		exit(1);
	}

	printf("Success to test the case 'CHECK-MISSING-OVPN'\n");
}

/*
 * check for missing OpenVPN profile
 */

static void
check_default_connect(void)
{
	pid_t rvd_pid;
	char *resp_buf = NULL;

	json_object *j_obj, *j_sub_obj;
	char *conn_status = NULL;

	char *args1[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};
	char *args2[] = {RVC_BIN_PATH, "test", "status", "--json", NULL};

	printf("\n\n################## Checking for OpenVPN connection with default configuration ######################\n\n");

	/* try to connect and get status */
	install_ovpn_profile("test", "test", 0);
	rvd_pid = start_rvd();
	sleep(3);
	run_rvc(args1, NULL);
	sleep(5);
	run_rvc(args2, &resp_buf);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");

	/* parse status buffer */
	j_obj = json_tokener_parse(resp_buf);
	if (!j_obj) {
		free(resp_buf);
		fprintf(stderr, "Failed to test the case 'CHECK-DEFAULT-CONNECT'"
				"Failed to parse JSON buffer '%s'\n", resp_buf);
		exit(1);
	}

	printf("response JSON buffer is %s\n", resp_buf);
	if (json_object_object_get_ex(j_obj, "status", &j_sub_obj))
		conn_status = strdup(json_object_get_string(j_sub_obj));
	else
		fprintf(stderr, "Couldn't get 'status' field from json buffer '%s'\n", resp_buf);

	free(resp_buf);
	json_object_put(j_obj);

	if (!conn_status || strcmp(conn_status, "CONNECTED") != 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-DEFAULT-CONNECT'"
				"Connection status is %s\n", conn_status);
		print_ovpn_log("test");
		if (conn_status)
			free(conn_status);
		exit(1);
	}

	free(conn_status);

	printf("Success to test the case 'CHECK-DEFAULT-CONNECT'\n");
}

/*
 * check for pre-connect command execution
 */

static void
check_preconn_cmd(void)
{
	pid_t rvd_pid;
	char *resp_buf = NULL;

	json_object *j_obj, *j_sub_obj;

	char *conn_status = NULL;
	int pre_exec_status;

	char *args1[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};
	char *args2[] = {RVC_BIN_PATH, "test", "status", "--json", NULL};

	int i;

	printf("\n\n################## Checking for OpenVPN connection with pre-connect command ######################\n\n");

	for (i = 0; i < 2; i++) {
		/* try to connect and get status */
		install_ovpn_profile("test", "test", 0);
		install_json_config(i == 0 ? "pre-exec-failed" : "pre-exec-success", "test");
		rvd_pid = start_rvd();
		sleep(3);
		run_rvc(args1, NULL);
		sleep(5);
		run_rvc(args2, &resp_buf);
		stop_rvd(rvd_pid);
		uninstall_json_config("test");
		uninstall_ovpn_profile("test");

		/* parse status buffer */
		j_obj = json_tokener_parse(resp_buf);
		if (!j_obj) {
			free(resp_buf);
			fprintf(stderr, "Failed to test the case 'CHECK-PRECONN-CMD'"
					"Failed to parse JSON buffer '%s'\n", resp_buf);
			exit(1);
		}

		printf("response JSON buffer is %s\n", resp_buf);
		if (json_object_object_get_ex(j_obj, "status", &j_sub_obj))
			conn_status = strdup(json_object_get_string(j_sub_obj));
		else
			fprintf(stderr, "Couldn't get 'status' field from json buffer '%s'\n", resp_buf);

		pre_exec_status = i == 0 ? 0 : 1;
		if (json_object_object_get_ex(j_obj, "pre-exec-status", &j_sub_obj))
			pre_exec_status = json_object_get_int(j_sub_obj);
		else
			fprintf(stderr, "Couldn't get 'pre-exec-status' field from json buffer '%s'\n", resp_buf);

		free(resp_buf);
		json_object_put(j_obj);

		if (!conn_status) {
			fprintf(stderr, "Failed to test the case 'CHECK-PRECONN-CMD'"
					"Connection status is NULL\n");
			exit(1);
		}

		if (i == 0) {
			if (strcmp(conn_status, "DISCONNECTED") != 0 || pre_exec_status != 1) {
				fprintf(stderr, "Failed to test the case 'CHECK-PRECONN-CMD'"
						"Connection state:'%s', Pre-exec status:'%d'\n", conn_status, pre_exec_status);
				exit(1);
			}
		} else {
			if (strcmp(conn_status, "CONNECTED") != 0 || pre_exec_status != 0) {
				fprintf(stderr, "Failed to test the case 'CHECK-PRECONN-CMD'"
						"Connection state:'%s', Pre-exec status:'%d'\n", conn_status, pre_exec_status);
				print_ovpn_log("test");
				exit(1);
			}
		}

		free(conn_status);
	}

	printf("Success to test the case 'CHECK-PRECONN-CMD'\n");
}

/*
 * check for reloading configurations
 */

static void
check_reload(void)
{
	pid_t rvd_pid;

	char *args1[] = {RVC_BIN_PATH, "reload", NULL};
	char *args2[] = {RVC_BIN_PATH, "test1", "status", "--json", NULL};

	int exit_code;

	/* try to connect and get status */
	install_ovpn_profile("test", "test", 0);
	rvd_pid = start_rvd();
	sleep(3);
	install_ovpn_profile("test", "test1", 0);
	run_rvc(args1, NULL);
	sleep(5);
	exit_code = run_rvc(args2, NULL);
	if (exit_code != 0) {
		stop_rvd(rvd_pid);
		fprintf(stderr, "Failed to test the case 'CHECK-RELOAD'\n");
		exit(1);
	}
	uninstall_ovpn_profile("test1");
	run_rvc(args1, NULL);
	sleep(5);
	exit_code = run_rvc(args2, NULL);
	stop_rvd(rvd_pid);
	if (exit_code == 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-RELOAD'\n");
		exit(1);
	}

	printf("Success to test the case 'CHECK-RELOAD'\n");
}

/*
 * check auto reconnect after killed openvpn process in connected status
 */

static void
check_kill_ovpn(void)
{
	pid_t rvd_pid;
	char *resp_buf = NULL;

	json_object *j_obj, *j_sub_obj;
	char *conn_status = NULL;

	char *args1[] = {RVC_BIN_PATH, "test", "connect", "--json", NULL};
	char *args2[] = {RVC_BIN_PATH, "test", "status", "--json", NULL};

	int ret;

	printf("\n\n################## Checking for detecting status after killed openvpn process ######################\n\n");

	/* try to connect and get status */
	install_ovpn_profile("test", "test", 0);
	rvd_pid = start_rvd();
	sleep(3);
	run_rvc(args1, NULL);
	sleep(5);
	ret = kill_ovpn("test");
	if (ret == 0) {
		sleep(8);
		run_rvc(args2, &resp_buf);
	}
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");

	if (ret != 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-KILL'"
				"Failed to kill OpenVPN process in force\n");
		exit(1);
	}

	/* parse status buffer */
	j_obj = json_tokener_parse(resp_buf);
	if (!j_obj) {
		free(resp_buf);
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-KILL'"
				"Failed to parse JSON buffer:'%s'\n", resp_buf);
		exit(1);
	}

	printf("response JSON buffer is %s\n", resp_buf);
	if (json_object_object_get_ex(j_obj, "status", &j_sub_obj))
		conn_status = strdup(json_object_get_string(j_sub_obj));
	else
		fprintf(stderr, "Couldn't get 'status' field from json buffer '%s'\n", resp_buf);

	free(resp_buf);
	json_object_put(j_obj);

	if (!conn_status || strcmp(conn_status, "DISCONNECTED") != 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-OVPN-KILL'"
				"Connection status is %s\n", conn_status);
		if (conn_status)
			free(conn_status);
		exit(1);
	}

	free(conn_status);

	printf("Success to test the case 'CHECK-OVPN-KILL'\n");
}

/*
 * check auto connection
 */

static void
check_auto_connect(void)
{
	pid_t rvd_pid;
	char *resp_buf = NULL;

	json_object *j_obj, *j_sub_obj;
	char *conn_status = NULL;

	char *args[] = {RVC_BIN_PATH, "test", "status", "--json", NULL};

	printf("\n\n################## Checking for auto starting of VPN connection ######################\n\n");

	/* try to connect and get status */
	install_ovpn_profile("test", "test", 0);
	install_json_config("auto-connect", "test");
	rvd_pid = start_rvd();
	sleep(10);
	run_rvc(args, &resp_buf);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");
	uninstall_json_config("test");

	/* parse status buffer */
	j_obj = json_tokener_parse(resp_buf);
	if (!j_obj) {
		free(resp_buf);
		fprintf(stderr, "Failed to test the case 'CHECK-AUTO-CONNECT'"
				"Failed to parse JSON buffer:'%s'\n", resp_buf);
		exit(1);
	}

	printf("response JSON buffer is %s\n", resp_buf);
	if (json_object_object_get_ex(j_obj, "status", &j_sub_obj))
		conn_status = strdup(json_object_get_string(j_sub_obj));
	else
		fprintf(stderr, "Couldn't get 'status' field from json buffer '%s'\n", resp_buf);

	free(resp_buf);
	json_object_put(j_obj);

	if (!conn_status || strcmp(conn_status, "DISCONNECTED") == 0) {
		fprintf(stderr, "Faield to test the case 'CHECK-AUTO-CONNECT'"
				"Connection status is %s\n", conn_status);
		print_ovpn_log("test");
		if (conn_status)
			free(conn_status);
		exit(1);
	}

	free(conn_status);

	printf("Success to test the case 'CHECK-AUTO-CONNECT'\n");
}

/*
 * check duplicate configurations
 */

static void
check_dup_config(void)
{
	pid_t rvd_pid;
	int exit_code;

	char *args[] = {RVC_BIN_PATH, "import", "new-from-ovpn", "profile/test.ovpn", NULL};

	printf("\n\n################## Checking for duplicate configurations ######################\n\n");

	/* try to connect and get status */
	install_ovpn_profile("test", "test", 0);
	install_json_config("test", "test");
	rvd_pid = start_rvd();
	sleep(3);
	exit_code = run_rvc(args, NULL);
	stop_rvd(rvd_pid);
	uninstall_ovpn_profile("test");
	uninstall_json_config("test");

	if (exit_code == 0) {
		fprintf(stderr, "Failed to test the case 'CHECK-DUP-CONFIG'\n");
		exit(1);
	}

	printf("Success to test the case 'CHECK-DUP-CONFIG'\n");
}

/*
 * main function
 */

int
main(int argc, char *argv[])
{
	if (getuid() != 0) {
		fprintf(stderr, "Please run as root privilege.\n");
		exit(1);
	}

	if (argc == 1) {
		permission_check_rvd_json();
		permission_check_ovpn_bin();
		permission_check_ovpn_profile();
		check_missing_json();
		check_missing_ovpn();
		check_default_connect();
		check_preconn_cmd();
		check_reload();
		check_kill_ovpn();
		check_auto_connect();
		check_dup_config();
	} else {
		if (strcmp(argv[1], "--check-rvd-json") == 0)
			permission_check_rvd_json();
		else if (strcmp(argv[1], "--check-ovpn-bin") == 0)
			permission_check_ovpn_bin();
		else if (strcmp(argv[1], "--check-ovpn-profile") == 0)
			permission_check_ovpn_profile();
		else if (strcmp(argv[1], "--check-missing-json") == 0)
			check_missing_json();
		else if (strcmp(argv[1], "--check-missing-ovpn") == 0)
			check_missing_ovpn();
		else if (strcmp(argv[1], "--check-connect") == 0)
			check_default_connect();
		else if (strcmp(argv[1], "--check-preconn-cmd") == 0)
			check_preconn_cmd();
		else if (strcmp(argv[1], "--check-reload") == 0)
			check_reload();
		else if (strcmp(argv[1], "--check-kill-ovpn") == 0)
			check_kill_ovpn();
		else if (strcmp(argv[1], "--check-auto-connect") == 0)
			check_auto_connect();
		else if (strcmp(argv[1], "--check-dup-config") == 0)
			check_dup_config();
		else
			usage();
	}

	return 0;
}
