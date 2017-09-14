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

/* static global variables */
static int g_sock;

static char g_cmd[RVD_MAX_CMD_LEN + 1];
static char g_resp[RVD_MAX_RESP_LEN + 1];

/*
 * get process ID of rvd process
 */

static pid_t
get_pid_of_rvd()
{
	FILE *pid_fp;
	char buf[128];

	pid_t pid = 0;

	/* open pid file */
	pid_fp = fopen(RVD_PID_FPATH, "r");
	if (!pid_fp)
		return 0;

	/* get pid */
	while (fgets(buf, sizeof(buf), pid_fp) != NULL) {
		if (buf[strlen(buf) - 1] == '\n')
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

	return pid;
}

/*
 * reload rvd daemon
 */

static int reload_rvd()
{
	pid_t pid_rvd;

	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* get process ID of rvd */
	pid_rvd = get_pid_of_rvd();
	if (pid_rvd <= 0) {
		fprintf(stderr, "The rvd process isn't running.\n");
		return RVD_RESP_RVD_NOT_RUNNING;
	}

	/* send SIGUSR1 signal */
	if (kill(pid_rvd, SIGUSR1) < 0) {
		fprintf(stderr, "Couldn't to send SIGUSR1 signal to rvd process.(err:%d)\n", errno);
		return RVD_RESP_SEND_SIG; 
	} else
		fprintf(stderr, "Sending reload signal to rvd process '%d' has succeeded.\n", pid_rvd);

	return RVD_RESP_OK;
}

/*
 * write tunnelblick key and certs to OpenVPN config file
 */

static int write_tblk_cred(const char *dir, int cred_type, const char *fname, FILE *dst_fp)
{
	char cred_path[RVD_MAX_PATH];
	char *cred_data;

	

	/* get the full path of credential */
	snprintf(cred_path, sizeof(cred_path), "%s/%s", dir, fname);

	/* open credential file */
	cred_fp = fopen(cred_path, "r");
	if (!cred_fp)
		return -1;

	if (cred_type == TBLK_CRED_TYPE_CA || cred_type == TBLK_CRED_TYPE_CERT) {
		X509 *x509;

		/* read */
	} else {

	}

}

/*
 * convert tblk profile to OpenVPN profile
 */

static int convert_tblk_to_ovpn(const char *container_path, const char *ovpn_name)
{
	char ovpn_path[RVD_MAX_PATH];
	char new_ovpn_path[RVD_MAX_PATH];

	FILE *fp, *new_fp;
	int fd, new_fd;

	char buf[512];

	size_t fsize;

	int ret = 0;

	/* build full path of profile */
	snprintf(ovpn_path, sizeof(ovpn_path), "%s/%s", container_path, ovpn_name);
	snprintf(new_ovpn_path, sizeof(new_ovpn_path), "/tmp/%s", ovpn_name);

	/* remove old one */
	remove(new_ovpn_path);

	/* check the file size */
	fsize = get_file_size(ovpn_path);
	if (fsize > RVC_MAX_IMPORT_SIZE)
		return -1;

	/* open the profile */
	fd = open(ovpn_path, O_RDONLY);
	if (fd < 0)
		return -1;

	fp = fdopen(fd, "r");
	if (!fp) {
		close(fd);
		return -1;
	}

	/* open new profile */
	new_fd = open(new_ovpn_path, O_CREAT | O_WRONLY);
	if (new_fd < 0) {
		fclose(fp);
		return -1;
	}

	new_fp = fdopen(new_fd, "w");
	if (!new_fp) {
		close(new_fd);
		fclose(fp);

		return -1;
	}

	/* copy each line in profile */
	while (fgets(buf, sizeof(buf), fp) != 0) {
		int cred_type = -1;
		const char *cred_name;

		/* remove endline */
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if (strncmp(buf, "ca ", 3) == 0) {
			cred_name = buf + 3;
			cred_type = TBLK_CRED_TYPE_CA;
		} else if (strncmp(buf, "cert ", 5) == 0) {
			cred_name = buf + 5;
			cred_type = TBLK_CRED_TYPE_CERT;
		} else if (strncmp(buf, "key ", 4) == 0) {
			cred_name = buf + 4;
			cred_type = TBLK_CRED_TYPE_KEY;
		} else
			fprintf(new_fp, "%s\n", buf);

		if (cred_type > 0 &&
		    write_tblk_cred(container_path, cred_type, cred_name, new_fp) != 0) {
			ret = -1;
			break;
		}
	}

	/* close file pointers */
	fclose(new_fp);
	fclose(fp);

	/* copy new profile to rvd configuratio directory */
	if (ret == 0)
		ret = copy_file_into_dir(new_ovpn_path, RVD_DEFAULT_VPN_CONFIG_DIR, S_IRUSR | S_IWUSR);

	/* remove new profile */
	remove(new_ovpn_path);

	return ret;
}

/*
 * import openvpn profile from TunnelBlick profile
 */

static int import_ovpn_from_tblk(const char *tblk_path, int *count)
{
	DIR *dir;
	struct dirent *entry;

	char container_path[RVD_MAX_PATH];

	struct stat st;
	int count = 0;

	/* check whether tblk profile path is directory */
	if (stat(tblk_path, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;

	/* build containter path */
	snprintf(container_path, sizeof(container_path), "%s/Contents/Resources", tblk_path);

	/* open directory */
	dir = opendir(container_path);
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_REG)
			continue;

		/* check extension */
		if (!is_valid_extension(entry->d_name, ".ovpn"))
			continue;

		/* convert tblk profile to openvpn */
		if (convert_tblk_to_ovpn(container_path, entry->d_name) == 0)
			count++;
	}

	/* close directory */
	closedir(dir);

	return count;
}

/*
 * import VPN connection
 */

static int import_vpn_connection(int import_type, const char *import_path)
{
	int ret;

	/* check UID */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* check import type */
	if (import_type != RVC_VPN_PROFILE_OVPN && import_type != RVC_VPN_PROFILE_TBLK) {
		fprintf(stderr, "Invalid VPN profile type\n");
		return RVD_RESP_INVALID_PROFILE_TYPE;
	}

	/* checks whether import_path has valid extension */
	if (!is_valid_extension(import_path, import_type == RVC_VPN_PROFILE_TBLK ? ".tblk" : ".ovpn")) {
		fprintf(stderr, "Invalid extension of file '%s'\n", import_path);
		return RVD_RESP_INVALID_PROFILE_TYPE;
	}

	if (import_type == RVC_VPN_PROFILE_TBLK &&) {
		ret = import_ovpn_from_tblk(import_path);
		if (ret <= 0) {
			fprintf(stderr, "Couldn't import OpenVPN profile from TunnelBlick profile '%s'", import_path);
			return RVD_RESP_INVALID_PROFILE_TYPE;
		}
	} else {
		size_t fsize;

		/* checks whether size of imported profile */
		fsize = get_file_size(ovpn_profile);
		if (fsize <= 0 || fsize >= RVC_MAX_IMPORT_SIZE) {
			fprintf(stderr, "Invalid size or too large file '%s'\n", ovpn_profile);
			return RVD_RESP_IMPORT_TOO_LARGE;
		}

		/* copy files into rvd config directory */
		if (copy_file_into_dir(ovpn_profile, RVD_DEFAULT_VPN_CONFIG_DIR, S_IRUSR | S_IWUSR) != 0) {
			fprintf(stderr, "Couldn't copy file '%s' into '%s'\n", ovpn_profile, RVD_DEFAULT_VPN_CONFIG_DIR);
			return RVD_RESP_UNKNOWN_ERR;
		}

		return 0;
	}

	fprintf(stderr, "Success to import VPN configuration from '%s'\n", import_path);

	return reload_rvd();
}

/*
 * send command and print response
 */

static struct {
	enum RVD_CMD_CODE code;
	const char *name;
} g_cmd_names[] = {
	{RVD_CMD_LIST, "list"},
	{RVD_CMD_CONNECT, "connect"},
	{RVD_CMD_DISCONNECT, "disconnect"},
	{RVD_CMD_STATUS, "status"},
	{RVD_CMD_SCRIPT_SECURITY, "script-security"},
	{RVD_CMD_RELOAD, "reload"},
	{RVD_CMD_IMPORT, "import"},
	{RVD_CMD_UNKNOWN, NULL}
};

static int send_cmd(enum RVD_CMD_CODE cmd_code, const char *cmd_param, bool use_json)
{
	json_object *j_obj;

	/* create json object */
	j_obj = json_object_new_object();
	if (!j_obj) {
		fprintf(stderr, "Couldn't create JSON object\n");
		return RVD_RESP_NO_MEMORY;
	}

	json_object_object_add(j_obj, "cmd", json_object_new_int(cmd_code));

	if (cmd_param)
		json_object_object_add(j_obj, "param", json_object_new_string(cmd_param));

	json_object_object_add(j_obj, "json", json_object_new_boolean(use_json ? 1 : 0));

	snprintf(g_cmd, sizeof(g_cmd), "%s", json_object_get_string(j_obj));

	/* free json object */
	json_object_put(j_obj);

	/* send command */
	if (send(g_sock, g_cmd, strlen(g_cmd), 0) <= 0) {
		fprintf(stderr, "Couldn't send command %s\n", g_cmd);
		return RVD_RESP_SOCK_CONN;
	}

	/* receive response */
	memset(g_resp, 0, sizeof(g_resp));
	if (recv(g_sock, g_resp, sizeof(g_resp), 0) <= 0) {
		fprintf(stderr, "Couldn't receive response\n");
		return RVD_RESP_SOCK_CONN;
	}

	printf("%s\n", g_resp);

	return RVD_RESP_OK;
}

/*
 * parse response from rvd
 */

static int parse_resp(char **resp_data)
{
	json_object *j_obj, *j_sub_obj;
	int ret = RVD_RESP_OK;

	/* parse JSON response */
	j_obj = json_tokener_parse(g_resp);
	if (!j_obj)
		return RVD_RESP_JSON_INVALID;

	/* get code */
	if (!json_object_object_get_ex(j_obj, "code", &j_sub_obj) ||
		json_object_get_type(j_obj) != json_type_int) {
		ret = RVD_RESP_JSON_INVALID;
		goto end;
	}

	ret = json_object_get_int(j_sub_obj);

	/* get response */
	if (json_object_object_get_ex(j_obj, "data", &j_sub_obj)) {
		const char *p = json_object_get_string(j_sub_obj);

		/* allocate and set response data */
		*resp_data = (char *) malloc(strlen(p) + 1);
		if (*resp_data == NULL) {
			ret = RVD_RESP_NO_MEMORY;
			goto end;
		}

		strcpy(*resp_data, p);
		(*resp_data)[strlen(p)] = '\0';
	}

end:
	/* free json object */
	json_object_put(j_obj);

	return ret;
}

/*
 * connect to rvd
 */

static int connect_to_rvd(void)
{
	struct sockaddr_un addr;

	/* create unix domain socket */
	g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_sock < 0)
		return -1;

	/* set server address */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, RVD_LISTEN_SOCK_PATH);

	/* connect to rvd */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

/*
 * send command to rvd daemon
 */

static int send_cmd_to_rvd(int cmd_code, const char *param, bool json_format, char **resp_data)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0) {
		fprintf(stderr, "Couldn't to connect to rvd(err:%d)\n", errno);
		return RVD_RESP_SOCK_CONN;
	}

	/* send command to core */
	ret = send_cmd(cmd_code, param, json_format);
	if (ret == 0 && resp_data)
		ret = parse_resp(resp_data);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * List RVC connections
 */

int rvc_list_connections(char **connections)
{
	return send_cmd_to_rvd(RVD_CMD_LIST, NULL, true, connections);
}

/*
 * Try to connect VPN server
 */

int rvc_connect(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_CONNECT, name, true, conn_status);
}

/*
 * Try to disconnect from VPN server
 */

int rvc_disconnect(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_DISCONNECT, name, true, conn_status);
}

/*
 * Get connection status
 */

int rvc_get_status(const char *name, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_STATUS, name, true, conn_status);
}

/*
 * reload VPN connections
 */

int rvc_reload()
{
	return reload_rvd();
}

/*
 * import VPN profiles
 */

int rvc_import(int import_type, const char *import_path)
{
	return import_vpn_connection(import_type, import_path);
}
