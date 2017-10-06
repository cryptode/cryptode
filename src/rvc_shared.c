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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#include <json-c/json.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "common.h"
#include "util.h"

#include "rvc_shared.h"

/* TunnelBlick credential types */
#define TBLK_CRED_TYPE_CA		0
#define TBLK_CRED_TYPE_CERT		1
#define TBLK_CRED_TYPE_KEY		2

/* static global variables */
static int g_sock;

/*
 * rvd connection state strings
 */

struct rvd_vpn_state {
	enum RVD_VPNCONN_STATE state;
	const char *state_str;
} g_conn_state[] = {
	{RVD_CONN_STATE_DISCONNECTED, "DISCONNECTED"},
	{RVD_CONN_STATE_CONNECTED, "CONNECTED"},
	{RVD_CONN_STATE_CONNECTING, "CONNECTING"},
	{RVD_CONN_STATE_DISCONNECTING, "DISCONNECTING"},
	{RVD_CONN_STATE_RECONNECTING, "RECONNECTING"},
	{RVD_CONN_STATE_UNKNOWN, NULL}
};

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
 * read PEM data from X509 file
 */

static int read_x509_data(FILE *fp, char **x509_data)
{
	X509 *x509 = NULL;
	BIO *bio = NULL;

	char *p;

	/* try to read in PEM format */
	if (!PEM_read_X509(fp, &x509, NULL, NULL)) {
		/* if file isn't PEM format, then try to read in DER format */
		fseek(fp, 0, SEEK_SET);

		/* read in DER format */
		if (!d2i_X509_fp(fp, &x509))
			return -1;
	}

	/* write X509 as PEM format to bio */
	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		X509_free(x509);
		return -1;
	}

	if (!PEM_write_bio_X509(bio, x509)) {
		X509_free(x509);
		return -1;
	}

	/* free X509 */
	X509_free(x509);

	/* allocate and read buffer from bio */
	p = (char *) malloc(bio->num_write + 1);
	if (!p) {
		BIO_free(bio);
		return -1;
	}

	BIO_read(bio, p, (int) bio->num_write);
	p[bio->num_write] = '\0';

	/* free bio */
	BIO_free(bio);

	*x509_data = p;

	return 0;
}

/*
 * read key data from file
 */

static int read_key_data(FILE *fp, char **key_data)
{
	unsigned char buf[512];

	char *p = NULL;
	size_t len = 0;

	int ret = 0;

	while (!feof(fp)) {
		size_t read_bytes;

		/* read buffer */
		read_bytes = fread(buf, 1, sizeof(buf), fp);
		if (read_bytes > 0) {
			p = realloc(p, len + read_bytes + 1);
			if (!p) {
				ret = -1;
				break;
			}

			memcpy(&p[len], buf, read_bytes);
			len += read_bytes;
		}

	}

	/* set '\0' */
	p[len] = '\0';

	*key_data = p;

	return ret;
}

/*
 * write tunnelblick key and certs to OpenVPN config file
 */

static int write_tblk_cred(const char *dir, int cred_type, const char *fname, FILE *dst_fp)
{
	FILE *cred_fp;

	char cred_path[RVD_MAX_PATH];
	char *cred_data;

	int ret;

	/* get the full path of credential */
	snprintf(cred_path, sizeof(cred_path), "%s/%s", dir, fname);

	/* open credential file */
	cred_fp = fopen(cred_path, "rb");
	if (!cred_fp)
		return -1;

	/* read credetial data */
	if (cred_type == TBLK_CRED_TYPE_CA || cred_type == TBLK_CRED_TYPE_CERT)
		ret = read_x509_data(cred_fp, &cred_data);
	else
		ret = read_key_data(cred_fp, &cred_data);

	/* close file */
	fclose(cred_fp);

	if (ret != 0)
		return -1;

	if (cred_type == TBLK_CRED_TYPE_CA) {
		fprintf(dst_fp, "<ca>\n");
		fprintf(dst_fp, "%s\n", cred_data);
		fprintf(dst_fp, "</ca>\n");
	} else if (cred_type == TBLK_CRED_TYPE_CERT) {
		fprintf(dst_fp, "<cert>\n");
		fprintf(dst_fp, "%s\n", cred_data);
		fprintf(dst_fp, "</cert>\n");
	} else {
		fprintf(dst_fp, "<key>\n");
		fprintf(dst_fp, "%s\n", cred_data);
		fprintf(dst_fp, "</key>\n");
	}

	/* free credential data */
	free(cred_data);

	return 0;
}

/*
 * convert tblk profile to OpenVPN profile
 */

static int convert_tblk_to_ovpn(const char *conf_dir, const char *container_path, const char *ovpn_name)
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
	new_fd = open(new_ovpn_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
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

		if (cred_type >= 0 &&
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
		ret = copy_file_into_dir(conf_dir, new_ovpn_path, S_IRUSR | S_IWUSR);

	/* remove new profile */
	remove(new_ovpn_path);

	return ret;
}

/*
 * import openvpn profile from TunnelBlick profile
 */

static int import_ovpn_from_tblk(const char *conf_dir, const char *tblk_path)
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
		if (convert_tblk_to_ovpn(conf_dir, container_path, entry->d_name) == 0)
			count++;
	}

	/* close directory */
	closedir(dir);

	return count;
}

/*
 * send command and print response
 */

static int send_cmd(enum RVD_CMD_CODE cmd_code, const char *cmd_param, int use_json, char **resp_data)
{
	char *cmd;
	ssize_t ret;

	char resp[RVD_MAX_RESP_LEN];

	rvd_json_object_t cmd_jobjs[] = {
		{"cmd", RVD_JTYPE_INT, &cmd_code, 0, false, NULL},
		{"json", RVD_JTYPE_BOOL, &use_json, 0, false, NULL},
		{"param", RVD_JTYPE_STR, (void*)cmd_param, 0, false, NULL}
	};

	/* build JSON command */
	if (rvd_json_build(cmd_jobjs, sizeof(cmd_jobjs) / sizeof(rvd_json_object_t), &cmd) != 0) {
		fprintf(stderr, "Couldn't create JSON object\n");
		return RVD_RESP_NO_MEMORY;
	}

	/* send command */
	ret = send(g_sock, cmd, strlen(cmd), 0);

	/* free command buffer */
	free(cmd);

	if (ret <= 0) {
		fprintf(stderr, "Couldn't send command %s\n", cmd);
		return RVD_RESP_SOCK_CONN;
	}

	/* receive response */
	memset(resp, 0, sizeof(resp));
	if (recv(g_sock, resp, sizeof(resp), 0) <= 0) {
		fprintf(stderr, "Couldn't receive response\n");
		return RVD_RESP_SOCK_CONN;
	}

	*resp_data = strdup(resp);

	return RVD_RESP_OK;
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
	strlcpy(addr.sun_path, RVD_LISTEN_SOCK_PATH, sizeof(addr.sun_path));

	/* connect to rvd */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

/*
 * send command to rvd daemon
 */

int send_cmd_to_rvd(int cmd_code, const char *param, int json_format, char **resp_data)
{
	int ret;

	/* connect to rvd daemon */
	ret = connect_to_rvd();
	if (ret != 0) {
		fprintf(stderr, "Couldn't to connect to rvd(err:%d)\n", errno);
		return RVD_RESP_SOCK_CONN;
	}

	/* send command to core */
	ret = send_cmd(cmd_code, param, json_format, resp_data);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * Try to connect VPN server
 */

int rvc_connect(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_CONNECT, name, json_format, conn_status);
}

/*
 * Try to disconnect from VPN server
 */

int rvc_disconnect(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_DISCONNECT, name, json_format, conn_status);
}

/*
 * Get connection status
 */

int rvc_get_status(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_rvd(RVD_CMD_STATUS, name, json_format, conn_status);
}

/*
 * Get the configuration directory
 */

int rvc_get_confdir(char **conf_dir)
{
	return send_cmd_to_rvd(RVD_CMD_GET_CONFDIR, NULL, false, conf_dir);
}


/*
 * reload VPN connections
 */

int rvc_reload()
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
 * import VPN profiles
 */

int rvc_import(int import_type, const char *import_path)
{
	int ret;
	char *conf_dir = NULL;

	/* check UID */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* get configuration directory path */
	if (rvc_get_confdir(&conf_dir) != 0) {
		fprintf(stderr, "Couldn't get the configuration directory of rvd\n");
		return RVD_RESP_INVALID_CONF_DIR;
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

	if (import_type == RVC_VPN_PROFILE_TBLK) {
		ret = import_ovpn_from_tblk(conf_dir, import_path);
		if (ret <= 0) {
			fprintf(stderr, "Couldn't import OpenVPN profile from TunnelBlick profile '%s'", import_path);
			return RVD_RESP_INVALID_PROFILE_TYPE;
		}
	} else {
		size_t fsize;

		/* checks whether size of imported profile */
		fsize = get_file_size(import_path);
		if (fsize <= 0 || fsize >= RVC_MAX_IMPORT_SIZE) {
			fprintf(stderr, "Invalid size or too large file '%s'\n", import_path);
			return RVD_RESP_IMPORT_TOO_LARGE;
		}

		/* checks whether same profile is exist */
		if (is_exist_file_in_dir(conf_dir, import_path)) {
			fprintf(stderr, "The same configuration is already exist in '%s'\n", conf_dir);
			return RVD_RESP_IMPORT_EXIST_PROFILE;
		}

		/* copy files into rvd config directory */
		if (copy_file_into_dir(conf_dir, import_path, S_IRUSR | S_IWUSR) != 0) {
			fprintf(stderr, "Couldn't copy file '%s' into '%s'\n", import_path, conf_dir);
			return RVD_RESP_UNKNOWN_ERR;
		}
	}

	fprintf(stderr, "Success to import VPN configuration from '%s'\n", import_path);

	return rvc_reload();
}

/*
 * remove VPN connection
 */

int rvc_remove(const char *conn_name, int force)
{
	char *conn_status = NULL;

	int i, resp_code;

	enum RVD_VPNCONN_STATE state = RVD_CONN_STATE_UNKNOWN;
	char state_str[64];
	char profile_path[RVD_MAX_PATH];

	rvd_json_object_t status_jobjs[] = {
		{"code", RVD_JTYPE_INT, &resp_code, 0, true, NULL},
		{"status", RVD_JTYPE_STR, state_str, sizeof(state_str), true, "data"},
		{"profile", RVD_JTYPE_STR, profile_path, sizeof(profile_path), true, "data"}
	};

	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* check connection status */
	if (rvc_get_status(conn_name, 1, &conn_status) != 0) {
		fprintf(stderr, "Couldn't get status for VPN connection '%s'\n", conn_name);
		return RVD_RESP_RVD_NOT_RUNNING;
	}

	/* parse response */
	if (rvd_json_parse(conn_status, status_jobjs, sizeof(status_jobjs) / sizeof(rvd_json_object_t)) != 0) {
		fprintf(stderr, "Couldn't parse connection status response '%s'\n", conn_status);
		free(conn_status);

		return RVD_RESP_JSON_INVALID;
	}

	/* check response code */
	if (resp_code != RVD_RESP_OK) {
		fprintf(stderr, "Couldn't find VPN connection with name '%s'\n", conn_name);
		return RVD_RESP_CONN_NOT_FOUND;
	}

	/* get connection status */
	for (i = 0; g_conn_state[i].state_str != NULL; i++) {
		if (strcmp(g_conn_state[i].state_str, state_str) == 0) {
			state = g_conn_state[i].state;
			break;
		}
	}

	if (state != RVD_CONN_STATE_DISCONNECTED && !force) {
		fprintf(stderr, "The connection '%s' is in connected or pending progress.\n", conn_name);
		return RVD_RESP_CONN_IN_PROGRESS;
	}

	/* remove profile connection */
	remove(profile_path);

	/* reload rvd */
	return rvc_reload();
}

/*
 * check whether DNS utility has installed perperly
 */

static int check_dns_util_path()
{
	/* check whether dns utility is exist */
	if (!is_exist_path(RVC_DNS_UTIL_PATH, 0)) {
		fprintf(stderr, "No exist rvc DNS utility '%s'\n", RVC_DNS_UTIL_PATH);
		return RVD_RESP_NO_EXIST_DNS_UTIL;
	}

	/* check whether rvc utility is exist and valid permission */
	if (!is_valid_permission(RVC_DNS_UTIL_PATH, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) ||
		!is_owned_by_user(RVC_DNS_UTIL_PATH, "root")) {
		fprintf(stderr, "rvc DNS utility '%s' has wrong owner or permission.\n", RVC_DNS_UTIL_PATH);
		return RVD_RESP_WRONG_PERMISSION;
	}

	return RVD_RESP_OK;
}

/*
 * Override DNS settings
 */

int rvc_dns_override(int enabled, const char *dns_ip_list)
{
	char cmd[RVD_MAX_PATH];
	int ret;

	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* check utility path */
	ret = check_dns_util_path();
	if (ret != RVD_RESP_OK)
		return ret;

	/* build command string */
	if (enabled)
		snprintf(cmd, sizeof(cmd), "%s enable %s", RVC_DNS_UTIL_PATH, dns_ip_list);
	else
		snprintf(cmd, sizeof(cmd), "%s disable", RVC_DNS_UTIL_PATH);

	/* run command */
	ret = system(cmd);
	if (ret != 0)
		return RVD_RESP_ERR_DNS_UTIL;

	return RVD_RESP_OK;
}

/*
 * print DNS setting on the system
 */

int rvc_dns_print(void)
{
	char cmd[RVD_MAX_PATH];
	int ret;

	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privilege. Please run with 'sudo'\n");
		return RVD_RESP_SUDO_REQUIRED;
	}

	/* check utility path */
	ret = check_dns_util_path();
	if (ret != RVD_RESP_OK)
		return ret;

	/* build command */
	snprintf(cmd, sizeof(cmd), "%s status", RVC_DNS_UTIL_PATH);

	/* run command */
	ret = system(cmd);
	if (ret != 0)
		return RVD_RESP_ERR_DNS_UTIL;

	return RVD_RESP_OK;
}
