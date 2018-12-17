
/*
 * Copyright (c) 2017, [Ribose Inc](https://www.cryptode.com).
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
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#ifdef _DARWIN_C_SOURCE
#include <mach-o/dyld.h>
#endif

#include <json-c/json.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "common.h"
#include "conf.h"
#include "util.h"
#include "json.h"

#include "coc_shared.h"

/* TunnelBlick credential types */
#define TBLK_CRED_TYPE_CA		0
#define TBLK_CRED_TYPE_CERT		1
#define TBLK_CRED_TYPE_KEY		2

/* static global variables */
static int g_sock;

/*
 * cryptode connection state strings
 */

struct cod_vpn_state {
	enum COD_VPNCONN_STATE state;
	const char *state_str;
} g_conn_state[] = {
	{COD_CONN_STATE_DISCONNECTED, "DISCONNECTED"},
	{COD_CONN_STATE_CONNECTED, "CONNECTED"},
	{COD_CONN_STATE_CONNECTING, "CONNECTING"},
	{COD_CONN_STATE_DISCONNECTING, "DISCONNECTING"},
	{COD_CONN_STATE_RECONNECTING, "RECONNECTING"},
	{COD_CONN_STATE_UNKNOWN, NULL}
};

/*
 * get process ID of cryptoded process
 */

static pid_t
get_pid_of_cryptoded()
{
	FILE *pid_fp;
	pid_t pid = 0;

	char *buf = NULL;
	size_t buf_size = 0;
	ssize_t buf_len;

	/* open pid file */
	pid_fp = fopen(COD_PID_FPATH, "r");
	if (!pid_fp)
		return 0;

	buf_len = getline(&buf, &buf_size, pid_fp);
	if (buf_len > 0) {
		if (buf[buf_len - 1] == '\n')
			buf[buf_len - 1] = '\0';
		pid = atoi(buf);
		free(buf);
	}
	fclose(pid_fp);

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
			if (!p)
				return -1;

			memcpy(&p[len], buf, read_bytes);
			len += read_bytes;
		}

	}
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

	char cred_path[COD_MAX_PATH];
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
	char ovpn_path[COD_MAX_PATH];
	char new_ovpn_path[COD_MAX_PATH];

	FILE *fp, *new_fp = NULL;
	int new_fd;

	size_t fsize;

	int ret = 0;

	/* build full path of profile */
	snprintf(ovpn_path, sizeof(ovpn_path), "%s/%s", container_path, ovpn_name);
	snprintf(new_ovpn_path, sizeof(new_ovpn_path), "/tmp/%s", ovpn_name);

	/* remove old one */
	unlink(new_ovpn_path);

	/* check the file size */
	fsize = get_file_size(ovpn_path);
	if (fsize > COC_MAX_IMPORT_SIZE)
		return -1;

	/* open the profile */
	fp = fopen(ovpn_path, "r");
	if (!fp)
		return -1;

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
	while (1) {
		char *buf = NULL;
		size_t buf_size = 0;
		ssize_t buf_len;

		int cred_type = -1;
		const char *cred_name;

		buf_len = getline(&buf, &buf_size, fp);
		if (buf_len <= 0)
			break;

		if (buf[buf_len - 1] == '\n')
			buf[buf_len - 1] = '\0';

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
			free(buf);
			break;
		}
		free(buf);
	}
	fclose(new_fp);
	fclose(fp);

	/* copy new profile to cryptoded configuration directory */
	if (ret == 0)
		ret = copy_file_into_dir(conf_dir, new_ovpn_path, S_IRUSR | S_IWUSR);

	/* remove new profile */
	unlink(new_ovpn_path);

	return ret;
}

/*
 * import openvpn profile from TunnelBlick profile
 */

static int import_ovpn_from_tblk(const char *conf_dir, const char *tblk_path)
{
	DIR *dir;
	struct dirent *entry;

	char container_path[COD_MAX_PATH];

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

static int send_cmd(enum COD_CMD_CODE cmd_code, const char *cmd_param, int use_json, char **resp_data)
{
	char *cmd;
	ssize_t ret;

	char resp[COD_MAX_RESP_LEN];

	cod_json_object_t cmd_jobjs[] = {
		{"cmd", COD_JTYPE_INT, &cmd_code, 0, false, NULL},
		{"json", COD_JTYPE_BOOL, &use_json, 0, false, NULL},
		{"param", COD_JTYPE_STR, (void *)cmd_param, 0, false, NULL}
	};

	/* build JSON command */
	if (cod_json_build(cmd_jobjs, sizeof(cmd_jobjs) / sizeof(cod_json_object_t), &cmd) != 0) {
		fprintf(stderr, "Couldn't create JSON object\n");
		return COD_RESP_NO_MEMORY;
	}

	/* send command */
	ret = send(g_sock, cmd, strlen(cmd), 0);
	if (ret <= 0) {
		fprintf(stderr, "Couldn't send command %s\n", cmd);
		free(cmd);
		return COD_RESP_SOCK_CONN;
	}
	free(cmd);

	/* receive response */
	ret = recv(g_sock, resp, sizeof(resp) - 1, 0);
	if (ret <= 0) {
		fprintf(stderr, "Couldn't receive response\n");
		return COD_RESP_SOCK_CONN;
	}
	resp[ret] = '\0';
	*resp_data = strdup(resp);

	return COD_RESP_OK;
}

/*
 * parse response
 */

static int parse_resp(const char *resp, char **resp_data)
{
	json_object *j_obj, *j_sub_obj;

	int resp_code;

	/* parse response */
	j_obj = json_tokener_parse(resp);
	if (!j_obj) {
		fprintf(stderr, "Invalid JSON response '%s'\n", resp);
		return COD_RESP_JSON_INVALID;
	}

	if (!json_object_object_get_ex(j_obj, "code", &j_sub_obj)) {
		fprintf(stderr, "Invalid JSON response '%s'\n", resp);
		json_object_put(j_obj);
		return COD_RESP_JSON_INVALID;
	}

	resp_code = json_object_get_int(j_sub_obj);

	if (!json_object_object_get_ex(j_obj, "data", &j_sub_obj)) {
		fprintf(stderr, "Invalid JSON response '%s'\n", resp);
		json_object_put(j_obj);
		return COD_RESP_JSON_INVALID;
	}

	*resp_data = strdup(json_object_get_string(j_sub_obj));

	return resp_code;
}

/*
 * connect to cryptoded
 */

static int connect_to_cryptoded(void)
{
	struct sockaddr_un addr;

	/* create unix domain socket */
	g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_sock < 0)
		return -1;

	/* set server address */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, COD_LISTEN_SOCK_PATH, sizeof(addr.sun_path));

	/* connect to cryptoded */
	return connect(g_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
}

/*
 * send command to cryptoded daemon
 */

int send_cmd_to_cryptoded(int cmd_code, const char *param, int json_format, char **resp_data)
{
	int ret;
	char *resp;

	/* connect to cryptoded daemon */
	ret = connect_to_cryptoded();
	if (ret != 0) {
		fprintf(stderr, "Couldn't to connect to cryptoded(err:%d)\n", errno);
		return COD_RESP_SOCK_CONN;
	}

	/* send command to core */
	ret = send_cmd(cmd_code, param, json_format, &resp);
	if (ret == COD_RESP_OK)
		ret = parse_resp(resp, resp_data);

	/* close socket */
	close(g_sock);

	return ret;
}

/*
 * Try to connect VPN server
 */

int coc_connect(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_cryptoded(COD_CMD_CONNECT, name, json_format, conn_status);
}

/*
 * Try to disconnect from VPN server
 */

int coc_disconnect(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_cryptoded(COD_CMD_DISCONNECT, name, json_format, conn_status);
}

/*
 * Try to reconnect VPN server
 */

int coc_reconnect(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_cryptoded(COD_CMD_RECONNECT, name, json_format, conn_status);
}

/*
 * Get connection status
 */

int coc_get_status(const char *name, int json_format, char **conn_status)
{
	return send_cmd_to_cryptoded(COD_CMD_STATUS, name, json_format, conn_status);
}

/*
 * Get the configuration directory
 */

int coc_get_confdir(char **conf_dir)
{
	return send_cmd_to_cryptoded(COD_CMD_GET_CONFDIR, NULL, false, conf_dir);
}


#ifdef ENABLE_STRICT_PATH

/*
 * check whether cryptode is located into desired installation directory
 */

static const char *g_coc_allowed_paths[] = {
#ifdef _DARWIN_C_SOURCE
	"/opt/cryptode/bin/cryptode",
#else
	"/usr/bin/cryptode",
	"/usr/local/bin/cryptode",
#endif
	NULL
};

static int check_coc_bin_path(void)
{
	char run_path[COD_MAX_PATH];
	int i = 0;

#if _DARWIN_C_SOURCE
	unsigned int len;

	/* get current working directory */
	len = sizeof(run_path);
	if (_NSGetExecutablePath(run_path, &len) != 0)
		return -1;
#else
	if (readlink("/proc/self/exe", run_path, sizeof(run_path)) < 0)
		return -1;
#endif

	for (i = 0; g_coc_allowed_paths[i] != NULL; i++) {
		if (strcmp(g_coc_allowed_paths[i], run_path) == 0)
			return 0;
	}

	return -1;
}
#endif

/*
 * pre-checks for running environment of cryptode utility
 */

static int pre_check_running_env(void)
{
	/* check UID is root */
	if (getuid() != 0) {
		fprintf(stderr, "This option requires root privileges. Please run with 'sudo'\n");
		return COD_RESP_SUDO_REQUIRED;
	}

#ifdef ENABLE_STRICT_PATH
	/* check cryptode binrary path */
	if (check_coc_bin_path() != 0) {
#ifdef _DARWIN_C_SOURCE
		fprintf(stderr, "Wrong path, cryptode needs to be installed in '/opt/cryptode/bin'\n");
#else
		fprintf(stderr, "Wrong path, cryptode needs to be installed in '/usr/bin' or '/usr/local/bin'\n");
#endif
		return COD_RESP_ERR_WRONG_COC_PATH;
	}
#endif

	return 0;
}

/*
 * reload VPN connections
 */

int coc_reload(void)
{
	pid_t pid_cryptoded;
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* get process ID of cryptoded */
	pid_cryptoded = get_pid_of_cryptoded();
	if (pid_cryptoded <= 0) {
		fprintf(stderr, "The cryptoded process isn't running.\n");
		return COD_RESP_COD_NOT_RUNNING;
	}

	/* send SIGUSR1 signal */
	if (kill(pid_cryptoded, SIGUSR1) < 0) {
		fprintf(stderr, "Couldn't to send SIGUSR1 signal to cryptoded process.(err:%d)\n", errno);
		return COD_RESP_SEND_SIG;
	} else
		fprintf(stderr, "Sending reload signal to cryptoded process '%d' has succeeded.\n", pid_cryptoded);

	return COD_RESP_OK;
}

/*
 * import VPN profiles
 */

int coc_import(int import_type, const char *import_path)
{
	char *conf_dir = NULL;
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* get configuration directory path */
	if (coc_get_confdir(&conf_dir) != 0) {
		fprintf(stderr, "Couldn't get the configuration directory of cryptoded\n");
		if (conf_dir)
			free(conf_dir);
		return COD_RESP_INVALID_CONF_DIR;
	}

	/* check import type */
	if (import_type != COC_VPN_PROFILE_OVPN && import_type != COC_VPN_PROFILE_TBLK) {
		fprintf(stderr, "Invalid VPN profile type\n");
		free(conf_dir);
		return COD_RESP_INVALID_PROFILE_TYPE;
	}

	/* checks whether import_path has valid extension */
	if (!is_valid_extension(import_path, import_type == COC_VPN_PROFILE_TBLK ? ".tblk" : ".ovpn")) {
		fprintf(stderr, "Invalid extension of file '%s'\n", import_path);
		free(conf_dir);
		return COD_RESP_INVALID_PROFILE_TYPE;
	}

	if (import_type == COC_VPN_PROFILE_TBLK) {
		ret = import_ovpn_from_tblk(conf_dir, import_path);
		if (ret <= 0) {
			fprintf(stderr, "Couldn't import OpenVPN profile from TunnelBlick profile '%s'", import_path);
			free(conf_dir);
			return COD_RESP_INVALID_PROFILE_TYPE;
		}
	} else {
		size_t fsize;

		/* checks whether size of imported profile */
		fsize = get_file_size(import_path);
		if (fsize <= 0 || fsize >= COC_MAX_IMPORT_SIZE) {
			fprintf(stderr, "Invalid size or too large file '%s'\n", import_path);
			free(conf_dir);
			return COD_RESP_IMPORT_TOO_LARGE;
		}

		/* checks whether same profile is exist */
		if (is_exist_file_in_dir(conf_dir, import_path)) {
			fprintf(stderr, "The same configuration is already exist in '%s'\n", conf_dir);
			free(conf_dir);
			return COD_RESP_IMPORT_EXIST_PROFILE;
		}

		/* copy files into cryptoded config directory */
		if (copy_file_into_dir(conf_dir, import_path, S_IRUSR | S_IWUSR) != 0) {
			fprintf(stderr, "Couldn't copy file '%s' into '%s'\n", import_path, conf_dir);
			free(conf_dir);
			return COD_RESP_UNKNOWN_ERR;
		}
	}

	fprintf(stderr, "Success to import VPN configuration from '%s'\n", import_path);

	free(conf_dir);

	return coc_reload();
}

/*
 * check if the connection is exist
 */

static int check_connection_exist(const char *conn_name, struct coc_vpnconn_status *vpnconn_status)
{
	int resp_code;
	char state_str[64];
	char auto_connect[64];

	char *resp_data = NULL;

	int i;

	cod_json_object_t status_jobjs[] = {
		{"code", COD_JTYPE_INT, &resp_code, 0, true, NULL},
		{"status", COD_JTYPE_STR, state_str, sizeof(state_str), true, "data"},
		{"profile", COD_JTYPE_STR, vpnconn_status->ovpn_profile_path, sizeof(vpnconn_status->ovpn_profile_path),
							true, "data"},
		{"auto-connect", COD_JTYPE_STR, auto_connect, sizeof(auto_connect), true, "data"},
		{"pre-exec-cmd", COD_JTYPE_STR, vpnconn_status->pre_exec_cmd, sizeof(vpnconn_status->pre_exec_cmd),
							true, "data"}
	};

	/* initiailize connection status */
	memset(vpnconn_status, 0, sizeof(struct coc_vpnconn_status));

	/* check connection status */
	if (coc_get_status(conn_name, 1, &resp_data) != 0) {
		fprintf(stderr, "Couldn't get status for VPN connection '%s'\n", conn_name);

		if (resp_data)
			free(resp_data);

		return COD_RESP_COD_NOT_RUNNING;
	}

	/* parse response */
	if (cod_json_parse(resp_data, status_jobjs, sizeof(status_jobjs) / sizeof(cod_json_object_t)) != 0) {
		fprintf(stderr, "Couldn't parse connection status response '%s'\n", resp_data);
		free(resp_data);

		return COD_RESP_JSON_INVALID;
	}

	/* free response data */
	free(resp_data);

	/* set connection status */
	vpnconn_status->conn_state = COD_CONN_STATE_UNKNOWN;
	for (i = 0; g_conn_state[i].state_str != NULL; i++) {
		if (strcmp(g_conn_state[i].state_str, state_str) == 0) {
			vpnconn_status->conn_state = g_conn_state[i].state;
			break;
		}
	}

	/* set auto connect flag */
	vpnconn_status->auto_connect = strcmp(auto_connect, "Enabled") == 0 ? true : false;

	/* check response code */
	if (resp_code != COD_RESP_OK) {
		fprintf(stderr, "Couldn't find VPN connection with name '%s'\n", conn_name);
		return COD_RESP_CONN_NOT_FOUND;
	}

	return COD_RESP_OK;
}

/*
 * edit VPN connection
 */

int coc_edit(const char *conn_name, enum COC_VPNCONN_OPTION opt_type, const char *opt_val)
{
	struct coc_vpn_config vpn_config;
	char *conf_dir = NULL;

	struct coc_vpnconn_status vpnconn_status;
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* check connection status */
	ret = check_connection_exist(conn_name, &vpnconn_status);
	if (ret != COD_RESP_OK)
		return ret;

	if (vpnconn_status.conn_state != COD_CONN_STATE_DISCONNECTED) {
		fprintf(stderr, "The connection '%s' is in connected or pending progress.\n", conn_name);
		return COD_RESP_CONN_IN_PROGRESS;
	}

	/* check option type is valid */
	if (opt_type == COC_VPNCONN_OPT_UNKNOWN) {
		fprintf(stderr, "Unknown VPN configuration option");
		return COD_RESP_ERR_VPNCONF_OPT_TYPE;
	}

	/* get configuration directory path */
	if (coc_get_confdir(&conf_dir) != 0) {
		fprintf(stderr, "Couldn't get the configuration directory of cryptoded\n");

		if (conf_dir)
			free(conf_dir);

		return COD_RESP_INVALID_CONF_DIR;
	}

	/* read old configuration */
	if (coc_read_vpn_config(conf_dir, conn_name, &vpn_config) != 0) {
		fprintf(stderr, "Couldn't get the VPN configuration with name '%s'", conn_name);
		free(conf_dir);
		return COD_RESP_ERR_NOT_FOUND_VPNCONF;
	}

	ret = COD_RESP_OK;

	switch (opt_type) {
	case COC_VPNCONN_OPT_AUTO_CONNECT:
		if (strcmp(opt_val, "enable") == 0)
			vpn_config.auto_connect = true;
		else if (strcmp(opt_val, "disable") == 0)
			vpn_config.auto_connect = false;
		else {
			fprintf(stderr, "Wrong option value. Please try to specify 'enable' or 'disable'\n");
			ret = COD_RESP_ERR_VPNCONF_OPT_VAL;
		}

		break;

	case COC_VPNCONN_OPT_PREEXEC_CMD:
		strlcpy(vpn_config.pre_exec_cmd, opt_val, sizeof(vpn_config.pre_exec_cmd));
		break;

	case COC_VPNCONN_OPT_PROFIEL:
		strlcpy(vpn_config.ovpn_profile_path, opt_val, sizeof(vpn_config.ovpn_profile_path));
		break;

	default:
		break;
	}

	/* write the configuration */
	if (ret == COD_RESP_OK) {
		ret = coc_write_vpn_config(conf_dir, conn_name, &vpn_config);
		if (ret != 0) {
			fprintf(stderr, "Couldn't edit VPN confiugration with name '%s'\n", conn_name);
		}
	}

	/* free configuration directory buffer */
	free(conf_dir);

	return COD_RESP_OK;
}

/*
 * remove VPN connection
 */

int coc_remove(const char *conn_name, int force)
{
	struct coc_vpnconn_status vpnconn_status;
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* check connection status */
	ret = check_connection_exist(conn_name, &vpnconn_status);
	if (ret != COD_RESP_OK)
		return ret;

	if (vpnconn_status.conn_state != COD_CONN_STATE_DISCONNECTED && !force) {
		fprintf(stderr, "The connection '%s' is in connected or pending progress.\n", conn_name);
		return COD_RESP_CONN_IN_PROGRESS;
	}

	/* remove profile connection */
	unlink(vpnconn_status.ovpn_profile_path);

	/* reload cryptoded */
	return coc_reload();
}

/*
 * check whether DNS utility has installed perperly
 */

static int check_dns_util_path()
{
	/* check whether dns utility is exist */
	if (!is_exist_path(COC_DNS_UTIL_PATH, 0)) {
		fprintf(stderr, "No exist cryptode DNS utility '%s'\n", COC_DNS_UTIL_PATH);
		return COD_RESP_NO_EXIST_DNS_UTIL;
	}

	/* check whether cryptode utility is exist and valid permission */
	if (!is_valid_permission(COC_DNS_UTIL_PATH, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) ||
		!is_owned_by_user(COC_DNS_UTIL_PATH, "root")) {
		fprintf(stderr, "cryptode DNS utility '%s' has wrong owner or permission.\n", COC_DNS_UTIL_PATH);
		return COD_RESP_WRONG_PERMISSION;
	}

	return COD_RESP_OK;
}

/*
 * Override DNS settings
 */

int coc_dns_override(int enabled, const char *dns_ip_list)
{
	char cmd[512];
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* check utility path */
	ret = check_dns_util_path();
	if (ret != COD_RESP_OK)
		return ret;

	/* build command string */
	if (enabled)
		snprintf(cmd, sizeof(cmd), "%s enable %s", COC_DNS_UTIL_PATH, dns_ip_list);
	else
		snprintf(cmd, sizeof(cmd), "%s disable", COC_DNS_UTIL_PATH);

	/* run command */
	ret = system(cmd);
	if (ret != 0)
		return COD_RESP_ERR_DNS_UTIL;

	return COD_RESP_OK;
}

/*
 * print DNS setting on the system
 */

int coc_dns_print(void)
{
	char cmd[COD_MAX_PATH];
	int ret;

	/* pre-checking for running environment of cryptode */
	ret = pre_check_running_env();
	if (ret != 0)
		return ret;

	/* check utility path */
	ret = check_dns_util_path();
	if (ret != COD_RESP_OK)
		return ret;

	/* build command */
	snprintf(cmd, sizeof(cmd), "%s status", COC_DNS_UTIL_PATH);

	/* run command */
	ret = system(cmd);
	if (ret != 0)
		return COD_RESP_ERR_DNS_UTIL;

	return COD_RESP_OK;
}
