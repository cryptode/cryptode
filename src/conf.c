
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
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <json-c/json.h>

#include "rvd.h"

/*
 * initialize RVC VPN configuration
 */

static void init_rvc_vpn_config(struct rvc_vpn_config *vpn_config, const char *config_name,
	const char *ovpn_profile_path)
{
	/* initialize structure */
	memset(vpn_config, 0, sizeof(struct rvc_vpn_config));

	/* set default values */
	strlcpy(vpn_config->name, config_name, sizeof(vpn_config->name));
	strlcpy(vpn_config->ovpn_profile_path, ovpn_profile_path, sizeof(vpn_config->ovpn_profile_path));
}

/*
 * check whether VPN configuration is valid
 */

static int check_vpn_config(struct rvc_vpn_config *config)
{
	/* check whether connection name is valid */
	if (!is_valid_conn_name(config->name)) {
#ifdef _RVD_SOURCE
		RVD_DEBUG_ERR("CONF: Invalid VPN connection name '%s'", config->name);
#else
		fprintf(stderr, "Invalid VPN connection name '%s'\n", config->name);
#endif
		return -1;
	}

	/* check whether VPN profile has valid owner and permission */
	if (!is_owned_by_user(config->ovpn_profile_path, "root") ||
	    !is_valid_permission(config->ovpn_profile_path, S_IRUSR | S_IWUSR)) {
#ifdef _RVD_SOURCE
		RVD_DEBUG_ERR("CONF: Invalid owner or permission for VPN configuration file '%s'",
				config->ovpn_profile_path);
#else
		fprintf(stderr, "Invalid owner or permission for VPN configuration file '%s'\n",
				config->ovpn_profile_path);
#endif
		config->load_status |= OVPN_STATUS_INVALID_PERMISSION;
	} else
		config->load_status |= OVPN_STATUS_LOADED;

	/* check if interval is in valid range */
	if (config->pre_exec_interval != 0 &&
		(config->pre_exec_interval < MIN_PRE_EXEC_INTERVAL ||
		config->pre_exec_interval > MAX_PRE_EXEC_INTERVAL)) {
#ifdef _RVD_SOURCE
		RVD_DEBUG_WARN("CONF: Invalid interval of pre-exec-cmd '%d'", config->pre_exec_interval);
#else
		fprintf(stderr, "Invalid interval of pre-exec-cmd '%d'\n", config->pre_exec_interval);
#endif
		config->pre_exec_interval = 0;
	}

	return 0;
}

/*
 * parse RVC configuration file
 */

int rvc_read_vpn_config(const char *config_dir, const char *config_name, struct rvc_vpn_config *vpn_config)
{
	struct rvc_vpn_config config;

	char ovpn_profile_path[RVD_MAX_PATH];
	char json_config_path[RVD_MAX_PATH];

	bool json_config_exist = true;

	struct stat st;

#ifdef _RVD_SOURCE
	RVD_DEBUG_MSG("CONF: Parsing the configuration with name '%s'", config_name);
#else
	fprintf(stderr, "Parsing the configuration with name '%s'\n", config_name);
#endif

	/* get full paths */
	get_full_path(config_dir, config_name, ovpn_profile_path, sizeof(ovpn_profile_path));
	strlcat(ovpn_profile_path, OVPN_CONFIG_EXTENSION, sizeof(ovpn_profile_path));

	/* check whether openvpn profile is exist */
	if (stat(ovpn_profile_path, &st) != 0 || !S_ISREG(st.st_mode)
		|| st.st_size == 0) {
#ifdef _RVD_SOURCE
		RVD_DEBUG_ERR("CONF: Couldn't find OpenVPN configuration file '%s'", ovpn_profile_path);
#else
		fprintf(stderr, "Couldn't find OpenVPN configuration file '%s'\n", ovpn_profile_path);
#endif
		return -1;
	}

	/* set json configuration path */
	get_full_path(config_dir, config_name, json_config_path, sizeof(json_config_path));
	strlcat(json_config_path, RVC_CONFIG_EXTENSION, sizeof(json_config_path));

	/* check whether configuration file is exist */
	if (stat(json_config_path, &st) != 0 || !S_ISREG(st.st_mode) ||
		st.st_size == 0)
		json_config_exist = false;

	/* initializ VPN config */
	init_rvc_vpn_config(&config, config_name, ovpn_profile_path);

	/* parse config file */
	if (json_config_exist) {
		int fd;
		FILE *fp;

		struct stat st;

		char *config_buf;
		size_t read_len;

		rvd_json_object_t vpn_config[] = {
			{"auto-connect", RVD_JTYPE_BOOL, &config.auto_connect, 0, false, NULL},
			{"pre-connect-exec", RVD_JTYPE_STR, config.pre_exec_cmd, sizeof(config.pre_exec_cmd), false, NULL},
			{"pre-connect-exec-interval", RVD_JTYPE_INT, &config.pre_exec_interval, 0, false, NULL}
		};

#ifdef _RVD_SOURCE
		RVD_DEBUG_MSG("CONF: Parsing configuration file '%s'", json_config_path);
#else
		fprintf(stderr, "Parsing configuration file '%s'\n", json_config_path);
#endif

		/* get the size of json configuration file */
		if (stat(json_config_path, &st) != 0 || st.st_size <= 0) {
#ifdef _RVD_SOURCE
			RVD_DEBUG_MSG("CONF: Invalid JSON configuration file '%s'", json_config_path);
#else
			fprintf(stderr, "Invalid JSON configuration file '%s'\n", json_config_path);
#endif
		}

		/* open configuration file */
		fd = open(json_config_path, O_RDONLY);
		if (fd > 0)
			fp = fdopen(fd, "r");

		if (fd < 0 || !fp) {
#ifdef _RVD_SOURCE
			RVD_DEBUG_ERR("CONF: Couldn't open configuration file '%s' for reading(err:%d)",
					json_config_path, errno);
#else
			fprintf(stderr, "Couldn't open configuration file '%s' for reading(err:%d)\n",
					json_config_path, errno);
#endif
			if (fd > 0)
				close(fd);

			return -1;
		}

		/* read config buffer */
		config_buf = (char *) malloc(st.st_size + 1);
		if (!config_buf) {
			fclose(fp);
			return -1;
		}

		memset(config_buf, 0, st.st_size + 1);
		read_len = fread(config_buf, 1, st.st_size, fp);

		/* close file */
		fclose(fp);

		if (read_len <= 0 ||
			rvd_json_parse(config_buf, vpn_config, sizeof(vpn_config) / sizeof(rvd_json_object_t)) != 0) {
#ifdef _RVD_SOURCE
			RVD_DEBUG_ERR("CONF: Invalid configuration file '%s'", json_config_path);
#else
			fprintf(stderr, "Invalid configuration file '%s'\n", json_config_path);
#endif
			free(config_buf);

			return -1;
		}

		/* free configuration buffer */
		free(config_buf);

		/* set JSON configuration status */
		config.load_status |= OVPN_STATUS_HAVE_JSON;
	}

	/* check for the permissions of VPN config */
	if (check_vpn_config(&config) != 0)
		return -1;

	/* set VPN config result */
	memcpy(vpn_config, &config, sizeof(struct rvc_vpn_config));

	return 0;
}

/*
 * write RVD configuration file
 */

int rvc_write_vpn_config(const char *config_dir, const char *config_name, struct rvc_vpn_config *vpn_config)
{
	int fd;
	FILE *fp = NULL;

	char json_config_path[RVD_MAX_PATH];
	char *config_buffer;

	rvd_json_object_t vpn_config_jobjs[] = {
		{"name", RVD_JTYPE_STR, vpn_config->name, 0, false, NULL},
		{"auto-connect", RVD_JTYPE_BOOL, &vpn_config->auto_connect, 0, false, NULL},
		{"pre-connect-exec", RVD_JTYPE_STR, vpn_config->pre_exec_cmd, 0, false, NULL},
		{"pre-connect-exec-interval", RVD_JTYPE_INT, &vpn_config->pre_exec_interval, 0, false, NULL}
	};

#ifdef _RVD_SOURCE
	RVD_DEBUG_MSG("CONF: Writting the RVC configuration with name '%s'", config_name);
#else
	fprintf(stderr, "Writting the RVC configuration with name '%s'\n", config_name);
#endif

	/* set json configuration path */
	get_full_path(config_dir, config_name, json_config_path, sizeof(json_config_path));
	strlcat(json_config_path, RVC_CONFIG_EXTENSION, sizeof(json_config_path));

	/* write configuration buffer to config file */
	fd = open(json_config_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd > 0)
		fp = fdopen(fd, "w");

	if (fd < 0 || !fp) {
#ifdef _RVD_SOURCE
		RVD_DEBUG_ERR("CONF: Couldn't open RVC configuration file '%s' for writting(err:%d)",
				json_config_path, errno);
#else
		fprintf(stderr, "Couldn't open RVC configuration file '%s' for writting(err:%d)\n",
				json_config_path, errno);
#endif

		if (fd > 0)
			close(fd);

		return -1;
	}

	/* build json buffer */
	rvd_json_build(vpn_config_jobjs, sizeof(vpn_config_jobjs) / sizeof(rvd_json_object_t), &config_buffer);

	fwrite(config_buffer, 1, strlen(config_buffer), fp);
	fclose(fp);

	/* free config buffer */
	free(config_buffer);

	return 0;
}
