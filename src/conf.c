
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <json-c/json.h>

#include "cryptoded.h"
#include "conf.nos.h"

/*
 * initialize cryptode VPN configuration
 */

static void init_coc_vpn_config(struct coc_vpn_config *vpn_config, const char *config_name,
	const char *ovpn_profile_path)
{
	/* initialize structure */
	memset(vpn_config, 0, sizeof(struct coc_vpn_config));

	/* set default values */
	strlcpy(vpn_config->name, config_name, sizeof(vpn_config->name));
	strlcpy(vpn_config->ovpn_profile_path, ovpn_profile_path, sizeof(vpn_config->ovpn_profile_path));
}

/*
 * check whether VPN configuration is valid
 */

static int check_vpn_config(struct coc_vpn_config *config)
{
	/* check whether connection name is valid */
	if (!is_valid_conn_name(config->name)) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Invalid VPN connection name '%s'", config->name);
#else
		fprintf(stderr, "Invalid VPN connection name '%s'\n", config->name);
#endif
		return -1;
	}

	/* check whether VPN profile has valid owner and permission */
	if (!is_owned_by_user(config->ovpn_profile_path, "root") ||
	    !is_valid_permission(config->ovpn_profile_path, S_IRUSR | S_IWUSR)) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Invalid owner or permission for VPN configuration file '%s'",
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
#ifdef _COD_SOURCE
		COD_DEBUG_WARN("CONF: Invalid interval of pre-exec-cmd '%d'", config->pre_exec_interval);
#else
		fprintf(stderr, "Invalid interval of pre-exec-cmd '%d'\n", config->pre_exec_interval);
#endif
		config->pre_exec_interval = 0;
	}

	return 0;
}

/*
 * parse cryptode configuration file
 */

int coc_read_vpn_config(const char *config_dir, const char *config_name, struct coc_vpn_config *vpn_config)
{
	struct coc_vpn_config config;

	char ovpn_profile_path[COD_MAX_PATH];
	char noc_config_path[COD_MAX_PATH];

	bool noc_config_exist = true;

	struct stat st;

#ifdef _COD_SOURCE
	COD_DEBUG_MSG("CONF: Parsing the configuration with name '%s'", config_name);
#else
	fprintf(stderr, "Parsing the configuration with name '%s'\n", config_name);
#endif

	/* get full paths */
	get_full_path(config_dir, config_name, ovpn_profile_path, sizeof(ovpn_profile_path));
	strlcat(ovpn_profile_path, OVPN_CONFIG_EXTENSION, sizeof(ovpn_profile_path));

	/* check whether openvpn profile is exist */
	if (stat(ovpn_profile_path, &st) != 0 || !S_ISREG(st.st_mode)
		|| st.st_size == 0) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Couldn't find OpenVPN configuration file '%s'", ovpn_profile_path);
#else
		fprintf(stderr, "Couldn't find OpenVPN configuration file '%s'\n", ovpn_profile_path);
#endif
		return -1;
	}

	/* set json configuration path */
	get_full_path(config_dir, config_name, noc_config_path, sizeof(noc_config_path));
	strlcat(noc_config_path, COC_CONFIG_EXTENSION, sizeof(noc_config_path));

	/* check whether configuration file is exist */
	if (stat(noc_config_path, &st) != 0 || !S_ISREG(st.st_mode) ||
		st.st_size == 0)
		noc_config_exist = false;

	/* initializ VPN config */
	init_coc_vpn_config(&config, config_name, ovpn_profile_path);

	/* parse config file */
	if (noc_config_exist) {
		nereon_ctx_t vpn_conf_ctx;
		char *pre_exec_cmd = NULL;

		nereon_config_option_t vpn_conf_opts[] = {
			{"auto-connect", NEREON_TYPE_BOOL, false, NULL, &config.auto_connect},
			{"pre-connect-exec", NEREON_TYPE_STRING, false, NULL, &pre_exec_cmd},
			{"pre-connect-exec-interval", NEREON_TYPE_INT, false, NULL, &config.pre_exec_interval}
		};

#ifdef _COD_SOURCE
		COD_DEBUG_MSG("CONF: Parsing configuration file '%s'", noc_config_path);
#else
		fprintf(stderr, "Parsing configuration file '%s'\n", noc_config_path);
#endif

		/* initialize VPN configuration parser */
		if (nereon_ctx_init(&vpn_conf_ctx, get_vpnconf_nos_cfg()) != 0) {
#ifdef _COD_SOURCE
			COD_DEBUG_ERR("CONF: Failed to parse VPN NOS configuration");
#else
			fprintf(stderr, "Could not parse VPN NOS configuration\n");
#endif
			return -1;
		}

		if (nereon_parse_config_file(&vpn_conf_ctx, noc_config_path) != 0) {
#ifdef _COD_SOURCE
			COD_DEBUG_ERR("CONF: Failed to parse VPN configruration '%s'", noc_config_path);
#else
			fprintf(stderr, "Failed to parse VPN configuration '%s'\n", noc_config_path);
#endif

			nereon_ctx_finalize(&vpn_conf_ctx);
			return -1;
		}

		if (nereon_get_config_options(&vpn_conf_ctx, vpn_conf_opts) != 0) {
#ifdef _COD_SOURCE
			COD_DEBUG_ERR("CONF: Failed to get configuration options(err:%s)", nereon_get_errmsg());
#else
			fprintf(stderr, "Failed to get configuration options(err:%s)\n", nereon_get_errmsg());
#endif

			nereon_ctx_finalize(&vpn_conf_ctx);
			return -1;
		}

		if (pre_exec_cmd)
			strlcpy(config.pre_exec_cmd, pre_exec_cmd, sizeof(config.pre_exec_cmd));

		nereon_ctx_finalize(&vpn_conf_ctx);

		/* set NOC configuration status */
		config.load_status |= OVPN_STATUS_HAVE_NOC;
	}

	/* check for the permissions of VPN config */
	if (check_vpn_config(&config) != 0)
		return -1;

	/* set VPN config result */
	memcpy(vpn_config, &config, sizeof(struct coc_vpn_config));

	return 0;
}

/*
 * write cryptode configuration file
 */

int coc_write_vpn_config(const char *config_dir, const char *config_name, struct coc_vpn_config *vpn_config)
{
	FILE *fp;
	int fd;

	char json_config_path[COD_MAX_PATH];
	char *config_buffer;

	cod_json_object_t vpn_config_jobjs[] = {
		{"name", COD_JTYPE_STR, vpn_config->name, 0, false, NULL},
		{"auto-connect", COD_JTYPE_BOOL, &vpn_config->auto_connect, 0, false, NULL},
		{"pre-connect-exec", COD_JTYPE_STR, vpn_config->pre_exec_cmd, 0, false, NULL},
		{"pre-connect-exec-interval", COD_JTYPE_INT, &vpn_config->pre_exec_interval, 0, false, NULL}
	};

#ifdef _COD_SOURCE
	COD_DEBUG_MSG("CONF: Writing the cryptode configuration with name '%s'", config_name);
#else
	fprintf(stderr, "Writing the cryptode configuration with name '%s'\n", config_name);
#endif

	/* set json configuration path */
	get_full_path(config_dir, config_name, json_config_path, sizeof(json_config_path));
	strlcat(json_config_path, COC_CONFIG_EXTENSION, sizeof(json_config_path));

	/* write configuration buffer to config file */
	fd = open(json_config_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Couldn't open cryptode configuration file '%s' for writing(err:%d)",
				json_config_path, errno);
#else
		fprintf(stderr, "Couldn't open cryptode configuration file '%s' for writing(err:%d)\n",
				json_config_path, errno);
#endif
		return -1;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Couldn't open cryptode configuration file '%s' for writing(err:%d)",
				json_config_path, errno);
#else
		fprintf(stderr, "Couldn't open cryptode configuration file '%s' for writing(err:%d)\n",
				json_config_path, errno);
#endif
		close(fd);
		return -1;
	}

	/* build json buffer */
	if (cod_json_build(vpn_config_jobjs, sizeof(vpn_config_jobjs) / sizeof(cod_json_object_t), &config_buffer) != 0) {
#ifdef _COD_SOURCE
		COD_DEBUG_ERR("CONF: Couldn't build NOC config. Out of memory!");
#else
		fprintf(stderr, "Couldn't build NOC config. Out of memory!\n");
#endif
		fclose(fp);
		return -1;
	}

	fwrite(config_buffer, 1, strlen(config_buffer), fp);
	fclose(fp);

	free(config_buffer);

	return 0;
}
