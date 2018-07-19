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
#include <stdbool.h>

#include <nereon.h>
#include "rvc.nos.h"

#include "common.h"
#include "rvc_shared.h"

/*
 * RVC options structure
 */

struct rvc_options {
	char *conn_name, *disconn_name, *reconn_name, *status_name;

	bool connect, disconnect;
	bool reconnect, status;

	bool json;

	bool edit;
	bool edit_auto_connect, edit_pre_exec_cmd, edit_profile;
	char *edit_data;

	bool remove, remove_force;

	bool import, import_tblk, import_ovpn;
	char *import_path;

	bool reload;

	bool dns_override;
	bool dns_override_enable, dns_override_disable, dsn_override_status;
	char *dns_srvs;

	bool script_security;
	bool script_security_enable, script_security_disable;

	bool print_version;
};

/*
 * print version
 */

static void print_version(void)
{
	static const char build_time[] = { __DATE__ " " __TIME__ };

	printf("Relaxed VPN command line client - %s (built on %s)\n%s\n",
			PACKAGE_VERSION,
			build_time,
			RVC_COPYRIGHT_MSG);
}

/*
 * main function
 */

int main(int argc, char *argv[])
{
	nereon_ctx_t ctx;
	struct rvc_options opt;
	bool require_exit = false;

	int ret = -1;

	char *resp_data = NULL;

	struct nereon_config_option rvc_opts[] = {
		{"connect", NEREON_TYPE_STRING, false, &opt.connect, &opt.conn_name},
		{"disconnect", NEREON_TYPE_STRING, false, &opt.disconnect, &opt.disconn_name},
		{"reconnect", NEREON_TYPE_STRING, false, &opt.reconnect, &opt.reconn_name},
		{"status", NEREON_TYPE_STRING, false, &opt.status, &opt.status_name},

		{"json", NEREON_TYPE_BOOL, false, NULL, &opt.json},

		{"edit", NEREON_TYPE_STRING, false, &opt.edit, &opt.conn_name},
		{"edit.auto-connect", NEREON_TYPE_STRING, false, &opt.edit_auto_connect, &opt.edit_data},
		{"edit.pre-exec-cmd", NEREON_TYPE_STRING, false, &opt.edit_pre_exec_cmd, &opt.edit_data},
		{"edit.profile", NEREON_TYPE_STRING, false, &opt.edit_profile, &opt.edit_data},

		{"remove", NEREON_TYPE_STRING, false, &opt.remove, &opt.conn_name},
		{"remove.force", NEREON_TYPE_BOOL, false, NULL, &opt.remove_force},

		{"import", NEREON_TYPE_BOOL, false, NULL, &opt.import},
		{"import.new-from-tblk", NEREON_TYPE_STRING, false, &opt.import_tblk, &opt.import_path},
		{"import.new-from-ovpn", NEREON_TYPE_STRING, false, &opt.import_ovpn, &opt.import_path},

		{"reload", NEREON_TYPE_STRING, false, &opt.reload, &opt.reload},

		{"dns-override", NEREON_TYPE_BOOL, false, NULL, &opt.dns_override},
		{"dns-override.enable", NEREON_TYPE_STRING, false, &opt.dns_override_enable, &opt.dns_srvs},
		{"dns-override.disable", NEREON_TYPE_BOOL, false, NULL, &opt.dns_override_disable},
		{"dns-override.status", NEREON_TYPE_BOOL, false, NULL, &opt.dsn_override_status},

		{"script-security", NEREON_TYPE_BOOL, false, NULL, &opt.script_security},
		{"script-security.enable", NEREON_TYPE_BOOL, false, NULL, &opt.script_security_enable},
		{"script-security.disable", NEREON_TYPE_BOOL, false, NULL, &opt.script_security_disable},

		{"version", NEREON_TYPE_BOOL, false, NULL, &opt.print_version},
	};

	/* initialize nereon context */
	ret = nereon_ctx_init(&ctx, get_rvc_nos_cfg());
	if (ret != 0) {
		fprintf(stderr, "Could not initialize nereon context(err:%s)\n", nereon_get_errmsg());
		exit(-1);
	}

	/* print command line usage */
	ret = nereon_parse_cmdline(&ctx, argc, argv, &require_exit);
	if (ret != 0 || require_exit) {
		if (ret != 0)
			fprintf(stderr, "Failed to parse command line(err:%s)\n", nereon_get_errmsg());

		nereon_print_usage(&ctx);
		nereon_ctx_finalize(&ctx);

		exit(ret);
	}

	/* get configuration options */
	memset(&opt, 0, sizeof(struct rvc_options));
	if (nereon_get_config_options(&ctx, rvc_opts, sizeof(rvc_opts) / sizeof(struct nereon_config_option)) != 0) {
		fprintf(stderr, "Could not get confiugration options(err:%s)\n", nereon_get_errmsg());
		nereon_ctx_finalize(&ctx);

		exit(-1);
	}

	/* print version */
	if (opt.print_version) {
		print_version();
		exit(0);
	}

	if (opt.connect)
		ret = rvc_connect(opt.conn_name, opt.json, &resp_data);
	else if (opt.disconnect)
		ret = rvc_disconnect(opt.disconn_name, opt.json, &resp_data);
	else if (opt.reconnect)
		ret = rvc_reconnect(opt.reconn_name, opt.json, &resp_data);
	else if (opt.status)
		ret = rvc_get_status(opt.status_name, opt.json, &resp_data);
	else if (opt.reload) {
		ret = rvc_reload();
		goto end;
	} else if (opt.import) {
		int import_type = opt.import_tblk ? RVC_VPN_PROFILE_TBLK : RVC_VPN_PROFILE_OVPN;

		ret = rvc_import(import_type, opt.import_path);
		goto end;
	} else if (opt.edit) {
		int edit_type = RVC_VPNCONN_OPT_UNKNOWN;

		if (opt.edit_auto_connect)
			edit_type = RVC_VPNCONN_OPT_AUTO_CONNECT;
		else if (opt.edit_pre_exec_cmd)
			edit_type = RVC_VPNCONN_OPT_PREEXEC_CMD;
		else if (opt.edit_profile)
			edit_type = RVC_VPNCONN_OPT_PROFIEL;

		ret = rvc_edit(opt.conn_name, edit_type, opt.edit_data);
		goto end;
	} else if (opt.remove) {
		ret = rvc_remove(opt.conn_name, opt.remove_force ? 1 : 0);
		goto end;
	} else if (opt.dns_override) {
		if (opt.dsn_override_status)
			ret = rvc_dns_print();
		else
			ret = rvc_dns_override(opt.dns_override_enable ? 1 : 0, opt.dns_srvs);

		goto end;
	}

	if (resp_data) {
		printf("%s\n", resp_data);
		free(resp_data);
	}

end:
	nereon_ctx_finalize(&ctx);

	return ret;
}
