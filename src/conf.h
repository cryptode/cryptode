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

#ifndef __COD_CONF_H__
#define __COD_CONF_H__

#define OVPN_CONFIG_EXTENSION           ".ovpn"
#define COC_CONFIG_EXTENSION            ".noc"

#define OVPN_STATUS_NOT_LOADED          0x0000
#define OVPN_STATUS_INVALID_PERMISSION  0x0001
#define OVPN_STATUS_LOADED              0x0002
#define OVPN_STATUS_HAVE_NOC            0x0004

#define MIN_PRE_EXEC_INTERVAL           1
#define MAX_PRE_EXEC_INTERVAL           60

/*
 * RVC configuration structure
 */

struct coc_vpn_config {
	char name[COD_MAX_CONN_NAME_LEN + 1];
	char ovpn_profile_path[COD_MAX_PATH];
	char ovpn_log_path[COD_MAX_PATH];

	int load_status;
	bool auto_connect;

	uid_t pre_exec_uid;
	char pre_exec_cmd[512];

	int pre_exec_interval;            /* pre exec command interval in seconds */
	time_t pre_exec_ts;               /* timestamp of pre-exec-cmd */

	int pre_exec_status;
};

/*
 * parse cryptode configuration file
 */

int coc_read_vpn_config(const char *conf_dir, const char *config_name, struct coc_vpn_config *vpn_config);

/*
 * write cryptode configuration file
 */

int coc_write_vpn_config(const char *config_dir, const char *config_name, struct coc_vpn_config *vpn_config);

#endif /* __COD_CONF_H__ */
