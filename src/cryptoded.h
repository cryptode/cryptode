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

#ifndef __CRYPT_ODED_MAIN_H__
#define __CRYPT_ODED_MAIN_H__

struct cod_ctx;

#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include <nereon/nereon.h>

#include "common.h"
#include "log.h"
#include "util.h"

#include "json.h"
#include "cmd.h"
#include "conf.h"
#include "vpn.h"

/* cryptoded context options */
typedef struct cod_options {
	nereon_ctx_t nctx;

	char *config_fpath;
	bool go_daemon;

	bool check_config;
	bool print_version;
	bool print_help;

	char *ovpn_bin_path;
	bool ovpn_root_check;
	bool ovpn_use_scripts;

	int allowed_uid;
	bool restrict_cmd_sock;

	char *log_dir_path;
	char *vpn_config_dir;
} cod_options_t;

/* cryptoded context structure */
typedef struct cod_ctx {
	cod_options_t opt;

	cod_cmd_proc_t cmd_proc;
	cod_vpnconn_mgr_t vpnconn_mgr;
} cod_ctx_t;

#endif /* __CRYPT_ODED_MAIN_H__ */
