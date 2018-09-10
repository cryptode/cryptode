#ifndef __RVD_MAIN_H__
#define __RVD_MAIN_H__

struct rvd_ctx;

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

/* rvd context options */
typedef struct rvd_options {
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
} rvd_options_t;

/* rvd context structure */
typedef struct rvd_ctx {
	rvd_options_t opt;

	rvd_cmd_proc_t cmd_proc;
	rvd_vpnconn_mgr_t vpnconn_mgr;
} rvd_ctx_t;

#endif /* __RVD_MAIN_H__ */
