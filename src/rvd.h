#ifndef __RVD_MAIN_H__
#define __RVD_MAIN_H__

struct rvd_ctx;

#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "common.h"
#include "log.h"
#include "util.h"

#include "cmd.h"
#include "vpn.h"

/* macro constants */
#define RVD_PID_FPATH				"/var/run/rvd.pid"

/* rvd context options */
typedef struct rvd_ctx_option {
	char ovpn_bin_path[RVD_MAX_PATH];
	bool ovpn_root_check;
	bool ovpn_use_scripts;

	uid_t allowed_uid;
	bool restrict_cmd_sock;

	char log_path[RVD_MAX_PATH];

	struct rvd_json_array *vpn_config_dirs;
} rvd_ctx_opt_t;

/* rvd context structure */
typedef struct rvd_ctx {
	const char *config_path;

	rvd_ctx_opt_t ops;

	rvd_cmd_proc_t cmd_proc;
	rvd_vpnconn_mgr_t vpnconn_mgr;
} rvd_ctx_t;

#endif /* __RVD_MAIN_H__ */
