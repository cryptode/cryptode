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

typedef struct rvd_ctx {
	const char *config_path;

	rvd_cmd_proc_t cmd_proc;
	rvd_vpnconn_mgr_t vpnconn_mgr;
} rvd_ctx_t;

#endif /* __RVD_MAIN_H__ */
