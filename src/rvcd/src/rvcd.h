#ifndef __RVCD_MAIN_H__
#define __RVCD_MAIN_H__

struct rvcd_ctx;

#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "common.h"
#include "log.h"
#include "util.h"

#include "config.h"
#include "cmd.h"
#include "vpn.h"

/* macro constants */
#define RVCD_PID_FPATH				"/var/run/rvcd.pid"

typedef struct rvcd_ctx {
	const char *config_path;

	rvcd_config_t config;
	rvcd_cmd_proc_t cmd_proc;
	rvcd_vpnconn_mgr_t vpnconn_mgr;
} rvcd_ctx_t;

#endif /* __RVCD_MAIN_H__ */
