#ifndef __RVCD_MAIN_H__
#define __RVCD_MAIN_H__

struct rvcd_ctx;

#include "common.h"
#include "log.h"
#include "util.h"

#include "cmd.h"

/* macro constants */
#define RVCD_PID_FPATH				"/var/run/rvcd.pid"

typedef struct rvcd_ctx {
	rvcd_cmd_proc_t cmd_proc;
} rvcd_ctx_t;

#endif /* __RVCD_MAIN_H__ */
