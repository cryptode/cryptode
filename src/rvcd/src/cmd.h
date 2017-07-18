#ifndef __RVCD_CMD_H__
#define __RVCD_CMD_H__

/* rvcd command codes */
enum RVCD_CMD_CODE {
	RVCD_CMD_LIST = 0,
	RVCD_CMD_UNKNOWN
};

/* rvcd command processor */
typedef struct rvcd_cmd_proc {
	bool init_flag;
	bool end_flag;

	int listen_sock;			/* unix domain socket listening for commands */

	pthread_mutex_t cmd_mt;			/* mutex */

	pthread_t pt_cmd_proc;			/* command processor main thread ID */

	struct rvcd_ctx *c;
} rvcd_cmd_proc_t;

/* rvcd command processor functions */
int rvcd_cmd_proc_init(struct rvcd_ctx *c);
void rvcd_cmd_proc_finalize(rvcd_cmd_proc_t *cmd_proc);

#endif /* __RVCD_CMD_H__ */
