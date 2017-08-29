#ifndef __RVD_CMD_H__
#define __RVD_CMD_H__

/* rvd command processor */
typedef struct rvd_cmd_proc {
	bool init_flag;
	bool end_flag;

	int listen_sock;			/* unix domain socket listening for commands */

	pthread_mutex_t cmd_mt;			/* mutex */

	pthread_t pt_cmd_proc;			/* command processor main thread ID */

	struct rvd_ctx *c;
} rvd_cmd_proc_t;

/* rvd command processor functions */
int rvd_cmd_proc_init(struct rvd_ctx *c);
void rvd_cmd_proc_finalize(rvd_cmd_proc_t *cmd_proc);

#endif /* __RVD_CMD_H__ */
