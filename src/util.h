#ifndef __RVD_UTIL_H__
#define __RVD_UTIL_H__

#include <stdbool.h>

#define RVD_JSON_STR_MAX_LEN			512

enum RVD_JOBJ_TYPES {
	RVD_JTYPE_STR = 0,
	RVD_JTYPE_BOOL,
	RVD_JTYPE_UID,
	RVD_JTYPE_INT,
	RVD_JTYPE_STR_ARRAY,
	RVD_JTYPE_OBJ
};

struct rvd_json_array {
	char **val;
	int arr_size;
};

/* rvd json object structure */
typedef struct rvd_json_object {
	const char *key;
	enum RVD_JOBJ_TYPES type;
	void *val;
	size_t size;
	bool mondatory;
} rvd_json_object_t;

/* rvd json object API functions */
int rvd_json_parse(const char *jbuf, rvd_json_object_t *objs, int objs_count);
int rvd_json_build(rvd_json_object_t *objs, int objs_count, char **jbuf);

/* get maximum fd from fd_set */
int get_max_fd(int orig_max_fd, fd_set *fds);

/* get free listen port */
int get_free_listen_port(int start_port);

/* get token by comma */
void get_token_by_comma(char **pp, char *token, size_t size);

/* set socket as non-blocking mode */
int set_non_blocking(int sock);

/* check whether connection name is valid */
int is_valid_conn_name(const char *conn_name);

#endif /* __RVD_UTIL_H__ */
