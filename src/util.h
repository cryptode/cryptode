#ifndef __RVD_UTIL_H__
#define __RVD_UTIL_H__

#include <stdbool.h>

#define RVD_JSON_STR_MAX_LEN			512

enum RVD_JOBJ_TYPES {
	RVD_JTYPE_STR = 0,
	RVD_JTYPE_BOOL,
	RVD_JTYPE_UID,
	RVD_JTYPE_INT,
	RVD_JTYPE_INT64,
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
	const char *parent_key;
} rvd_json_object_t;

/* rvd json object API functions */
int rvd_json_parse(const char *jbuf, rvd_json_object_t *objs, int objs_count);
int rvd_json_build(rvd_json_object_t *objs, int objs_count, char **jbuf);
int rvd_json_add(const char *jbuf, rvd_json_object_t *objs, int objs_count, char **ret);

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

/* check whether given file or directory is exist */
int is_exist_path(const char *path, int is_dir);

/* check whether the file is owned by specified user */
int is_owned_by_user(const char *path, const char *uname);

/* check whether the file has valid permission */
int is_valid_permission(const char *path, mode_t mode);

/* get group ID from user ID */
int get_gid_by_uid(uid_t uid, gid_t *gid);

/* check whether given file has valid extension */
int is_valid_extension(const char *file_path, const char *extension);

/* get size of given file */
size_t get_file_size(const char *file_path);

/* copy file into directory */
int copy_file_into_dir(const char *file_path, const char *dir_path, mode_t mode);

#endif /* __RVD_UTIL_H__ */
