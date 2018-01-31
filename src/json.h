
#ifndef __RVD_JSON_H__
#define __RVD_JSON_H__

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

#endif /* __RVD_JSON_H__ */
