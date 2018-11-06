
/*
 * Copyright (c) 2017, [Ribose Inc](https://www.cryptode.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <json-c/json.h>

#include "json.h"

/* parse JSON string */
int cod_json_parse(const char *jbuf, cod_json_object_t *objs, int objs_count)
{
	json_object *j_obj;
	int i, ret = -1;

	/* parse json object */
	j_obj = json_tokener_parse(jbuf);
	if (!j_obj)
		return -1;

	for (i = 0; i < objs_count; i++) {
		json_object *j_sub_obj = NULL, *j_par_obj = NULL;
		cod_json_object_t *obj = &objs[i];

		int obj_not_found = 0;

		/* get parent object if parent key is exist */
		if (obj->parent_key) {
			if (!json_object_object_get_ex(j_obj, obj->parent_key, &j_par_obj) ||
				!json_object_object_get_ex(j_par_obj, obj->key, &j_sub_obj))
				obj_not_found = 1;
		} else if (!json_object_object_get_ex(j_obj, obj->key, &j_sub_obj)) {
			obj_not_found = 1;
		}

		if (obj_not_found) {
			if (!obj->mondatory)
				continue;

			break;
		}

		json_type j_type = json_object_get_type(j_sub_obj);

		switch (obj->type) {
		case COD_JTYPE_STR:
			if (j_type != json_type_string)
				break;

			snprintf((char *)obj->val, obj->size, "%s", json_object_get_string(j_sub_obj));
			ret = 0;

			break;

		case COD_JTYPE_BOOL:
			if (j_type != json_type_boolean)
				break;

			*((bool *)obj->val) = json_object_get_boolean(j_sub_obj) ? true : false;
			ret = 0;

			break;

		case COD_JTYPE_INT:
			if (j_type != json_type_int)
				break;

			*((int *)obj->val) = json_object_get_int(j_sub_obj);
			ret = 0;

			break;

		case COD_JTYPE_INT64:
			if (j_type != json_type_int)
				break;

			*((int64_t *)obj->val) = json_object_get_int64(j_sub_obj);
			ret = 0;

			break;

		case COD_JTYPE_STR_ARRAY:
			if (j_type == json_type_array) {
				struct cod_json_array *arr_val;
				int arr_idx, arr_len;

				/* allocate memory for array */
				arr_val = (struct cod_json_array *)malloc(sizeof(struct cod_json_array));
				if (!arr_val)
					break;

				memset(arr_val, 0, sizeof(struct cod_json_array));

				arr_len = json_object_array_length(j_sub_obj);
				if (arr_len <= 0) {
					free(arr_val);
					break;
				}

				arr_val->val = (char **) malloc(arr_len * sizeof(char **));
				if (!arr_val->val) {
					free(arr_val);
					break;
				}

				for (arr_idx = 0; arr_idx < arr_len; arr_idx++) {
					json_object *j_arr_obj;
					const char *str;

					/* get string item in array */
					j_arr_obj = json_object_array_get_idx(j_sub_obj, arr_idx);
					if (!j_arr_obj)
						continue;

					str = json_object_get_string(j_arr_obj);
					if (strlen(str) == 0)
						continue;

					/* set array value */
					arr_val->val[arr_idx] = strdup(str);

					/* increase array size */
					arr_val->arr_size++;
				}

				*((struct cod_json_array **)obj->val) = arr_val;
				ret = 0;
			}

			break;

		case COD_JTYPE_OBJ:
			if (j_type != json_type_object)
				break;

			snprintf((char *)obj->val, obj->size, "%s", json_object_get_string(j_sub_obj));
			ret = 0;

			break;

		default:
			break;
		}
	}

	/* free json object */
	json_object_put(j_obj);

	return ret;
}

/*
 * build JSON string
 */

int cod_json_build(cod_json_object_t *objs, int objs_count, char **jbuf)
{
	json_object *j_obj;
	int i;

	const char *p;

	int ret = -1;

	/* create new json object */
	j_obj = json_object_new_object();
	if (!j_obj)
		return -1;

	for (i = 0; i < objs_count; i++) {
		json_object *j_sub_obj = NULL, *j_par_obj = NULL;
		cod_json_object_t *obj = &objs[i];

		if (obj->parent_key && !json_object_object_get_ex(j_obj, obj->parent_key, &j_par_obj))
			continue;

		switch (obj->type) {
		case COD_JTYPE_STR:
			if (obj->val)
				j_sub_obj = json_object_new_string((char *)obj->val);
			else
				j_sub_obj = json_object_new_string("");

			break;

		case COD_JTYPE_BOOL:
			j_sub_obj = json_object_new_boolean(*((bool *)(obj->val)));
			break;

		case COD_JTYPE_INT:
			j_sub_obj = json_object_new_int(*(int *)(obj->val));
			break;

		case COD_JTYPE_INT64:
			j_sub_obj = json_object_new_int64(*(int64_t *)(obj->val));
			break;

		case COD_JTYPE_OBJ:
			if (obj->val)
				j_sub_obj = json_tokener_parse((char *)obj->val);
			else
				j_sub_obj = json_object_new_object();

			break;

		default:
			break;
		}

		if (j_sub_obj)
			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_sub_obj);
	}

	p = json_object_get_string(j_obj);
	if (p && strlen(p) > 0) {
		*jbuf = strdup(p);
		ret = 0;
	}

	/* free json object */
	json_object_put(j_obj);

	return ret;
}

/*
 * add json buffer
 */

int cod_json_add(const char *jbuf, cod_json_object_t *objs, int objs_count, char **ret_jbuf)
{
	json_object *j_obj;
	int i;

	const char *p;

	int ret = -1;

	/* create new json object */
	j_obj = json_tokener_parse(jbuf);
	if (!j_obj)
		return -1;

	for (i = 0; i < objs_count; i++) {
		cod_json_object_t *obj = &objs[i];
		json_object *j_sub_obj = NULL;

		json_object *j_par_obj = NULL;

		/* get parent object by key if object has parent */
		if (obj->parent_key && !json_object_object_get_ex(j_obj, obj->parent_key, &j_par_obj))
			continue;

		switch (obj->type) {
		case COD_JTYPE_STR:
			j_sub_obj = json_object_new_string((char *)obj->val);
			break;

		case COD_JTYPE_BOOL:
			j_sub_obj = json_object_new_boolean(*((bool *)(obj->val)));
			break;

		case COD_JTYPE_INT:
			j_sub_obj = json_object_new_int(*(int *)(obj->val));
			break;

		case COD_JTYPE_INT64:
			j_sub_obj = json_object_new_int64(*(int64_t *)(obj->val));
			break;

		case COD_JTYPE_OBJ:
			if (obj->val)
				j_sub_obj = json_tokener_parse((char *)obj->val);
			else
				j_sub_obj = json_object_new_object();

			break;

		default:
			break;
		}

		if (j_sub_obj)
			json_object_object_add(j_par_obj ? j_par_obj : j_obj, obj->key, j_sub_obj);
	}

	p = json_object_get_string(j_obj);
	if (p && strlen(p) > 0) {
		*ret_jbuf = strdup(p);
		ret = 0;
	}

	/* free json object */
	json_object_put(j_obj);

	return ret;
}
