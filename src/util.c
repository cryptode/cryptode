/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <uuid/uuid.h>

#include <json-c/json.h>

#include "util.h"

/* parse JSON string */
int rvd_json_parse(const char *jbuf, rvd_json_object_t *objs, int objs_count)
{
	json_object *j_obj;
	int i, ret = -1;

	/* parse json object */
	j_obj = json_tokener_parse(jbuf);
	if (!j_obj)
		return -1;

	for (i = 0; i < objs_count; i++) {
		json_object *j_sub_obj;
		rvd_json_object_t *obj = &objs[i];

		/* check whether the object is exist */
		if (!json_object_object_get_ex(j_obj, obj->key, &j_sub_obj)) {
			if (!obj->mondatory)
				continue;

			break;
		}

		json_type j_type = json_object_get_type(j_sub_obj);

		switch (obj->type) {
		case RVD_JTYPE_STR:
			if (j_type != json_type_string)
				break;

			snprintf((char *)obj->val, obj->size, "%s", json_object_get_string(j_sub_obj));
			ret = 0;

			break;

		case RVD_JTYPE_BOOL:
			if (j_type != json_type_boolean)
				break;

			*((bool *)obj->val) = json_object_get_boolean(j_sub_obj) ? true : false;
			ret = 0;

			break;

		case RVD_JTYPE_UID:
			if (j_type != json_type_int)
				break;

			*((uid_t *)obj->val) = json_object_get_int(j_sub_obj);
			ret = 0;

			break;

		case RVD_JTYPE_INT:
			if (j_type != json_type_int)
				break;

			*((int *)obj->val) = json_object_get_int(j_sub_obj);
			ret = 0;

			break;

		case RVD_JTYPE_INT64:
			if (j_type != json_type_int)
				break;

			*((int64_t *)obj->val) = json_object_get_int64(j_sub_obj);
			ret = 0;

			break;

		case RVD_JTYPE_STR_ARRAY:
			if (j_type == json_type_array) {
				struct rvd_json_array *arr_val;
				int arr_idx, arr_len;

				/* allocate memory for array */
				arr_val = (struct rvd_json_array *)malloc(sizeof(struct rvd_json_array));
				if (!arr_val)
					break;

				memset(arr_val, 0, sizeof(struct rvd_json_array));

				arr_len = json_object_array_length(j_sub_obj);
				if (arr_len <= 0)
					break;

				arr_val->val = (char **) malloc(arr_len * sizeof(char **));
				if (!arr_val->val)
					break;

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

					arr_val->val[arr_idx] = (char *) malloc(strlen(str) + 1);
					if (!arr_val->val[arr_idx])
						continue;

					strcpy(arr_val->val[arr_idx], str);
					arr_val->val[arr_idx][strlen(str)] = '\0';

					/* increase array size */
					arr_val->arr_size++;
				}

				*((struct rvd_json_array **)obj->val) = arr_val;
				ret = 0;
			}

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

int rvd_json_build(rvd_json_object_t *objs, int objs_count, char **jbuf)
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
		rvd_json_object_t *obj = &objs[i];
		json_object *j_sub_obj = NULL;

		switch (obj->type) {
		case RVD_JTYPE_STR:
			j_sub_obj = json_object_new_string((char *)obj->val);
			break;

		case RVD_JTYPE_BOOL:
			j_sub_obj = json_object_new_boolean(*((bool *)(obj->val)));
			break;

		case RVD_JTYPE_UID:
		case RVD_JTYPE_INT:
			j_sub_obj = json_object_new_int(*(int *)(obj->val));
			break;

		case RVD_JTYPE_INT64:
			j_sub_obj = json_object_new_int64(*(int64_t *)(obj->val));
			break;

		case RVD_JTYPE_OBJ:
			if (obj->val)
				j_sub_obj = json_tokener_parse((char *)obj->val);
			else
				j_sub_obj = json_object_new_object();

			break;

		default:
			break;
		}

		if (j_sub_obj)
			json_object_object_add(j_obj, obj->key, j_sub_obj);
	}

	p = json_object_get_string(j_obj);
	if (p && strlen(p) > 0) {
		*jbuf = (char *) malloc(strlen(p) + 1);
		if (*jbuf) {
			strcpy(*jbuf, p);
			(*jbuf)[strlen(p)] = '\0';

			ret = 0;
		}
	}

	/* free json object */
	json_object_put(j_obj);

	return ret;
}

/*
 * add json buffer
 */

int rvd_json_add(const char *jbuf, rvd_json_object_t *objs, int objs_count, char **ret_jbuf)
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
		rvd_json_object_t *obj = &objs[i];
		json_object *j_sub_obj = NULL;

		json_object *j_par_obj = NULL;

		/* get parent object by key if object has parent */
		if (obj->parent_key && !json_object_object_get_ex(j_obj, obj->parent_key, &j_par_obj))
			continue;

		switch (obj->type) {
		case RVD_JTYPE_STR:
			j_sub_obj = json_object_new_string((char *)obj->val);
			break;

		case RVD_JTYPE_BOOL:
			j_sub_obj = json_object_new_boolean(*((bool *)(obj->val)));
			break;

		case RVD_JTYPE_UID:
		case RVD_JTYPE_INT:
			j_sub_obj = json_object_new_int(*(int *)(obj->val));
			break;

		case RVD_JTYPE_INT64:
			j_sub_obj = json_object_new_int64(*(int64_t *)(obj->val));
			break;

		case RVD_JTYPE_OBJ:
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
		*ret_jbuf = (char *) malloc(strlen(p) + 1);
		if (*ret_jbuf) {
			strcpy(*ret_jbuf, p);
			(*ret_jbuf)[strlen(p)] = '\0';

			ret = 0;
		}
	}

	/* free json object */
	json_object_put(j_obj);

	return ret;
}


/*
 * get maximum fd from fd_set
 */

int get_max_fd(int orig_max_fd, fd_set *fds)
{
	int i, max_fd = -1;

	for (i = 0; i <= orig_max_fd; i++) {
		if (!FD_ISSET(i, fds))
			continue;

		if (i > max_fd)
			max_fd = i;
	}

	return max_fd;
}

/*
 * get free listen port
 */

int get_free_listen_port(int start_port)
{
	int sock;
	int listen_port = start_port;

	int ret;

	/* create socket */
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return -1;

	while (1) {
		struct sockaddr_in listen_addr;

		/* set listen address */
		memset(&listen_addr, 0, sizeof(listen_addr));

		listen_addr.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &listen_addr.sin_addr);
		listen_addr.sin_port = htons(listen_port);

		/* try bind */
		ret = bind(sock, (struct sockaddr *) &listen_addr, sizeof(struct sockaddr_in));
		if (ret == 0)
			break;

		/* check errno has in-use value */
		if (errno != EADDRINUSE)
			continue;

		/* check maximum listening port number */
		if (listen_port == 65535)
			break;

		listen_port++;
	}

	/* close socket */
	close(sock);

	return (ret == 0) ? listen_port : -1;
}

/* get token by comma */
void get_token_by_comma(char **pp, char *token, size_t size)
{
	char *p = *pp;
	int i = 0;

	/* set buffer until comma is exist */
	while (*p != ',' && *p != '\0' && *p != '\n' && !isspace(*p)) {
		if (i == (int) (size - 1))
			break;

		token[i++] = *p;
		p++;
	}

	token[i] = '\0';

	if (*p != '\0')
		*pp = p + 1;
}

/*
 * set socket as non-blocking mode
 */

int set_non_blocking(int sock)
{
	int on = 1;

	/* set socket option as reusable */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
		return -1;

	/* set non-blocking mode */
	if (ioctl(sock, FIONBIO, (char *) &on) < 0)
		return -1;

	return 0;
}

/* check whether connection name is valid */
int is_valid_conn_name(const char *conn_name)
{
	int i = 0;

	while (conn_name[i] != '\0') {
		char p = conn_name[i++];

		/* check whether first character has alphabetic or digit */
		if (i == 0 && !isalpha(p) && !isdigit(p))
			return 0;

		if (!isalpha(p) && !isdigit(p) &&
			p != '-' && p != '_' && p != '.')
			return 0;
	}

	return 1;
}

/* check whether the file is owned by specified user */
int is_owned_by_user(const char *path, const char *uname)
{
	struct stat st;

	char *buf;
	int bufsize;

	struct passwd pwd, *res;

	uid_t uid;

	/* allocate buffer for getpwnam_r */
	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 0)
		return 0;

	buf = (char *) malloc(bufsize + 1);
	if (!buf)
		return 0;

	/* get user id */
	if (getpwnam_r(uname, &pwd, buf, bufsize, &res) != 0 || !res) {
		free(buf);
		return 0;
	}

	uid = pwd.pw_uid;

	/* free buffer */
	free(buf);

	/* get file stat */
	if (stat(path, &st) != 0)
		return 0;

	if (st.st_uid != uid)
		return 0;

	return 1;
}

/* check whether the file has valid permission */
int is_valid_permission(const char *path, mode_t mode)
{
	struct stat st;

	/* get file stat */
	if (stat(path, &st) != 0)
		return 0;

	st.st_mode &= 0777;
	if ((st.st_mode & mode) != st.st_mode)
		return 0;

	return 1;
}

/* get gid by user id */
int get_gid_by_uid(uid_t uid, gid_t *gid)
{
	int bufsize;
	char *buffer;

	struct passwd pwd, *result = NULL;

	int ret = 0;

	/* get buffer size */
	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize <= 0)
		return -1;

	buffer = (char *) malloc(bufsize + 1);
	if (!buffer)
		return -1;

	if (getpwuid_r(uid, &pwd, buffer, bufsize, &result) != 0 || !result)
		ret = -1;

	/* free buffer */
	free(buffer);

	if (ret == 0)
		*gid = pwd.pw_gid;

	return ret;
}
