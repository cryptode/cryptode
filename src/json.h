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

#ifndef __COD_JSON_H__
#define __COD_JSON_H__

#include <stdbool.h>

#define COD_JSON_STR_MAX_LEN			512

enum COD_JOBJ_TYPES {
	COD_JTYPE_STR = 0,
	COD_JTYPE_BOOL,
	COD_JTYPE_INT,
	COD_JTYPE_INT64,
	COD_JTYPE_STR_ARRAY,
	COD_JTYPE_OBJ
};

struct cod_json_array {
	char **val;
	int arr_size;
};

/* cod json object structure */
typedef struct cod_json_object {
	const char *key;
	enum COD_JOBJ_TYPES type;
	void *val;
	size_t size;
	bool mondatory;
	const char *parent_key;
} cod_json_object_t;

/* cryptoded json object API functions */
int cod_json_parse(const char *jbuf, cod_json_object_t *objs, int objs_count);
int cod_json_build(cod_json_object_t *objs, int objs_count, char **jbuf);
int cod_json_add(const char *jbuf, cod_json_object_t *objs, int objs_count, char **ret);

#endif /* __COD_JSON_H__ */
