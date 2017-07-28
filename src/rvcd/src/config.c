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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <json-c/json.h>

#include "common.h"

#include "rvcd.h"

/*
 * add configuration item
 */

static void add_config_item(rvcd_config_t *config, struct rvcd_config_item *config_item)
{
	/* allocate memory */
	if (!config->config_items)
		config->config_items = (struct rvcd_config_item *) malloc(sizeof(struct rvcd_config_item));
	else
		config->config_items = (struct rvcd_config_item *) realloc(config->config_items,
			(config->config_items_count + 1) * sizeof(struct rvcd_config_item));

	if (!config->config_items) {
		/* init count */
		config->config_items_count = 0;

		return;
	}

	/* copy config item into list */
	memcpy(&config->config_items[config->config_items_count++], config_item, sizeof(struct rvcd_config_item));

	RVCD_DEBUG_MSG("CONFIG: Added configuration with name '%s', openvpn path '%s'", config_item->name, config_item->ovpn_profile_path);
}

/*
 * free configuration items
 */

static void free_config_items(rvcd_config_t *config)
{
	if (!config->config_items)
		return;

	/* free items */
	free(config->config_items);
}

/*
 * parse configuration
 */

static int parse_config(rvcd_config_t *config, const char *config_buffer)
{
	json_object *j_obj;

	int i;
	size_t count;

	/* parse json object */
	j_obj = json_tokener_parse(config_buffer);
	if (!j_obj) {
		RVCD_DEBUG_ERR("CONFIG: Invalid configuration JSON buffer");
		return -1;
	}

	/* check if the type of json object is array */
	if (json_object_get_type(j_obj) != json_type_array) {
		RVCD_DEBUG_ERR("CONFIG: Invalid configuration JSON array");
		return -1;
	}

	/* get configuration item count */
	count = json_object_array_length(j_obj);
	for (i = 0; i < count; i++) {
		json_object *j_item_obj, *j_sub_obj;

		struct rvcd_config_item config_item;

		/* get json object for item */
		j_item_obj = json_object_array_get_idx(j_obj, i);
		if (!j_item_obj)
			continue;

		/* init config item */
		memset(&config_item, 0, sizeof(config_item));

		/* get name object */
		if (!json_object_object_get_ex(j_item_obj, "name", &j_sub_obj)) {
			RVCD_DEBUG_WARN("CONFIG: Couldn't find object with key 'name' at index:%d", i);
			continue;
		}

		snprintf(config_item.name, sizeof(config_item.name), "%s", json_object_get_string(j_sub_obj));

		/* get ovpn object */
		if (!json_object_object_get_ex(j_item_obj, "ovpn", &j_sub_obj)) {
			RVCD_DEBUG_WARN("CONFIG: Couldn't find object with key 'ovpn' at index:%d", i);
			continue;
		}

		snprintf(config_item.ovpn_profile_path, sizeof(config_item.ovpn_profile_path), "%s", json_object_get_string(j_sub_obj));

		/* since connection status is disconnected at startup, so will leave connected flag as false */
		config_item.connected = false;

		/* add config item */
		add_config_item(config, &config_item);
	}

	return 0;
}

/*
 * read configuration
 */

static int read_config(rvcd_config_t *config, const char *config_path)
{
	struct stat st;
	char *config_buf = NULL;

	int fd;
	FILE *fp;
	size_t read_len;

	int ret = -1;

	RVCD_DEBUG_MSG("CONFIG: Reading configuration from '%s'", config_path);

	/* get size of configuration file */
	if (stat(config_path, &st) != 0)
		return -1;

	if (!S_ISREG(st.st_mode) || st.st_size == 0)
		return -1;

	/* open configuration file */
	fd = open(config_path, O_RDONLY);
	if (fd < 0) {
		RVCD_DEBUG_ERR("CONFIG: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
		return -1;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		RVCD_DEBUG_ERR("CONFIG: Couldn't open configuration file '%s' for reading(err:%d)", config_path, errno);
		close(fd);

		return -1;
	}

	/* read config buffer */
	config_buf = (char *) malloc(st.st_size + 1);
	if (!config_buf) {
		fclose(fp);
		return -1;
	}

	memset(config_buf, 0, st.st_size + 1);

	read_len = fread(config_buf, 1, st.st_size, fp);
	if (read_len > 0)
		ret = parse_config(config, config_buf);

	/* free buffer */
	free(config_buf);

	/* close file */
	fclose(fp);

	return ret;
}

/*
 * initialize rvcd configuration
 */

int rvcd_config_init(rvcd_ctx_t *c)
{
	rvcd_config_t *config = &c->config;
	const char *config_path;

	RVCD_DEBUG_MSG("CONFIG: Initializing configuration");

	/* set configuration path */
	config_path = c->config_path ? c->config_path : RVCD_CONFIG_DEFAULT_PATH;

	/* read configuration from file */
	if (read_config(config, config_path) != 0) {
		RVCD_DEBUG_ERR("CONFIG: Couldn't read configuration from file '%s'", config_path);
		return -1;
	}

	/* initialize mutex */
	pthread_mutex_init(&config->config_mt, NULL);

	/* set init flag */
	config->init_flag = true;

	return 0;
}

/*
 * finalize rvcd configuration
 */

void rvcd_config_finalize(rvcd_config_t *config)
{
	/* check init flag */
	if (!config->init_flag)
		return;

	RVCD_DEBUG_MSG("CONFIG: Finalizing configuration");

	/* free config */
	free_config_items(config);

	/* destroy mutex */
	pthread_mutex_destroy(&config->config_mt);
}

/*
 * convert config item into buffer
 */

#define CONFIG_ITEM_SEPARATOR_LINE			"###################################################\n"

static ssize_t write_config_item_to_file(int fd, bool json_format, struct rvcd_config_item *config_item)
{
	char buffer[RVCD_MAX_LINE];

	ssize_t total_bytes = 0, write_bytes;

	/* write separator */
	if (!json_format && (write_bytes = write(fd, CONFIG_ITEM_SEPARATOR_LINE, strlen(CONFIG_ITEM_SEPARATOR_LINE))) > 0)
		total_bytes += write_bytes;

	/* write name */
	if (!json_format) {
		snprintf(buffer, sizeof(buffer), "Name: %s\n", config_item->name);
		if ((write_bytes = write(fd, buffer, strlen(buffer))) > 0)
			total_bytes += write_bytes;

		/* write openvpn profile */
		snprintf(buffer, sizeof(buffer), "Profile: %s\n", config_item->ovpn_profile_path);
		if ((write_bytes = write(fd, buffer, strlen(buffer))) > 0)
			total_bytes += write_bytes;

		/* write connected status */
		snprintf(buffer, sizeof(buffer), "Connected: %s\n", config_item->connected ? "YES" : "NO");
		if ((write_bytes = write(fd, buffer, strlen(buffer))) > 0)
			total_bytes += write_bytes;
	} else {
		json_object *j_obj;
		const char *json_buffer;

		/* create json object */
		j_obj = json_object_new_object();
		if (!j_obj)
			return 0;

		/* add json object */
		json_object_object_add(j_obj, "name", json_object_new_string(config_item->name));
		json_object_object_add(j_obj, "profile", json_object_new_string(config_item->ovpn_profile_path));
		json_object_object_add(j_obj, "connected", json_object_new_string(config_item->connected ? "YES" : "NO"));

		json_buffer = json_object_get_string(j_obj);
		if (json_buffer)
			total_bytes = write(fd, json_buffer, strlen(json_buffer));

		/* free json object */
		json_object_put(j_obj);
	}

	return total_bytes;
}

/*
 * convert config list to buffer
 */

#define TEMP_FILE_FORMAT			"rvcd-list.XXXXXX"

void rvcd_config_to_buffer(rvcd_config_t *config, bool json_format, char **buffer)
{
	char *p = NULL;
	int i;

	char tmp_fpath[RVCD_MAX_PATH];
	const char *tmp_dpath = getenv("TMPDIR");
	int tmp_fd;

	ssize_t buffer_len = 0;

	RVCD_DEBUG_MSG("CONFIG: Writing config list into buffer");

	/* create temporary file */
	snprintf(tmp_fpath, sizeof(tmp_fpath), "%s%s", tmp_dpath ? tmp_dpath : "/tmp/", TEMP_FILE_FORMAT);
	if (!mktemp(tmp_fpath))
		return;

	/* open temporary file for writing mode */
	tmp_fd = open(tmp_fpath, O_CREAT | O_RDWR);
	if (tmp_fd < 0)
		return;

	/* lock mutex */
	pthread_mutex_lock(&config->config_mt);

	for (i = 0; i < config->config_items_count; i++)
		buffer_len += write_config_item_to_file(tmp_fd, json_format, &config->config_items[i]);

	/* unlock mutex */
	pthread_mutex_unlock(&config->config_mt);

	/* if buffer length is 0, then return */
	if (buffer_len > 0) {
		/* allocate buffer */
		p = (char *) malloc(buffer_len + 1);
		if (!p)
			return;

		memset(p, 0, buffer_len + 1);

		/* seek file position */
		lseek(tmp_fd, 0L, SEEK_SET);

		if (read(tmp_fd, p, buffer_len) > 0)
			*buffer = p;
	}

	/* close file */
	close(tmp_fd);

	/* remove file */
	remove(tmp_fpath);
}
