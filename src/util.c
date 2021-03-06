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
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "common.h"
#include "util.h"

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

/* get token by given character */
void get_token_by_char(char **pp, char sep, char *token, size_t size)
{
	char *p = *pp;
	int i = 0;

	/* set buffer until comma is exist */
	while (*p != sep && *p != '\0' && *p != '\n' && !isspace(*p)) {
		if (size > 0 && (i == (int) (size - 1)))
			break;

		if (token)
			token[i++] = *p;
		p++;
	}

	if (token)
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

	/* check whether last character has alphabetic or digit */
	if (i > 1 && !isalpha(conn_name[i - 1]) && !isdigit(conn_name[i - 1]))
		return 0;

	return 1;
}

/* check whether given file or directory is exist */
int is_exist_path(const char *path, int is_dir)
{
	struct stat st;
	int valid_mode;

	/* check the stat of path */
	if (stat(path, &st) != 0)
		return 0;

	valid_mode = is_dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);

	return valid_mode;
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
	bufsize = (int) sysconf(_SC_GETPW_R_SIZE_MAX);
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
	bufsize = (int) sysconf(_SC_GETPW_R_SIZE_MAX);
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

/*
 * check whether given file has valid extension
 */

int is_valid_extension(const char *file_path, const char *extension)
{
	const char *p;

	/* get extension */
	p = strrchr(file_path, '.');
	if (!p)
		return 0;

	/* compare extension */
	if (strcmp(p, extension) != 0)
		return 0;

	return 1;
}

/* get size of given file */
size_t get_file_size(const char *file_path)
{
	struct stat st;

	/* get stat of file */
	if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode))
		return 0;

	return st.st_size;
}

/* get file name from path */
int get_file_name_by_path(const char *file_path, char *file_name, size_t size)
{
	const char *p;

	/* check whether file path has '/' */
	p = strrchr(file_path, '/');
	if (!p)
		p = file_path;
	else
		p = p + 1;

	/* check length */
	if (strlen(p) == 0)
		return -1;

	strlcpy(file_name, p, size);

	return 0;
}

/* check whether the file is exist in the directory */
int is_exist_file_in_dir(const char *dir_path, const char *file_path)
{
	char file_name[COD_MAX_FILE_NAME];
	char dst_path[COD_MAX_PATH];

	struct stat st;

	/* get filename by path */
	if (get_file_name_by_path(file_path, file_name, sizeof(file_name)) != 0)
		return 0;

	/* get full path of file */
	get_full_path(dir_path, file_name, dst_path, sizeof(dst_path));

	/* get stat of file */
	if (stat(dst_path, &st) == 0)
		return 1;

	return 0;
}

/* copy file into directory */
int copy_file_into_dir(const char *dir_path, const char *file_path, mode_t mode)
{
	char file_name[COD_MAX_FILE_NAME];
	char dst_path[COD_MAX_PATH];

	int src_fd = -1, dst_fd = -1;
	int ret = 0;

	ssize_t read_bytes = 0;

	/* get file name */
	if (get_file_name_by_path(file_path, file_name, sizeof(file_name)) != 0)
		return -1;

	/* get full path of destination file */
	get_full_path(dir_path, file_name, dst_path, sizeof(dst_path));

	/* open source file */
	src_fd = open(file_path, O_RDONLY);
	if (src_fd < 0)
		return -1;

	/* create and open destination file */
	dst_fd = open(dst_path, O_CREAT | O_WRONLY, mode);
	if (dst_fd < 0) {
		close(src_fd);
		return -1;
	}

	/* copy file contents */
	do {
		char buf[1024];
		ssize_t write_bytes = 0;

		/* read buffer from file */
		read_bytes = read(src_fd, buf, sizeof(buf));
		if (read_bytes > 0)
			write_bytes = write(dst_fd, buf, read_bytes);

		if (read_bytes < 0 || write_bytes < 0) {
			ret = -1;
			break;
		}
	} while (read_bytes > 0);

	/* close files */
	close(dst_fd);
	close(src_fd);

	return ret;
}

/* get full path of file */
void get_full_path(const char *dir_path, const char *file_name, char *full_path, size_t size)
{
	size_t len;

	/* get length of dir path buffer */
	len = strlen(dir_path);
	if (len < 1)
		return;

	/* set full path */
	if (dir_path[len - 1] == '/')
		snprintf(full_path, size, "%s%s", dir_path, file_name);
	else
		snprintf(full_path, size, "%s/%s", dir_path, file_name);
}

/* create directory with given permission */
int create_dir(const char *dir_path, mode_t mode)
{
	struct stat st;

	/* check directory is exist */
	if (stat(dir_path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return chmod(dir_path, mode);
		unlink(dir_path);
	}

	return mkdir(dir_path, mode);
}

/* convert time_t to string */
void convert_tt_to_str(time_t tt, char *tm_str, size_t size)
{
	struct tm *tm;

	tm = localtime(&tt);
	strftime(tm_str, size, "%FT%T%Z", tm);
}

#ifndef HAVE_STRLCPY

/* size bounded string copy function */
size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t srclen;

	/* decrease size value */
	size--;

	/* get source len */
	srclen = strlen(src);
	if (srclen > size)
		srclen = size;

	memcpy(dst, src, srclen);
	dst[srclen] = '\0';

	return srclen;
}

#endif

#ifndef HAVE_STRLCAT

/* size bounded string copy function */
size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t srclen;
	size_t dstlen;

	/* set length of destination buffer */
	dstlen = strlen(dst);
	size -= dstlen + 1;
	if (!size)
		return dstlen;

	/* get the length of source buffer */
	srclen = strlen(src);
	if (srclen > size)
		srclen = size;

	memcpy(dst + dstlen, src, srclen);
	dst[dstlen + srclen] = '\0';

	return (dstlen + srclen);
}

#endif
