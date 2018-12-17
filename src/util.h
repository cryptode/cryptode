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

#ifndef __CRYPTODED_UTIL_H__
#define __CRYPTODED_UTIL_H__

/* get maximum fd from fd_set */
int get_max_fd(int orig_max_fd, fd_set *fds);

/* get free listen port */
int get_free_listen_port(int start_port);

/* get token by given character */
void get_token_by_char(char **pp, char sep, char *token, size_t size);

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

/* check whether the file is exist in the directory */
int is_exist_file_in_dir(const char *dir_path, const char *file_path);

/* copy file into directory */
int copy_file_into_dir(const char *dir_path, const char *file_path, mode_t mode);

/* get full path of file */
void get_full_path(const char *dir_path, const char *file_name, char *full_path, size_t size);

/* create directory with given permission */
int create_dir(const char *dir_path, mode_t mode);

/* convert time_t to string */
void convert_tt_to_str(time_t tt, char *tm_str, size_t size);

#ifndef HAVE_STRLCPY
/* size bounded string copy function */
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
/* size bounded string copy function */
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#endif /* __CRYPTODED_UTIL_H__ */
