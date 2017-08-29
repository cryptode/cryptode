#ifndef __RVCD_UTIL_H__
#define __RVCD_UTIL_H__

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

#endif /* __RVCD_UTIL_H__ */
