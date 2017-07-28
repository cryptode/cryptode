#ifndef __RVCD_UTIL_H__
#define __RVCD_UTIL_H__

/* get maximum fd from fd_set */
int get_max_fd(int orig_max_fd, fd_set *fds);

/* get free listen port */
int get_free_listen_port(int start_port);

/* get token by comma */
void get_token_by_comma(char **pp, char *token, size_t size);

#endif /* __RVCD_UTIL_H__ */
