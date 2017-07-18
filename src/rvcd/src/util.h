#ifndef __RVCD_UTIL_H__
#define __RVCD_UTIL_H__

/* get maximum fd from fd_set */
int get_max_fd(int orig_max_fd, fd_set *fds);

#endif /* __RVCD_UTIL_H__ */
