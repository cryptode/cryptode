#ifndef __RVD_LOG_H__
#define __RVD_LOG_H__

#define RVD_LOG_FPATH					"/var/log/rvd.log"
#define RVD_LOG_BACKUP_FPATH				"/var/log/rvd.log.0"

#define RVD_MAX_LOG_FSIZE				30 * 1024 * 1024

/* macro definition of debug functions */
#define RVD_DEBUG_MSG(...)				rvd_debug_log(LOG_TYPE_MSG, __FILE__, __LINE__, __VA_ARGS__);
#define RVD_DEBUG_ERR(...)				rvd_debug_log(LOG_TYPE_ERR, __FILE__, __LINE__, __VA_ARGS__);
#define RVD_DEBUG_WARN(...)				rvd_debug_log(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);

/* debug types */
enum LOG_TYPE {
	LOG_TYPE_MSG = 0,
	LOG_TYPE_ERR,
	LOG_TYPE_WARN
};

/* rvd log functions */
int rvd_log_init(const char *log_path);
void rvd_log_finalize();

void rvd_debug_log(enum LOG_TYPE log_type, const char *file_name, int file_line, const char *format, ...);

#endif /* __RVD_LOG_H__ */
