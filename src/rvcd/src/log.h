#ifndef __RVCD_LOG_H__
#define __RVCD_LOG_H__

#define RVCD_LOG_FPATH					"/var/log/rvcd.log"
#define RVCD_LOG_BACKUP_FPATH				"/var/log/rvcd.log.0"

#define RVCD_MAX_LOG_FSIZE				30 * 1024 * 1024

/* macro definition of debug functions */
#define RVCD_DEBUG_MSG(...)				rvcd_debug_log(LOG_TYPE_MSG, __FILE__, __LINE__, __VA_ARGS__);
#define RVCD_DEBUG_ERR(...)				rvcd_debug_log(LOG_TYPE_ERR, __FILE__, __LINE__, __VA_ARGS__);
#define RVCD_DEBUG_WARN(...)				rvcd_debug_log(LOG_TYPE_WARN, __FILE__, __LINE__, __VA_ARGS__);

/* debug types */
enum LOG_TYPE {
	LOG_TYPE_MSG = 0,
	LOG_TYPE_ERR,
	LOG_TYPE_WARN
};

/* rvcd log functions */
int rvcd_log_init();
void rvcd_log_finalize();

void rvcd_debug_log(enum LOG_TYPE log_type, const char *file_name, int file_line, const char *format, ...);

#endif /* __RVCD_LOG_H__ */
