#ifndef __RVD_COMMON_H__
#define __RVD_COMMON_H__

/* macro constants */

#define RVD_MAX_PATH				256
#define RVD_MAX_LINE				512
#define RVD_MAX_LOGMSG_LEN			1024
#define RVD_MAX_CMD_LEN			2048
#define RVD_MAX_RESP_LEN			2048
#define RVD_MAX_CONN_NAME_LEN			128
#define RVD_MAX_CONN_INFO_LEN			2048

/* rvd command listen socket path */
#define RVD_CMD_LISTEN_SOCK			"/tmp/.rvd_cmd"

/* rvd default configuration path */
#define RVD_CONFIG_DEFAULT_PATH		"~/.setup/vpn/vpn.json"

/* rvd command codes */
enum RVD_CMD_CODE {
	RVD_CMD_LIST = 0,
	RVD_CMD_CONNECT,
	RVD_CMD_DISCONNECT,
	RVD_CMD_STATUS,
	RVD_CMD_SCRIPT_SECURITY,
	RVD_CMD_UNKNOWN
};

/* rvd command response codes */
enum RVD_RESP_CODE
{
	RVD_RESP_OK = 0,
	RVD_RESP_INVALID_CMD,
	RVD_RESP_NO_MEMORY,
	RVD_RESP_EMPTY_LIST,
	RVD_RESP_CONN_NOT_FOUND,
	RVD_RESP_CONN_ALREADY_CONNECTED,
	RVD_RESP_CONN_ALREADY_DISCONNECTED,
	RVD_RESP_CONN_IN_PROGRESS,
};

#endif /* __RVD_COMMON_H__ */
