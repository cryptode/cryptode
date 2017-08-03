#ifndef __RVCD_COMMON_H__
#define __RVCD_COMMON_H__

/* macro constants */

#define RVCD_MAX_PATH				256
#define RVCD_MAX_LINE				512
#define RVCD_MAX_LOGMSG_LEN			1024
#define RVCD_MAX_CMD_LEN			2048
#define RVCD_MAX_RESP_LEN			2048
#define RVCD_MAX_CONN_NAME_LEN			128
#define RVCD_MAX_CONN_INFO_LEN			2048

/* rvcd command listen socket path */
#define RVCD_CMD_LISTEN_SOCK			"/tmp/.rvcd_cmd"

/* rvcd default configuration path */
#define RVCD_CONFIG_DEFAULT_PATH		"~/.setup/vpn/vpn.json"

/* rvcd command codes */
enum RVCD_CMD_CODE {
	RVCD_CMD_LIST = 0,
	RVCD_CMD_CONNECT,
	RVCD_CMD_DISCONNECT,
	RVCD_CMD_STATUS,
	RVCD_CMD_UNKNOWN
};

/* rvcd command response codes */
enum RVCD_RESP_CODE
{
	RVCD_RESP_OK = 0,
	RVCD_RESP_INVALID_CMD,
	RVCD_RESP_EMPTY_LIST,
	RVCD_RESP_CONN_NOT_FOUND,
	RVCD_RESP_CONN_ALREADY_CONNECTED,
	RVCD_RESP_CONN_ALREADY_DISCONNECTED,
	RVCD_RESP_CONN_IN_PROGRESS,
};

#endif /* __RVCD_COMMON_H__ */
