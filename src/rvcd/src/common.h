#ifndef __RVCD_COMMON_H__
#define __RVCD_COMMON_H__

/* macro constants */

#define RVCD_MAX_PATH				256
#define RVCD_MAX_LOGMSG_LEN			1024
#define RVCD_MAX_CMD_LEN			2048
#define RVCD_CONFIG_NAME_MAX_LEN		128

/* rvcd command listen socket path */
#define RVCD_CMD_LISTEN_SOCK			"/tmp/.rvcd_cmd"

/* rvcd default configuration path */
#define RVCD_CONFIG_DEFAULT_PATH		"~/.setup/vpn/vpn.json"

#endif /* __RVCD_COMMON_H__ */
