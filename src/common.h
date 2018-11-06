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

#ifndef __COD_COMMON_H__
#define __COD_COMMON_H__

#include <netinet/in.h>

/* macro constants */

#define COD_MAX_PATH               256
#define COD_MAX_FILE_NAME          256
#define COD_MAX_LINE               512
#define COD_MAX_LOGMSG_LEN         1024
#define COD_MAX_CMD_LEN            2048
#define COD_MAX_RESP_LEN           4096
#define COD_MAX_CONN_NAME_LEN      128
#define COD_MAX_CONN_INFO_LEN      2048
#define COD_MAX_CONN_STATUS_LEN    2048
#define COD_BUF_SIZE               512
#define COD_MAX_IPADDR_LEN         INET6_ADDRSTRLEN
#define COD_MAX_HNAME_LEN          128
#define COD_MAX_PORTSTR_LEN        16
#define COD_MAX_PROTOSTR_LEN       16
#define COD_MAX_DATETIME_LEN       128

#define COC_MAX_IMPORT_SIZE        10240

/* copyright message */
#define COC_COPYRIGHT_MSG          "Copyright 2017 Ribose Inc <https://www.ribose.com>"

/* cryptoded default command listen socket path */
#define COD_LISTEN_SOCK_PATH       "/var/run/cod.sock"

/* cryptoded default log file path */
#define COD_DEFAULT_LOGDIR_PATH    "/var/log/cod"

/* cryptoded default UID for writing to cryptoded socket */
#define COD_DEFAULT_UID            501

/* cryptoded pid file path */
#define COD_PID_DPATH              "/var/run/cod"
#define COD_PID_FPATH              "/var/run/cod/cod.pid"

/* cryptoded command codes */
enum COD_CMD_CODE {
	COD_CMD_CONNECT,
	COD_CMD_DISCONNECT,
	COD_CMD_RECONNECT,
	COD_CMD_STATUS,
	COD_CMD_SCRIPT_SECURITY,
	COD_CMD_RELOAD,
	COD_CMD_IMPORT,
	COD_CMD_EDIT,
	COD_CMD_REMOVE,
	COD_CMD_DNS_OVERRIDE,
	COD_CMD_GET_CONFDIR,
	COD_CMD_UNKNOWN
};

/* cryptoded command response codes */
enum COD_RESP_CODE
{
	COD_RESP_OK = 0,
	COD_RESP_INVALID_CMD,
	COD_RESP_SOCK_CONN,
	COD_RESP_JSON_INVALID,
	COD_RESP_NO_MEMORY,
	COD_RESP_SUDO_REQUIRED,
	COD_RESP_COD_NOT_RUNNING,
	COD_RESP_SEND_SIG,
	COD_RESP_INVALID_PROFILE_TYPE,
	COD_RESP_INVALID_CONF_DIR,
	COD_RESP_IMPORT_TOO_LARGE,
	COD_RESP_IMPORT_EXIST_PROFILE,
	COD_RESP_EMPTY_LIST,
	COD_RESP_WRONG_PERMISSION,
	COD_RESP_CONN_NOT_FOUND,
	COD_RESP_CONN_ALREADY_CONNECTED,
	COD_RESP_CONN_ALREADY_DISCONNECTED,
	COD_RESP_CONN_IN_PROGRESS,
	COD_RESP_NO_EXIST_DNS_UTIL,
	COD_RESP_ERR_DNS_UTIL,
	COD_RESP_ERR_WRONG_COC_PATH,
	COD_RESP_ERR_NOT_FOUND_VPNCONF,
	COD_RESP_ERR_VPNCONF_OPT_TYPE,
	COD_RESP_ERR_VPNCONF_OPT_VAL,
	COD_RESP_ERR_INVALID_OVPN_BIN,
	COD_RESP_UNKNOWN_ERR,
};

/* VPN connection state */
enum COD_VPNCONN_STATE {
	COD_CONN_STATE_DISCONNECTED = 0,
	COD_CONN_STATE_CONNECTED,
	COD_CONN_STATE_CONNECTING,
	COD_CONN_STATE_DISCONNECTING,
	COD_CONN_STATE_RECONNECTING,
	COD_CONN_STATE_UNKNOWN
};

#endif /* __COD_COMMON_H__ */
