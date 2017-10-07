
# Documentation for the interface between rvd and UI

The interface between rvd and UI is a socket that takes commands and provides responses.

`rvd daemon` listens on unix domain socket `/var/run/rvd`

## Command Codes

```
RVD_CMD_CONNECT = 0,
RVD_CMD_DISCONNECT = 1,
RVD_CMD_STATUS = 2,
RVD_CMD_SCRIPT_SECURITY = 3,
RVD_CMD_RELOAD = 4,
RVD_CMD_IMPORT = 5,
RVD_CMD_REMOVE = 6,
RVD_CMD_DNS_OVERRIDE = 7,
RVD_CMD_GET_CONFDIR = 8,

```

## Response Codes

```
RVD_RESP_OK = 0,
RVD_RESP_INVALID_CMD = 1,
RVD_RESP_SOCK_CONN = 2,
RVD_RESP_JSON_INVALID = 3,
RVD_RESP_NO_MEMORY = 4,
RVD_RESP_SUDO_REQUIRED = 5,
RVD_RESP_RVD_NOT_RUNNING = 6,
RVD_RESP_SEND_SIG = 7,
RVD_RESP_INVALID_PROFILE_TYPE = 8,
RVD_RESP_INVALID_CONF_DIR = 9,
RVD_RESP_IMPORT_TOO_LARGE = 10,
RVD_RESP_IMPORT_EXIST_PROFILE = 11,
RVD_RESP_EMPTY_LIST = 12,
RVD_RESP_WRONG_PERMISSION = 13,
RVD_RESP_CONN_NOT_FOUND = 14,
RVD_RESP_CONN_ALREADY_CONNECTED = 15,
RVD_RESP_CONN_ALREADY_DISCONNECTED = 16,
RVD_RESP_CONN_IN_PROGRESS = 17,
RVD_RESP_NO_EXIST_DNS_UTIL = 18,
RVD_RESP_ERR_DNS_UTIL = 19,
RVD_RESP_UNKNOWN_ERR = 20,

```

## JSON commands and responses

### CONNECT command and response

- Command

```
{
    "cmd": RVD_CMD_CONNECT(0),
    "param": <all | connection name>
}

```

- Response

```
{
    "code": RESPONSE_CODE,
    "data": <connection status list | connection status>
}

```

### DISCONNECT command and response

- Command

```
{
    "cmd": RVD_CMD_DISCONNECT(2),
    "param": <all | connection name>
}

```

- Response

Same as RVD_CMD_CONNECT

### STATUS command and response

- Command

```
{
    "cmd": RVD_CMD_STATUS(3),
    "param": <all | connection name>
}

```

- Response

```
{
    "code": RESPONSE_CODE,
    "data": [
        {
            "name": <connection name>,
            "profile": <profile path>,
            "status": <CONNECTED | CONNECTING | DISCONNECTED | DISCONNECTING | RECONNECTING>,
            "ovpn-status": <CONNECTED | DISCONNECTED | TCP_CONNECT | WAIT | AUTH | GET_CONFIG | ASSIGN_IP |
                            ADD_ROUTES | RECONNECTING | EXITING>,
            "timestamp": <current timestamp>,
            "in-total": <total IN bytes after started rvd>,
            "out-total": <total OUT bytes after started rvd>,
            "auto-connect": <auto connect flag>,
            "pre-exec-cmd": <pre-execution command>,
            "pre-exec-status": <status of pre-execution command>,
            "network": {
                "in-current": <IN bytes in current connection>,
                "out-current": <OUT bytes in current connection>,
                "in-total": <total IN bytes since rvd started>,
                "out-total": <total OUT bytes since rvd started>
            }
        }

        ...
    ]
}

```

### SCRIPT_SECURITY command and response

- Command

```
{
    "cmd": RVD_CMD_SCRIPT_SECURITY(4),
    "param": <enable | disable>
}

```

- Response

```
{
    "code": RESPONSE_CODE
}

```
