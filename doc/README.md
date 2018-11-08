# Documentation for the interface between `cryptoded` and `cryptode` or UI

The interface between `cryptoded` and `cryptode` or UI is a socket that takes commands and provides responses.

`cryptoded` listens on Unix domain socket `/var/run/cryptoded`

## Command Codes

```
COD_CMD_CONNECT = 0,
COD_CMD_DISCONNECT = 1,
COD_CMD_STATUS = 2,
COD_CMD_SCRIPT_SECURITY = 3,
COD_CMD_RELOAD = 4,
COD_CMD_IMPORT = 5,
COD_CMD_REMOVE = 6,
COD_CMD_DNS_OVERRIDE = 7,
COD_CMD_GET_CONFDIR = 8,
```

## Response Codes

```
COD_RESP_OK = 0,
COD_RESP_INVALID_CMD = 1,
COD_RESP_SOCK_CONN = 2,
COD_RESP_JSON_INVALID = 3,
COD_RESP_NO_MEMORY = 4,
COD_RESP_SUDO_REQUIRED = 5,
COD_RESP_COD_NOT_RUNNING = 6,
COD_RESP_SEND_SIG = 7,
COD_RESP_INVALID_PROFILE_TYPE = 8,
COD_RESP_INVALID_CONF_DIR = 9,
COD_RESP_IMPORT_TOO_LARGE = 10,
COD_RESP_IMPORT_EXIST_PROFILE = 11,
COD_RESP_EMPTY_LIST = 12,
COD_RESP_WRONG_PERMISSION = 13,
COD_RESP_CONN_NOT_FOUND = 14,
COD_RESP_CONN_ALREADY_CONNECTED = 15,
COD_RESP_CONN_ALREADY_DISCONNECTED = 16,
COD_RESP_CONN_IN_PROGRESS = 17,
COD_RESP_NO_EXIST_DNS_UTIL = 18,
COD_RESP_ERR_DNS_UTIL = 19,
COD_RESP_UNKNOWN_ERR = 20,
```

## JSON commands and responses

### CONNECT command and response

- Command

```json
{
    "cmd": COD_CMD_CONNECT(0),
    "param": <all | connection name>
}
```

- Response

```json
{
    "code": RESPONSE_CODE,
    "data": <connection status list | connection status>
}
```

### DISCONNECT command and response

- Command

```json
{
    "cmd": COD_CMD_DISCONNECT(2),
    "param": <all | connection name>
}
```

- Response

Same as COD_CMD_CONNECT

### STATUS command and response

- Command

```json
{
    "cmd": COD_CMD_STATUS(3),
    "param": <all | connection name>
}
```

- Response

```json
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
            "in-total": <total IN bytes after started cryptoded>,
            "out-total": <total OUT bytes after started cryptoded>,
            "auto-connect": <auto connect flag>,
            "pre-exec-cmd": <pre-execution command>,
            "pre-exec-status": <status of pre-execution command>,
            "network": {
                "in-current": <IN bytes in current connection>,
                "out-current": <OUT bytes in current connection>,
                "in-total": <total IN bytes since cryptoded started>,
                "out-total": <total OUT bytes since cryptoded started>
            }
        }

        ...
    ]
}
```

### SCRIPT_SECURITY command and response

- Command

```json
{
    "cmd": COD_CMD_SCRIPT_SECURITY(4),
    "param": <enable | disable>
}
```

- Response

```json
{
    "code": RESPONSE_CODE
}
```
