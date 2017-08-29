
# Documentation for the interface between rvcd and UI

The interface between rvcd and UI is a socket that takes commands and provides responses.

`rvcd daemon` listens on unix domain socket `/tmp/.rvcd_cmd`

## Command Codes

```
RVCD_CMD_LIST = 0,
RVCD_CMD_CONNECT = 1,
RVCD_CMD_DISCONNECT = 2,
RVCD_CMD_STATUS = 3,
RVCD_CMD_SCRIPT_SECURITY = 4

```

## Response Codes

```
RVCD_RESP_OK = 0,
RVCD_RESP_INVALID_CMD  = 1,
RVCD_RESP_NO_MEMORY = 2,
RVCD_RESP_EMPTY_LIST = 3,
RVCD_RESP_CONN_NOT_FOUND = 4,
RVCD_RESP_CONN_ALREADY_CONNECTED = 5,
RVCD_RESP_CONN_ALREADY_DISCONNECTED = 6,
RVCD_RESP_CONN_IN_PROGRESS = 7,

```

## JSON commands and responses

### LIST command and response

- Command

```
{
    "cmd": RVCD_CMD_LIST(0),
    "json": true | false,
}

```

- Response

If json field is true,

```
{
    "code": RESPONSE_CODE,
    "data":
    [
        {
            "name": connection name,
            "profile": openvpn profile path,
            "auto-connect": true | false,
            "up-script": script when up openvpn connection,
            "down-script": script when down openvpn connection
        },

        ...
    ]
}

```

If json field is false, then print the response in general text format.

### CONNECT command and response

- Command

```
{
    "cmd": RVCD_CMD_CONNECT(1),
    "param": all | connection name
}

```

- Response

```
{
    "code": RESPONSE_CODE,
    "data": Refer status response
}

```

### DISCONNECT command and response

- Command

```
{
    "cmd": RVCD_CMD_DISCONNECT(2),
    "param": all | connection name
}

```

- Response

Same as RVCD_CMD_CONNECT

### STATUS command and response

- Command

```
{
    "cmd": RVCD_CMD_STATUS(3),
    "param": all | connection name
}

```

- Response

```
{
    "code": RESPONSE_CODE,
    "data": [
        {
            "name": connection name,
            "status": CONNECTED | CONNECTING | DISCONNECTED | DISCONNECTING | RECONNECTING,
            "ovpn-status": CONNECTED | DISCONNECTED | TCP_CONNECT | WAIT | AUTH | GET_CONFIG | ASSIGN_IP |
                            ADD_ROUTES | RECONNECTING | EXITING,
            "connected-time": connected timestamp,
            "timestamp": current timestamp,
            "network": {
                "in-current": IN bytes in current connection,
                "out-current": OUT bytes in current connection,
                "in-total": total IN bytes since rvcd started,
                "out-total": total OUT bytes since rvcd started
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
    "cmd": RVCD_CMD_SCRIPT_SECURITY(4),
    "param": enable | disable
}

```

- Response

```
{
    "code": RESPONSE_CODE
}

```
