
# Documentation for the interface between rvd and UI

The interface between rvd and UI is a socket that takes commands and provides responses.

`rvd daemon` listens on unix domain socket `/var/run/rvd`

## Command Codes

```
RVD_CMD_LIST = 0,
RVD_CMD_CONNECT = 1,
RVD_CMD_DISCONNECT = 2,
RVD_CMD_STATUS = 3,
RVD_CMD_SCRIPT_SECURITY = 4

```

## Response Codes

```
RVD_RESP_OK = 0,
RVD_RESP_INVALID_CMD  = 1,
RVD_RESP_NO_MEMORY = 2,
RVD_RESP_EMPTY_LIST = 3,
RVD_RESP_CONN_NOT_FOUND = 4,
RVD_RESP_CONN_ALREADY_CONNECTED = 5,
RVD_RESP_CONN_ALREADY_DISCONNECTED = 6,
RVD_RESP_CONN_IN_PROGRESS = 7,

```

## JSON commands and responses

### LIST command and response

- Command

```
{
    "cmd": RVD_CMD_LIST(0),
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
    "cmd": RVD_CMD_CONNECT(1),
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
    "cmd": RVD_CMD_DISCONNECT(2),
    "param": all | connection name
}

```

- Response

Same as RVD_CMD_CONNECT

### STATUS command and response

- Command

```
{
    "cmd": RVD_CMD_STATUS(3),
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
                "in-total": total IN bytes since rvd started,
                "out-total": total OUT bytes since rvd started
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
    "param": enable | disable
}

```

- Response

```
{
    "code": RESPONSE_CODE
}

```
