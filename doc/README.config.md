
# Documentation for RVD(Ribose VPN Daemon)

The main configuration file for `rvd` is located in `/opt/rvc/etc/rvd.json`.

```
{
  "openvpn_bin": "/opt/openvpn/sbin/openvpn",
  "openvpn_root_check": true,
  "ovpn_up_down_scripts": false,
  "user_id": 501,
  "restrict_socket": true,
  "log_directory": "/var/log/rvd.log",
  "vpn_config_paths": [
    "/opt/rvc/etc/vpn.d",
    "/Users/test/.rvc"
  ]
}
```

`openvpn_bin`: the path of the OpenVPN executable.

`openvpn_root_check`: check whether the OpenVPN executable is owned by `root:wheel`.

`ovpn_up_down_scripts`: ignore the up and down scripts set in the `.ovpn` files.

`user_id`: the UID of the user to which the rvd socket is writable.

`restrict_socket`: make the socket writable to others or only the user_id.

`log`: the location of the log file.

`paths`: the directories in which the `.ovpn/.json` files are located.


`rvd` will scan the paths[] in `rvd.json` for OpenVPN files: `.ovpn` and rvc configuration `.json` files.
Example:

```
/Users/test/.rvc/ct.ovpn:
...
```

```
/Users/test/.rvc/ct.json:
{
  "name": "ct",
  "auto-connect": true,
  "pre-connect-exec": "/usr/bin/echo ct"
}
```
`pre-connect-exec`: is something that will be executed before a connection is made.

The executing user should be the UID that is defined in the main configuration `user_id`.

In case this is not defined then `pre-connect-exec` should be ignored and a message in the `console/log` should be shown.

And please implement a timeout of something like 60 seconds for the execution (`kill -9` after 60 seconds).

The `pre-connect-exec` is used to perform pre authentication actions such as launching a 2FA program.
