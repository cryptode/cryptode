# RVC

The {R}elaxed {V}PN {C}lient.

`rvc` is a command line driven OpenVPN client for macOS with two focus areas:
* CLI usage for automation
* Security for protection of your OpenVPN private keys + certificates and ensuring that only approved routes are added


## Structure

`rvc` has the following structure:

* `/opt/rvc/bin/rvd`: the daemon that is responsible for starting and stopping OpenVPN connections
* `/opt/rvc/bin/rvc`: the client that is used to make `rvd` connect/disconnect to VPNs
* `/opt/rvc/etc/rvd.conf`: the main configuration file for `rvd`
* `/opt/rvc/etc/vpn.d`: the directory in which `.ovpn` files are stored
* `/Library/LaunchDaemons/com.ribose.rvd.plist`: the `rvd` plist for `launchd`
* `/var/run/rvd`: the socket to which `rvc` can communicate with `rvd`

VPN files (example):
* `/opt/rvc/etc/vpn.d/vpn1.ovpn`: the OpenVPN that contains the configuration of the VPN, private key, client certificate and CA certificate
* `/opt/rvc/etc/vpn.d/vpn1.json`: the `rvd` configuration of this particular VPN

Dependencies:
* `/opt/openvpn/bin/openvpn`: a root owned copy of OpenVPN


## Security architecture

* `rvd` is owned `root:wheel` and has the following permissions: `-r-x------`. `rvd` is meant to be only executed by `launchd`.
Upon starting `rvd` will create a socket which will be writable only by a predefined userid that is set in `/opt/rvc/etc/rvd.conf`.

* `rvc` is owned `root:wheel` and has the following permissions: `-r-xr-xr-x`. `rvc` can be executed by any user but the socket `rvc`
connects to can only be written to a predefined userid. This restricts the connecting/disconnecting of VPNs to a single userid.

* OpenVPN files are stored in `/opt/rvc/etc/vpn.d` and this directory is owned by `root:wheel` and has `drwxr-xr-x` permissions.
The OpenVPN files are stored as `/opt/rvc/etc/vpn.d/vpn1.ovpn`, owned by `root:wheel` and have `-rw-------` permissions.
The `rvd` VPN configuration are stored as `/opt/rvc/etc/vpn.d/vpn1.json`, owned by `root:wheel` and have `-rw-------` permissions.
This strict permission and owner scheme is to prevent your keys being read and/or your VPN configurations modified by a local attacker.
If `rvd` were to be allowed to use any OpenVPN file then a local attacker could change the routes to the system's DNS server and/or
execute some malicous pre/post connect script. We only accept `root` owned OpenVPN files.

* `brew` installs OpenVPN in `/usr/local/bin` any local attacker can replace the `openvpn` executable with something malicious. Therefor
during installation of `rvc` a `root` owned copy of `openvpn` needs to be made to `/opt/openvpn/bin`. Upon start `rvd` will perform the
`root` check on the `openvpn` executable before it starts it.

* Besides the installation target of `/opt/rvc/bin`, `brew` will also install `rvc` to `/usr/local/bin` which you most likely have in your
`PATH`. It is of upmost importance that you put `/opt/rvc/bin` in the beginning of your `PATH`.
Example: `PATH=/opt/rvc/bin:/usr/local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`. This is to prevent you from running sudo on a
modified `rvc` that's living in `/usr/local/bin`.


## Configuration file

The `rvd` configuration file looks like this:
```json
{
  "openvpn_bin": "/opt/openvpn/sbin/openvpn",
  "openvpn_root_check": true,
  "ovpn_up_down_scripts": false,
  "user_id": 501,
  "restrict_socket": true,
  "log": "/var/log/rvd.log",
  "vpn_config_paths": [
    "/opt/rvc/etc/vpn.d"
  ]
}
```

### Configuration details

`openvpn_bin`: the location of the OpenVPN executable. Since this executable will be ran with `uid 0` it is important
to place this in a directory not writable by unprivileged users. OpenVPN will be most likely installed by `brew` and
must therefor be copied to `/opt`. If you wish to have `rvd` use the OpenVPN executable in `/usr/local/bin` then you can, but
this is not advised.

`openvpn_root_check`: `rvd` can perform a check whether the OpenVPN executable is owned by root. By default `rvd` will
expect OpenVPN to live in `/opt/openvpn/bin` which should be owned by root. In case you want to use the OpenVPN executable
in `/usr/local/bin` then you can disable this check, which is not advised.

`ovpn_up_down_scripts`: OpenVPN allows to run up and down scripts to set routes and perform MFA actions. By default this
behaviour is disabled and up scripts are handled by `rvd` on a per VPN basis in the `pre-connect-exec` in the VPN JSON file.
It is not advised to enable the `ovpn_up_down_scripts` globally unless you really need this and know what you are doing.

`user_id`: this is the default UID of the regular desktop user on your macOS system. `pre-connect-exec` scripts will use
this UID to be run as, also the socket of `rvd` will only be writable to from this UID. By default it is set to `501` which
is the first UID used by macOS when creating a desktop user.

`restrict_socket`: `rvd` by default only accepts `rvc` socket connections from a UID set in `user_id`. This is to prevent
access to your VPN connects on multi-user systems. Disabling this is not advised.

`log`: this is the log file `rvd` will write to.

`vpn_config_paths`: `rvd` by default uses `/opt/rvc/etc/vpn.d` to store OpenVPN files. You can extend this by adding other
directories such as home directories or file shares. This however is not advised as keys will most likely be stored unprotected
and visible to other users. In addition, allowing `rvd` (which runs as root) to read OpenVPN files from insecure locations
might introduce security vulnerabilities.


## CLI usage of rvc

```console
usage: rvc <options>
  options:
    list [--json]                               show list of VPN connections
    connect <all|connection name> [--json]      connect to a VPN with given name
    disconnect <all|connection name> [--json]   disconnect from VPN with given name
    status [all|connection name] [--json]       get status of VPN connection with given name
    script-security <enable|disable>            enable/disable script security
    help                                        show help message
    reload                                      reload configuration (sudo required)
    import <new-from-tblk|new-from-ovpn> <path> import VPN connection (sudo required)
```

### VPN setup

Example `rvd` configuration for a VPN:
`/opt/rvc/etc/vpn.d/vpn1.json`
```json
{
  "name": "vpn1",
  "auto-connect": false,
  "pre-connect-exec": ""
}
```

Example OpenVPN file with empty `<cert>`, `<ca>` and `<key>`:
`/opt/rvc/etc/vpn.d/vpn1.ovpn`
```console
client
dev tun
proto tcp
remote 10.1.1.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
auth SHA512
cipher AES-256-CBC
tls-version-min 1.2

<ca>
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
</key>
```

### Connecting and disconnecting to VPNs

```sh
$ sudo /opt/rvc/bin/rvc reload
Sending reload signal to rvd process '3667' has succeeded.
```

```sh
$ /opt/rvc/bin/rvc status
name: vpn1
        status: DISCONNECTED
        openvpn-status: DISCONNECTED
        in-total: 0
        out-total: 0
        timestamp: 1505802943

```

To connect:
```sh
$ /opt/rvc/bin/rvc connect vpn1
name: vpn1
        status: CONNECTING
        openvpn-status: DISCONNECTED
        in-total: 0
        out-total: 0
        timestamp: 1505802970

```

To see the status:
```sh
$ /opt/rvc/bin/rvc status vpn1
name: vpn1
        status: CONNECTED
        openvpn-status: CONNECTED
        in-total: 0
        out-total: 3018
        connected-time: 1505802975
        in-current: 3005
        out-current: 3018
        timestamp: 1505803003

```

To disconnect:
```sh
$ /opt/rvc/bin/rvc disconnect vpn1
name: vpn1
        status: DISCONNECTING
        openvpn-status: CONNECTED
        in-total: 0
        out-total: 3276
        timestamp: 1505803046

```

```sh
$ /opt/rvc/bin/rvc status vpn1
name: vpn1
        status: DISCONNECTED
        openvpn-status: DISCONNECTED
        in-total: 3195
        out-total: 3276
        timestamp: 1505803072

```
