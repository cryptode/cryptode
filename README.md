# RVC

The **R**elaxed **V**PN **C**lient

RVC is a command line driven OpenVPN client for macOS (Sierra and High Sierra) and RHEL/CentOS (7) with two focus areas:
* CLI usage for automation
* Security for protection of your OpenVPN private keys + certificates and ensuring that only approved routes are added to your route table

Don't get fooled by the word *Relaxed*. It is meant that you can relax when using RVC and not having to stress about your VPN private keys and certificates will get leaked.

**Let us know if you have any comments, suggestions for improvement, found a bug or identified a security vulnerability. We are open to pull requests!**


## Structure

Operating system specific target directories:
* macOS RVC path: `/opt/rvc`
* RHEL/CentOS 7+ RVC path: `/usr/local`

RVC has the following structure:
* `<RVC path>/bin/rvd`: the daemon that is responsible for starting and stopping OpenVPN connections
* `<RVC path>/bin/rvc`: the client that is used to make `rvd` connect/disconnect to VPNs
* `<RVC path>/etc/rvd.conf`: the main configuration file for `rvd`
* `<RVC path>/etc/vpn.d`: the directory in which `.ovpn` files are stored
* `/var/run/rvd`: the socket that `rvc` uses to communicate with `rvd`
* `/var/log/rvd/rvd.log`: the log file from `rvd`, use this for troubleshooting

macOS:
* `/Library/LaunchDaemons/com.ribose.rvd.plist`: the `rvd` plist for use by `launchd`

RHEL/CentOS:
* `/lib/systemd/system/rvd.service`: the `systemd` unit file

VPN configuration files (example):
* `<RVC path>/etc/vpn.d/<vpn>.ovpn`: the OpenVPN file that contains the configuration of the VPN, private key, client certificate and CA certificate
* `<RVC path>/etc/vpn.d/<vpn>.json`: the `rvd` configuration of this particular VPN

VPN log files (example):
* `/var/log/rvd/<vpn>.ovpn.log`: VPN log file

macOS dependencies:
* `/opt/openvpn/sbin/openvpn`: a copy of the OpenVPN executable that is owned by `root`

RHEL/CentOS dependencies:
* `/usr/sbin/openvpn`: the location of the OpenVPN executable as installed via `yum`


## Overview:

```
+-----------------+
| launchd/systemd |
+-+---------------+
  |
  v
+--------------------+    +-main configuration------+
| <RVC path>/bin/rvd +--->| <RVC path>/etc/rvd.json |
+-+----+-------------+    +-------------------------+
  |
  |        +-rvd VPN configuration file------+
  |     +->| <RVC path>/etc/vpn.d/<vpn>.json |
  |     |  +---------------------------------+
  +-----+
  |     |  +-OpenVPN configuration file------+
  |     +->| <RVC path>/etc/vpn.d/<vpn>.ovpn |<-+
  |        +---------------------------------+  |
  |                                             |
  |      +-rvd log--------------+          +----+
  +----->| /var/log/rvd/rvd.log |          |
  |      +----------------------+          |
  |                                        |
  |      +-OpenVPN started by rvd----------+-------------------------------+
  +----->| <OpenVPN path>/openvpn --config <RVC path>/etc/vpn.d/<vpn>.ovpn |
  |      +                        --log-append /var/log/rvd/<vpn>.ovpn.log |
  |      +-------------------------------------+---------------------------+
  |                                            |
  |                        +-------------------+
  |                        |
  |      +-socket-------+  |  +-VPN log file----------------+
  +----->| /var/run/rvd |  +->| /var/log/rvd/<vpn>.ovpn.log |
         +--------------+     +-----------------------------+
           ^
           |
+----------+---------+
| <RVC path>/bin/rvc +
+--------------------+
```


## <RVC path>/etc/rvd.json configuration file

The `<RVC path>/etc/rvd.json` configuration file looks like this on macOS:
```json
{
  "openvpn_bin": "/opt/openvpn/sbin/openvpn",
  "openvpn_root_check": true,
  "ovpn_up_down_scripts": false,
  "user_id": 501,
  "restrict_socket": true,
  "log_directory": "/var/log/rvd.log",
  "vpn_config_paths": "/opt/rvc/etc/vpn.d"
}
```


### rvd.json configuration file details

`openvpn_bin`: the location of the OpenVPN executable. Since this executable will run as `uid 0` it is important
to place this executable in a directory not writable by unprivileged users.
Note: On macOS OpenVPN will be most likely installed by `brew` in `/usr/local/sbin` and for security purposes therefore must be copied to `/opt/openvpn/sbin`. If you wish to have `rvd` use the OpenVPN executable in `/usr/local/sbin` then you can, **but this is not advised as a local attacker could replace anything in `/usr/local/`.

`openvpn_root_check`: `rvd` can perform a check whether the OpenVPN executable is owned by root. On macOS `rvd` will
expect OpenVPN to live in `/opt/openvpn/sbin` which must be owned by root. In case you want to use the OpenVPN executable
in another directory such as `/usr/local/bin` then you can disable this check, **but this is not advised**.

`ovpn_up_down_scripts`: OpenVPN allows to run up and down scripts to set routes and perform MFA actions. By default this
behaviour is disabled and up scripts are handled by `rvd` on a per VPN basis with the `pre-connect-exec` statement in the VPN .json file. **It is not advised to enable the `ovpn_up_down_scripts` globally unless you really need this and know what you are doing.**

`user_id`: this is the UID of the unprivileged user `rvd` will execute `pre-connect-exec` scripts as. Also the socket of
`rvd` will only be writable to by this UID. By default it is set to `501` which is the UID used by macOS when creating the first desktop user.

`restrict_socket`: `rvd` by default only accepts `rvc` socket connections from the UID set in `user_id`. This is to prevent
access to your VPN connections on multi-user systems. **Disabling this restriction is not advised.**

`log`: this is the log file `rvd` will write to.

`vpn_config_paths`: `rvd` stores OpenVPN files on macOS in `/opt/rvc/etc/vpn.d` and on RHEL/CentOS in `/usr/local/etc/vpn.d/`.

This file is mandatory.


### VPN configuration file

Example `rvd` configuration for a VPN:
`<RVC path>/etc/vpn.d/vpn1.json`
```json
{
  "name": "vpn1",
  "auto-connect": false,
  "pre-connect-exec": ""
}
```

This file is optional.


### VPN configuration file details

`name`: The VPN name as it will appear in `rvc list`.
`auto-connect`: Set this to `true` when you want to automatically connect to a VPN when `rvd` starts. This is useful when you have Jenkins slaves auto connecting to VPNs upon boot.
`pre-connect-exec`: Run a script or executable before connecting to the VPN. This can be used to execute a script for MFA purposes.

As a .json file for a VPN is optional you should only create one if you need `auto-connect` and/or a `pre-connect-exec` script to run.

## Security architecture and considerations

Typically macOS clients are GUI based and require you to enter a password every time you want to change something. This approach
makes it impossible to automate VPN management and operation. RVC can only be managed via the command line. You need `sudo` for operations
that require access to root owned directories and files.

* `rvd` is owned by `root:wheel` and has the following permissions: `-r-x------`. `rvd` is meant to be only executed by `launchd`. So don't
start it manually. Upon starting `rvd` will create a socket in `/var/run/rvd` which will be writable only by a predefined userid that is
set in `<RVC path>/etc/rvd.conf`. It looks like this:
```console
$ ls -la /var/run/rvd
srw-------  1 test  wheel  0 Sep 19 15:52 /var/run/rvd
$ id test
uid=501(test) gid=20(staff) groups=20(staff),401(com.apple.sharepoint.group.1),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),501(access_bpf),701(com.apple.sharepoint.group.3),33(_appstore),100(_lpoperator),204(_developer),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),402(com.apple.sharepoint.group.2)
```

* `rvc` is owned by `root:wheel` and has the following permissions: `-r-xr-xr-x`. `rvc` can be executed by any user but the socket `rvc`
connects to can only be written to a predefined userid. This restricts the connecting/disconnecting of VPNs to a single userid. Sending a `reload` signal to `rvd` using `rvc` requires `sudo`.

* OpenVPN files are stored in `<RVC path>/etc/vpn.d` which is owned by `root:wheel` and has `drwxr-xr-x` permissions.
The OpenVPN files are stored as `<RVC path>/etc/vpn.d/<vpn>.ovpn`, owned by `root:wheel` and have `-rw-------` permissions.
The `rvd` VPN configuration are stored as `<RVC path>/etc/vpn.d/<vpn>.json`, owned by `root:wheel` and have `-rw-------` permissions.
This strict permission and owner scheme is to prevent your private keys being leaked and/or your VPN configurations modified by a local attacker.
If `rvd` were to be allowed to use *any* OpenVPN file then a local attacker could potentially change the routes to the system's DNS servers to an attacker controlled IP.
`rvd` only accepts OpenVPN files that are owned by `root` and are not readable by `others`:
```console
$ ls -la /opt/rvc/etc/vpn.d
total 144
drwxr-xr-x  14 root  wheel   476 Sep 15 13:28 .
drwxr-xr-x   4 root  wheel   136 Sep 15 16:48 ..
-rw-------   1 root  wheel   146 Sep 11 13:50 vpn1.json
-rw-------   1 root  wheel  7240 Sep 11 13:50 vpn1.ovpn
```

* VPNs do not not require a .json `rvd` configuration file. By default VPN connections will not `auto-connect` and no `pre-connect-exec` will be executed.

* VPNs can be configured that a script is executed before OpenVPN will connect. This is defined in `pre-connect-exec`
in `<RVC path>/etc/vpn.d/<vpn>.json`. As `rvd` runs as `root` it will drop its root privileges to the UID defined with `user_id` in
`<RVC path>/etc/rvd.json`. The following code in `src/vpn.c` is responsible for this:
```C
/* set UID */
setuid(vpn_conn->config.pre_exec_uid);

/* set gid */
if (get_gid_by_uid(vpn_conn->config.pre_exec_uid, &gid) == 0)
	setgid(gid);

/* run command */
ret = system(vpn_conn->config.pre_exec_cmd);
```

* OpenVPN will be executed as root but log files will be owned by `user_id`. This is to ensure that your desktop user can access and
delete the log files of his/her VPNs. The following code in `src/vpn.c` is responsible for this:
```C
/* set owner of openvpn log file */
uid = vpn_conn->vpnconn_mgr->c->opt.allowed_uid;
if (uid > 0) {
	gid_t gid;

	if (get_gid_by_uid(uid, &gid) == 0)
		chown(ovpn_log_fpath, uid, gid);
}
```

* On macOS Brew installs OpenVPN in `/usr/local/sbin`. This allows a local attacker to replace the `openvpn` executable with something malicious. Therefore during installation of RVC a root owned copy of `openvpn` needs to be placed in `/opt/openvpn/sbin`. Upon start `rvd` will perform the `root` check on the `openvpn` executable before it actually runs it. The following code in `src/vpn.c` is responsible for this:
```C
static int check_ovpn_binary(const char *ovpn_bin_path, bool root_check)
{
	struct stat st;

	/* get stat of openvpn binary file */
	if (stat(ovpn_bin_path, &st) != 0 || !S_ISREG(st.st_mode)) {
		RVD_DEBUG_ERR("VPN: Wrong path of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	/* check executable status */
	if (!is_valid_permission(ovpn_bin_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
		RVD_DEBUG_ERR("VPN: Wrong permission of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	/* check root status */
	if (root_check && !is_owned_by_user(ovpn_bin_path, "root")) {
		RVD_DEBUG_ERR("VPN: Wrong owner of OpenVPN binary '%s'", ovpn_bin_path);
		return -1;
	}

	return 0;
}
```

* On macOS Brew and/or a manual `make install` installs `rvc` to `/usr/local/bin`, follow the instructions to also install the executables in `/opt/rvc/bin`.
Your `PATH` will most likely have `/usr/local/bin` in it. **It is of upmost importance that you put `/opt/rvc/bin` in the beginning of your `PATH`.**
Example: `PATH=/opt/rvc/bin:/usr/local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`. This is to prevent you from running `sudo` on a
backdoored `rvc` that is put in `/usr/local/bin` by a local attacker.


## CLI usage of rvc

```console
usage: rvc <options>
  options:
    connect <all|connection name> [--json]	connect to a VPN with given name
    disconnect <all|connection name> [--json]	disconnect from VPN with given name
    status [all|connection name] [--json]	get status of VPN connection with given name
    script-security <enable|disable>		enable/disable script security
    help					show help message
    reload					reload configuration (sudo required)
    import <new-from-tblk|new-from-ovpn> <path>	import VPN connection (sudo required)
    remove <connection name> [--force]		remove VPN connection (sudo required)
```

## RVC RHEL/CentOS Installation instructions

```sh
sudo yum install https://github.com/<TODO>
```


## RVC macOS Installation instructions

### Installation via homebrew

```sh
brew install openvpn
brew tap riboseinc/rvc
brew install --HEAD rvc
```

**Be sure to follow the instructions in the caveats section during the brew installation**

And take a look at the homebrew formula: [homebrew-rvc](https://github.com/riboseinc/homebrew-rvc)


### Installation via source

Install dependencies:
```sh
brew install openvpn
```

Compilation:
```sh
git clone https://github.com/riboseinc/rvc
cd rvc
sh autogen.sh
./configure
make
make install
```

Extra installation steps on macOS:
```sh
sudo mkdir -m 755 -p /opt/rvc/bin /opt/openvpn/sbin
sudo mkdir -m 755 -p /opt/rvc/etc/vpn.d
sudo chown -R root:wheel /opt/rvc /opt/openvpn
sudo install -m 500 -g wheel -o root /usr/local/bin/rvd /opt/rvc/bin
sudo install -m 555 -g wheel -o root /usr/local/bin/rvc /opt/rvc/bin
sudo install -m 600 -g wheel -o root /usr/local/etc/rvd/rvd.json"} /opt/rvc/etc
sudo install -m 500 -g wheel -o root /usr/local/sbin/openvpn /opt/openvpn/sbin
sudo install -m 600 -g wheel -o root /usr/local/bin/com.ribose.rvd.plist /Library/LaunchDaemons
sudo launchctl load -w /Library/LaunchDaemons/com.ribose.rvd.plist
```

## Pro tip for macOS

After installation do the following:
```sh
rm -f /usr/local/bin/rvc /usr/local/bin/rvd 
```

This is to ensure you will always use the correct `rvc` that is living in `/opt/rvc/bin`.


## Commands to add, connect and disconnect a VPN

Follow these steps to setup a new VPN connection called `vpn1`:


### Add VPN configuration .json

```sh
sudo vi /opt/rvc/etc/vpn.d/vpn1.json
```

`<RVC path>/etc/vpn.d/vpn1.json`
```json
{
  "name": "vpn1",
  "auto-connect": false,
  "pre-connect-exec": ""
}
```


### Add VPN configuration .ovpn

```sh
sudo vi /opt/rvc/etc/vpn.d/vpn1.ovpn
```

Example OpenVPN file (with empty `<cert>`, `<ca>` and `<key>`, these obviously needs to be in there when actually adding the VPN):
`etc/vpn.d/vpn1.ovpn`
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


### Set correct permissions

```sh
sudo chmod 500 /opt/rvc/etc/vpn.d/vpn1.ovpn
sudo chmod 500 /opt/rvc/etc/vpn.d/vpn1.json
```


### Reload rvd

After adding a new VPN called `vpn1` by adding the .ovpn + .json files to `<RVC path>/etc/vpn.d` you need to reload `rvd`:
```console
$ sudo rvc reload
Sending reload signal to rvd process '3667' has succeeded.
```

```console
$ rvc list
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
	auto-connect: Disabled
	pre-exec-cmd:
```

```console
$ rvc status
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
        status: DISCONNECTED
        openvpn-status: DISCONNECTED
        in-total: 0
        out-total: 0
        timestamp: 1505802943

```


### To connect to the VPN
```console
$ rvc connect vpn1
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
        status: CONNECTING
        openvpn-status: DISCONNECTED
        in-total: 0
        out-total: 0
        timestamp: 1505802970

```


### Check the status of the VPN
```console
$ rvc status vpn1
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
        status: CONNECTED
        openvpn-status: CONNECTED
        in-total: 0
        out-total: 3018
        connected-time: 1505802975
        in-current: 3005
        out-current: 3018
        timestamp: 1505803003

```


### Disconnect the VPN
```console
$ rvc disconnect vpn1
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
        status: DISCONNECTING
        openvpn-status: CONNECTED
        in-total: 0
        out-total: 3276
        timestamp: 1505803046

```

```console
$ rvc status vpn1
name: vpn1
	profile: /opt/rvc/etc/vpn.d/vpn1.ovpn
        status: DISCONNECTED
        openvpn-status: DISCONNECTED
        in-total: 3195
        out-total: 3276
        timestamp: 1505803072

```
