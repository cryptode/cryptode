
# Description

rvd is Ribose VPN Daemon, OpenVPN connection management daemon running on MacOS system.

# Prerequirements

## Install OpenVPN

```sh
$ brew install openvpn
```

## Install development environment

```sh
$ brew install automake autoconf libtool json-c
```

# Run rvd and rvc utility

## Run rvd daemon

```sh
$ ./autogen.sh
$ ./configure
$ make
$ sudo ./src/rvd -c [path of configuration file]
```

## Run rvc utility

1. show help

```
$ ./src/rvc help

Usage: rvc [options]
    Options:
	list [--json]				show list of VPN connections
	connect [all|connection name]		connect to VPN server with given name
	disconnect [all|connection name]	disconnect from VPN server with given name
	status [all|connection name]		get status of VPN connection with given name
	help					print help message

```
2. show VPN configuration list

```sh
$ ./src/rvc list [--json]
```
3. Connect to VPN server

```sh
$ ./src/rvc connect [all | connection name]
```
4. Disconnect from VPN server

```sh
$ ./src/rvc disconnect [all | connection name]
```
5. Get connection status

```sh
$ ./src/rvc status [all | connection name]
```
