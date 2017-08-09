
# Description

rvcd is OpenVPN connection management daemon running on MacOS system.

# Prerequirements

## Install OpenVPN

```sh
$ brew install openvpn
```

## Install development environment

```sh
$ brew install automake autoconf libtool json-c
```

# Run rvcd and rvc utility

## Run rvcd daemon

```sh
$ ./autogen.sh
$ ./configure
$ make
$ sudo ./src/rvcd -c [path of configuration file]
```

## Run rvc utility

1. show help

```
$ ./src/rvc -h

Usage: rvc [options]
    Options:
	-l				show list of VPN connections
	-c [all|connection name]	connect to VPN server with given name
	-d [all|connection name]	disconnect from VPN server with given name
	-s [all|connection name]	get status of VPN connection with given name
	-j				print result using JSON format

```
2. show VPN configuration list

```sh
$ ./src/rvc -l [-j]
```
3. Connect to VPN server

```sh
$ ./src/rvc -c [all | connection name]
```
4. Disconnect from VPN server

```sh
$ ./src/rvc -d [all | connection name]
```
5. Get connection status

```sh
$ ./src/rvc -s [all | connection name]
```
