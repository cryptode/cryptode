
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

## Compile and run rvcd

```sh
$ ./autogen.sh
$ ./configure
$ make
$ sudo ./src/rvcd -c [path of configuration file]
```

