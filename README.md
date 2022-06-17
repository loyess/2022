# 2022script.sh
![](https://img.shields.io/github/stars/loyess/2022.svg)
![](https://img.shields.io/github/forks/loyess/2022.svg) 
![](https://img.shields.io/github/license/loyess/2022.svg)  

## Installation
```
curl -O https://github.com/loyess/2022/raw/main/2022script.sh
chmod +x 2022script.sh
./2022script.sh
```

## Env variables
```
# Specify shadowsocks-rust install path
export SSRUST_ROOT_DIR='/etc/rustss2022'

# Specify shadowsocks-rust install version
export SSRUST_VERSION='1.15.0-alpha.5'
```
Note: Env variables are specified before the script is run. `eg: export SSRUST_ROOT_DIR='/etc/rustss2022' && ./2022script.sh` If the `SSRUST_ROOT_DIR` path is not specified, it will be installed in the `rustss2022` directory under the current path.

## Help information
```
root@debian:~# ./2022script.sh -h
 ____   ___ ____  ____    ____            _       _   
|___ \ / _ \___ \|___ \  / ___|  ___ _ __(_)_ __ | |_ 
  __) | | | |__) | __) | \___ \ / __| '__| | '_ \| __|
 / __/| |_| / __/ / __/   ___) | (__| |  | | |_) | |_ 
|_____|\___/_____|_____| |____/ \___|_|  |_| .__/ \__|
                                           |_|        

Usage: 
  ./2022script.sh [OPTIONS...]

Options: 
  -i  --install        Install ss-rust
  -r  --remove         Uninstall ss-rust
  -f  --cover          Cover install ss-rust
  -l  --log            Show log information
  -c  --config         Show config information
  -u  --url-scheme     Show url-scheme information
  -st --start          Start ss-rust
  -sp --stop           Stop ss-rust
  -rt --restart        Restart ss-rust
  -ss --status         Show ss-rust status
  -h  --help           Show this help

Source: https://github.com/loyess/2022
```

## About firewall
```
This script has no firewall settings, please open the port yourself.
```

Note: Only Linux servers with architectures `amd64|x86_64` and `armv8|aarch64` launched by the `Systemd` management application are supported.

## Links
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [shadowsocks-android](<https://github.com/shadowsocks/shadowsocks-android>)
- [shadowsocks-windows](<https://github.com/shadowsocks/shadowsocks-windows>)
