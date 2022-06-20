# 2022script.sh
![](https://img.shields.io/github/stars/loyess/2022.svg)
![](https://img.shields.io/github/forks/loyess/2022.svg) 
![](https://img.shields.io/github/license/loyess/2022.svg)  

## Installation
```
curl -OL https://github.com/loyess/2022/raw/main/2022script.sh
chmod +x 2022script.sh
./2022script.sh
```

## Specify path install
```
curl -OL https://github.com/loyess/2022/raw/main/2022script.sh
chmod +x 2022script.sh
./2022script.sh --specifypi /etc/ss-rust
```

## Uninstall
```
./2022script.sh --remove
```

## Env variables
```
# Specify shadowsocks-rust install path
export SSRUST_ROOT_DIR='/etc/rustss2022'

# Specify shadowsocks-rust install version
export SSRUST_VERSION='1.15.0-alpha.5'
```
Note: Env variables are specified before the script is run. `eg: export SSRUST_ROOT_DIR='/etc/rustss2022' && ./2022script.sh` If the `SSRUST_ROOT_DIR` path is not specified, it will be installed in the `rustss2022` directory under the current path.

## Encryption method
```
Shadowsocks-rust Ciphers: 

  1. none
  2. plain
  3. aes-256-gcm
  4. aes-128-gcm
  5. chacha20-ietf-poly1305
  6. 2022-blake3-aes-128-gcm
  7. 2022-blake3-aes-256-gcm
  8. 2022-blake3-chacha20-poly1305

Please select an encryption method (deafult: 2022-blake3-aes-128-gcm):
```

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
  ./2022script.sh [OPTIONS...] [ARGS...]

Options: 
  -i  --install            Install ss-rust
  -r  --remove             Remove ss-rust
  -f  --cover              Cover install ss-rust
  -p  --specifypi          Specify path install ss-rust
  -u  --update-script      Update script
  -l  --log                Show log information
  -c  --config             Show config information
  -s  --url-scheme         Show url-scheme information
  -st --start              Start ss-rust
  -sp --stop               Stop ss-rust
  -rt --restart            Restart ss-rust
  -ss --status             Show ss-rust status
  -v  --version            Show script version number
  -h  --help               Show this help

Source: https://github.com/loyess/2022
```

## About firewall
```
This script only simply handles the firewall settings. If you can't connect to the server after installation, please open the port yourself.
```

Note: Only Linux servers with architectures `amd64|x86_64` and `armv8|aarch64` launched by the `Systemd` management application are supported.

## Links
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [shadowsocks-android](<https://github.com/shadowsocks/shadowsocks-android>)
- [shadowsocks-windows](<https://github.com/shadowsocks/shadowsocks-windows>)
