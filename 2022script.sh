#!/bin/bash

VERSION="1.1.5"

SSRUST_CIPHERS=(
none
plain
aes-128-gcm
aes-256-gcm
chacha20-ietf-poly1305
2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm
2022-blake3-chacha20-poly1305
)

CURRENT_PATH=$(pwd)
# You can set this variable whatever you want in shell session right before running this script by issuing:
# export SSRUST_ROOT_DIR='/etc/rustss2022'
SSRUST_ROOT_DIR="${SSRUST_ROOT_DIR:-$CURRENT_PATH/rustss2022}"
SSSERVICE_BIN_FILE="${SSRUST_ROOT_DIR}/ssservice"
SSRUST_CONFIG_FILE="${SSRUST_ROOT_DIR}/config.json"
URL_SCHEME_CONF="${SSRUST_ROOT_DIR}/url_scheme.conf"
SSRUST_SERVICE_FILE="/etc/systemd/system/ss-rust.service"
SSRUST_SERVICE_NAME="$(basename $SSRUST_SERVICE_FILE)"
SCRIPT_ENV_DIR="/root/.2022ScriptEnv"
SCRIPT_ENV_VARIABLES_FILE="${SCRIPT_ENV_DIR}/env.info"

logo(){
    yellow " ____   ___ ____  ____    ____            _       _   "
    yellow "|___ \ / _ \___ \|___ \  / ___|  ___ _ __(_)_ __ | |_ "
    yellow "  __) | | | |__) | __) | \___ \ / __| '__| | '_ \| __|"
    yellow " / __/| |_| / __/ / __/   ___) | (__| |  | | |_) | |_ "
    yellow "|_____|\___/_____|_____| |____/ \___|_|  |_| .__/ \__|"
    yellow "                                           |_|        "
}

usage(){
    clear -x && logo
    echo -e "\nUsage: "
    echo -e "  ./$(basename "$0") [OPTIONS...] [ARGS...]\n"
    echo -e "Options: "
    echo -e "  -i  --install            Install ss-rust"
    echo -e "  -r  --remove             Remove ss-rust"
    echo -e "  -f  --cover              Cover install ss-rust"
    echo -e "  -p  --specifypi          Specify path install ss-rust"
    echo -e "  -u  --update-script      Update script"
    echo -e "  -l  --log                Show log information"
    echo -e "  -c  --config             Show config information"
    echo -e "  -s  --url-scheme         Show url-scheme information"
    echo -e "  -st --start              Start ss-rust"
    echo -e "  -sp --stop               Stop ss-rust"
    echo -e "  -rt --restart            Restart ss-rust"
    echo -e "  -ss --status             Show ss-rust status"
    echo -e "  -b  --bbr                Enable bbr"
    echo -e "  -fw --firewall           Config firewall manual mode"
    echo -e "  -v  --version            Show script version number"
    echo -e "  -h  --help               Show this help\n"
    echo -e "Source: https://github.com/loyess/2022"
    echo -e "BBR-Source: https://github.com/teddysun/across\n"
}

info(){
    echo -e "\033[32m[Info]\033[0m $1"
}

error(){
    echo -e "\033[31m[Error]\033[0m $1"
}

red(){
    echo -e "\033[31m$1\033[0m"
}

yellow(){
    echo -e "\033[0;33m$1\033[0m"
}

check_arch(){
    case "$(uname -m)" in
      'amd64' | 'x86_64')
        ARCH='x86_64'
        ;;
      'armv8' | 'aarch64')
        ARCH='aarch64'
        ;;
      *)
        error "The architecture is not supported." && exit 1
        ;;
    esac
}

check_system(){
    if [ "$(command -v apt-get)" ]; then
        PKGMER='apt-get'
    elif [ "$(command -v dnf)" ]; then
        PKGMER='dnf'
    elif [ "$(command -v yum)" ]; then
        PKGMER='yum'
    else
        error "OS not supported..." && exit 1
    fi
}

pkg_install(){
    local packages=$1

    info "The following packages will be installed: " 
    if [ "${PKGMER}" = 'dnf' ] || [ "${PKGMER}" = 'yum' ]; then
        echo -e "\n  \033[32m${PKGMER} install -y ${packages}\033[0m\n"
        # shellcheck disable=SC2086
        ${PKGMER} install -y ${packages}
    else
        echo -e "\n  \033[32m${PKGMER} update\033[0m"
        echo -e "  \033[32m${PKGMER} install -y ${packages}\033[0m\\n"
        ${PKGMER} update
        # shellcheck disable=SC2086
        ${PKGMER} install -y ${packages}
    fi
}

get_ip(){
    local IP

    IP=$(ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    [ -z "${IP}" ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z "${IP}" ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo "${IP}"
}

get_ipv6(){
    local ipv6

    ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z "${ipv6}" ] && return 1 || return 0
}

get_char(){
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty "$SAVEDSTTY"
}

get_env_variable(){
    local varName=$1
    local keyValuePair

    keyValuePair=$(grep "${varName}" "${SCRIPT_ENV_VARIABLES_FILE}")
    # shellcheck disable=SC2163
    [ -n "${keyValuePair}" ] && export "${keyValuePair}"
}

write_env_variable(){
    local keyValuePairText=$1

    echo "${keyValuePairText}" >> "${SCRIPT_ENV_VARIABLES_FILE}"
}

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep -q 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

get_base64_encode(){
    echo -n "$1" | base64 -w0
}

gen_random_prot(){
    ran_prot="$(shuf -i 9000-19999 -n 1)"
}

gen_random_psk(){
    ssrustPwd=$(openssl rand -base64 "$1")
    echo "The PSK is automatically generated based on the selected encryption method. Please don't modify it."
    red "\n  Password = ${ssrustPwd}\n"
}

gen_random_str(){
    ran_str12="$(head -c 100 /dev/urandom | tr -dc a-z0-9A-Z | head -c 12)"
}

download(){
    local filename

    filename=$(basename "$1")
    if [ -e "${1}" ]; then
        error "The file ${filename} already exists."
    else
        info "The file ${filename} does't exist in the current directory to start downloading now."
        wget --no-check-certificate -c -t3 -T60 -O "${1}" "${2}"
        if [ $? -ne 0 ]; then
            error "The file ${filename} download failed."
            rm -rf "${1}" && info "rm -rf ${1}" && exit 1
        fi
    fi
}

download_ssrust(){
    local API_URL SSRUST_URL

    check_arch
    API_URL="https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases"
    # You can set this variable whatever you want in shell session right before running this script by issuing:
    # export SSRUST_VERSION='1.15.0-alpha.5'
    SSRUST_VERSION=${SSRUST_VERSION:-$(curl -s -m 10 ${API_URL} | grep 'tag_name' | grep 'alpha' | cut -d\" -f4 | head -n 1 | sed 's/v//g')}
    [ -z "${SSRUST_VERSION}" ] && error "The network connection timed out and failed to obtain the ss-rust version number." && exit 1
    SSRUST_TARXZ_FILE_NAME="shadowsocks-v${SSRUST_VERSION}.${ARCH}-unknown-linux-musl"
    SSRUST_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${SSRUST_VERSION}/${SSRUST_TARXZ_FILE_NAME}.tar.xz"
    TEMP_PATH=$(mktemp -d)
    download "${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}.tar.xz" "${SSRUST_URL}"
}

get_input_port(){
    local port
    
    gen_random_prot
    read -p "Please enter a port [1-65535] (deafult: ${ran_prot}): " port
    [ -z "${port}" ] && port="${ran_prot}"
    ssrustPort="${port}"
    red "\n  Port = ${ssrustPort}\n"
    info "The script does't perform port occupancy detection. If you cannot connect, please check by yourself.\n"
}

get_input_cipher(){
    local index

    echo -e "Shadowsocks-rust Ciphers: \n"
    for ((i=1;i<=${#SSRUST_CIPHERS[@]};i++)); do
        echo -e "  $i. ${SSRUST_CIPHERS[$i-1]}"
    done
    echo && read -p "Please select an encryption method (deafult: ${SSRUST_CIPHERS[5]}): " index
    [ -z "${index}" ] && index=6
    ssrustCipher="${SSRUST_CIPHERS[$index-1]}"
    red "\n  Method = ${ssrustCipher}\n"
}

get_input_password(){
    local pwdStr
    
    if [ "${ssrustCipher}" = "2022-blake3-aes-128-gcm" ]; then
        gen_random_psk 16
    elif [ "${ssrustCipher}" = "2022-blake3-aes-256-gcm" ]; then
        gen_random_psk 32
    elif [ "${ssrustCipher}" = "2022-blake3-chacha20-poly1305" ]; then
        gen_random_psk 32
    else
        gen_random_str
        read -p "Please enter a password (deafult: ${ran_str12}): " pwdStr
        [ -z "${pwdStr}" ] && pwdStr="${ran_str12}"
        ssrustPwd="${pwdStr}"
        red "\n  Password = ${ssrustPwd}\n"
    fi
}

get_input_dns(){
    local nameServer

    read -p "Please enter a dns (deafult: 8.8.8.8): " nameServer
    [ -z "${nameServer}" ] && nameServer="8.8.8.8"
    ssrustDns="${nameServer}"
    red "\n  DNS = ${ssrustDns}\n"
}

is_enable_persistent(){
    read -p "Whether to persist iptables and ip6tables (deafult: n)[y/n]" isPersist
    [ -z "${isPersist}" ] && isPersist="N"
    case "${isPersist}" in
        y|Y)
            PERSISTENT='yes'
            red "\n  iptables = enable persistent\n"
            ;;
        *)
            PERSISTENT='no'
            red "\n  iptables = disable persistent\n"
            ;;
    esac
    info "If you don't understand iptables persistence please keep the default options"
}

config_ssrust(){
    info "Writing config information into: ${SSRUST_CONFIG_FILE}"
	cat > "${SSRUST_CONFIG_FILE}" <<-EOF
	{
	    "server":${ssrustServer},
	    "server_port":${ssrustPort},
	    "password":"${ssrustPwd}",
	    "timeout":300,
	    "method":"${ssrustCipher}",
	    "ipv6_first":${ipv6First},
	    "mode":"tcp_and_udp"
	}
	EOF
}

iptables_start(){
    if ! systemctl is-active iptables 2>/dev/null | head -n 1 | grep -qE '^active$'; then
        systemctl start iptables
        systemctl enable iptables
    fi
}

ip6tables_start(){
    if ! systemctl is-active ip6tables 2>/dev/null | head -n 1 | grep -qE '^active$'; then
        systemctl start ip6tables
        systemctl enable ip6tables
    fi
}

iptables_persistent(){
    if [ "${PKGMER}" = 'dnf' ] || [ "${PKGMER}" = 'yum' ]; then
        if [ ! -e "/etc/systemd/system/multi-user.target.wants/iptables.service" ]; then
            ${PKGMER} install -y "iptables-services"
        fi
        iptables_start
        iptables-save > /etc/sysconfig/iptables
        ip6tables_start
        ip6tables-save > /etc/sysconfig/ip6tables
    else
        if [ ! -e "/etc/systemd/system/multi-user.target.wants/netfilter-persistent.service" ]; then
            # ref: https://gist.github.com/alonisser/a2c19f5362c2091ac1e7
            echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | debconf-set-selections
            echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections
            ${PKGMER} install -y "iptables-persistent"
        fi
        iptables_start
        iptables-save > /etc/iptables/rules.v4
        ip6tables_start
        ip6tables-save > /etc/iptables/rules.v6
    fi
}

add_firewall_rule(){
    local PORT=$1
    local PROTOCOL=$2

    if [ "${FIREWALL_MANAGE_TOOL}" = 'firewall-cmd' ]; then
        if firewall-cmd --list-ports --permanent 2>/dev/null | grep -qw "${PORT}/${PROTOCOL}"; then
            return
        fi
        firewall-cmd --permanent --zone=public --add-port="${PORT}"/"${PROTOCOL}" > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'ufw' ]; then
        if ufw status 2>/dev/null | grep -qw "${PORT}/${PROTOCOL}"; then
            return
        fi
        ufw allow "${PORT}"/"${PROTOCOL}" > /dev/null 2>&1
        ufw reload > /dev/null 2>&1
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'iptables' ]; then
        if iptables -L 2>/dev/null | grep -q "allow ${PORT}/${PROTOCOL}(ss-rust)"; then
            return
        fi
        iptables -I INPUT -p "${PROTOCOL}" --dport "${PORT}" -m comment --comment "allow ${PORT}/${PROTOCOL}(ss-rust)" -j ACCEPT > /dev/null 2>&1
        ip6tables -I INPUT -p "${PROTOCOL}" --dport "${PORT}" -m comment --comment "allow ${PORT}/${PROTOCOL}(ss-rust)" -j ACCEPT > /dev/null 2>&1
        if [ "${PERSISTENT}" = 'yes' ]; then
            iptables_persistent
        fi
    fi
}

remove_firewall_rule(){
    local PORT=$1
    local PROTOCOL=$2

    if [ "${FIREWALL_MANAGE_TOOL}" = 'firewall-cmd' ]; then
        if ! firewall-cmd --list-ports --permanent 2>/dev/null | grep -qw "${PORT}/${PROTOCOL}"; then
            return
        fi
        firewall-cmd --permanent --zone=public --remove-port="${PORT}"/"${PROTOCOL}" > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'ufw' ]; then
        if ! ufw status 2>/dev/null | grep -qw "${PORT}/${PROTOCOL}"; then
            return
        fi
        ufw delete allow "${PORT}"/"${PROTOCOL}" > /dev/null 2>&1
        ufw reload > /dev/null 2>&1
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'iptables' ]; then
        if ! iptables -L 2>/dev/null | grep -q "allow ${PORT}/${PROTOCOL}(ss-rust)"; then
            return
        fi
        iptables-save |  sed -e '/ss-rust/d' | iptables-restore
        ip6tables-save |  sed -e '/ss-rust/d' | ip6tables-restore
        if [ "${PERSISTENT}" = 'yes' ]; then
            iptables_persistent
        fi
    fi
}

view_firewll_rule(){
    local PORT=$1

    if [ "${FIREWALL_MANAGE_TOOL}" = 'firewall-cmd' ]; then
        info "Firewall Manager: \033[32mfirewall-cmd\033[0m"
        info "All open ports will be listed below including port: ${PORT}"
        firewall-cmd --list-ports --permanent
        info "If it does not include port: \033[32m${PORT}\033[0m then opening the port fails, please check the firewall settings yourself"
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'ufw' ]; then
        info "Firewall Manager: \033[32mufw\033[0m"
        info "All open ports will be listed below including port: ${PORT}"
        ufw status
        info "If it does not include port: \033[32m${PORT}\033[0m then opening the port fails, please check the firewall settings yourself"
    elif [ "${FIREWALL_MANAGE_TOOL}" = 'iptables' ]; then
        info "Firewall Manager: \033[32miptables\033[0m"
        info "All open ports will be listed below including port: ${PORT}"
        iptables -L INPUT --line-numbers
        info "Firewall Manager: \033[32mip6tables\033[0m"
        info "All open ports will be listed below including port: ${PORT}"
        ip6tables -L INPUT --line-numbers
        info "If it does not include port: \033[32m${PORT}\033[0m then opening the port fails, please check the firewall settings yourself"
    fi
}

firewall_status(){
    if [ "$(command -v firewall-cmd)" ] && firewall-cmd --state 2>/dev/null | head -n 1 | grep -Eq '^running$'; then
        FIREWALL_MANAGE_TOOL='firewall-cmd'
    elif [ "$(command -v ufw)" ] && ufw status numbered 2>/dev/null | head -n 1 | cut -d\  -f2 | grep -Eq '^active$'; then
        FIREWALL_MANAGE_TOOL='ufw'
    elif [ "$(command -v iptables)" ] && [ "$(command -v ip6tables)" ]; then
        FIREWALL_MANAGE_TOOL='iptables'
    fi
}

config_firewall(){
    local PORT=$1

    add_firewall_rule "${PORT}" "tcp"
    add_firewall_rule "${PORT}" "udp"
    view_firewll_rule "${PORT}"
    write_env_variable "FIREWALL_MANAGE_TOOL=${FIREWALL_MANAGE_TOOL}"
    [ -n "${PERSISTENT}" ] && write_env_variable "PERSISTENT=${PERSISTENT}"
}

config_firewall_manual(){
    local ACTIONS=$1
    local PORT=$2

    firewall_status
    if [ -z "${FIREWALL_MANAGE_TOOL}" ]; then
        error "Command firewall-cmd | ufw | iptables not exsits or not enabled"
        exit 1
    fi
    case "${ACTIONS}" in
      a|add)
        add_firewall_rule "${PORT}" "tcp"
        add_firewall_rule "${PORT}" "udp"
        view_firewll_rule "${PORT}"
        ;;
      r|remove)
        remove_firewall_rule "${PORT}" "tcp"
        remove_firewall_rule "${PORT}" "udp"
        view_firewll_rule "${PORT}"
        ;;
      v|view)
        view_firewll_rule "${PORT}"
        exit 0
        ;;
      *)
        error "Usage: ./$(basename "$0") [-fw|--firewall] <a|add|r|remove|v|view> <port>"
        exit 1
        ;;
    esac
}

ssrust_service(){
    info "Writing service information into: ${SSRUST_SERVICE_FILE}"
	cat > ${SSRUST_SERVICE_FILE} <<-EOF
	[Unit]
	Description=Shadowsocks-rust Default Server Service
	Documentation=https://github.com/shadowsocks/shadowsocks-rust
	After=network.target
	
	[Service]
	Type=simple
	LimitNOFILE=32768
	ExecStart=${SSSERVICE_BIN_FILE} server --log-without-time --dns ${ssrustDns} -c ${SSRUST_CONFIG_FILE}
	
	[Install]
	WantedBy=multi-user.target
	EOF
    info "Reload systemd manager configuration."
    systemctl daemon-reload
    info "Set the shadowsocks-rust service to start on boot."
    systemctl enable "${SSRUST_SERVICE_NAME}"
    info "Starting shadowsocks-rust service."
    systemctl start "${SSRUST_SERVICE_NAME}"
}

url_scheme(){
    local userinfo hostnamePort

    userinfo=$(get_base64_encode "${ssrustCipher}:${ssrustPwd}")
    hostnamePort="$(get_ip):${ssrustPort}"
    info "The information of shadowsocks-rust <ss://links> is as follows:"
    red "\n  ss://${userinfo}@${hostnamePort}\n"
    info "Writing <ss://links> information into: ${URL_SCHEME_CONF}"
    echo -e "\033[32m[Info]\033[0m The information of shadowsocks-rust <ss://links> is as follows:" > "${URL_SCHEME_CONF}"
    echo -e "\n\033[31m  ss://${userinfo}@${hostnamePort}\033[0m\n" >> "${URL_SCHEME_CONF}"
    info "Shadowsocks-rust installation is complete."
}

install_detect(){
    if [ -e "/root/.2022ScriptEnv/path.info" ]; then
        read SSRUST_ROOT_DIR < /root/.2022ScriptEnv/path.info
        return
    fi
    if [ -e "${SCRIPT_ENV_VARIABLES_FILE}" ]; then
        get_env_variable "SSRUST_ROOT_DIR"
    else
        error "Shadowsocks-rust not installed." && exit 1
    fi
}

log_cat(){
    install_detect
    journalctl -xen -u ss-rust --no-pager
}

config_cat(){
    install_detect
    clear -x && cat "${SSRUST_ROOT_DIR}/config.json"
    echo -e "\n${SSRUST_ROOT_DIR}/config.json\n"
}

url_scheme_cat(){
    install_detect
    clear -x && cat "${SSRUST_ROOT_DIR}/url_scheme.conf"
}

start_cmd(){
    install_detect
    systemctl start "${SSRUST_SERVICE_NAME}"
    [ $? -eq 0 ] && info "Shadowsocks-rust start success."
}

stop_cmd(){
    install_detect
    systemctl stop "${SSRUST_SERVICE_NAME}"
    [ $? -eq 0 ] && info "Shadowsocks-rust stop success."
}

restart_cmd(){
    install_detect
    systemctl restart "${SSRUST_SERVICE_NAME}"
    [ $? -eq 0 ] && info "Shadowsocks-rust restart success."
}

status_cmd(){
    install_detect
    systemctl status "${SSRUST_SERVICE_NAME}"
}

judge_folder_is_null()(
    if [ "$(ls -A "$1")" = "" ]; then
        return 0
    else
        return 1
    fi
)

remove_ssrust(){
    local file filesList port

    install_detect
    info "Starting remove shadowsocks-rust."
    port=$(grep 'server_port' "${SSRUST_ROOT_DIR}/config.json" | sed 's/"//g;s/,//g' | cut -d: -f2)
    get_env_variable "PERSISTENT"
    get_env_variable "FIREWALL_MANAGE_TOOL"
    remove_firewall_rule "${port}" tcp
    remove_firewall_rule "${port}" udp
    info "Remove port ${port} from firewall rule."
    systemctl stop "${SSRUST_SERVICE_NAME}" && echo "systemctl stop ${SSRUST_SERVICE_NAME}"
    systemctl disable "${SSRUST_SERVICE_NAME}" && echo "systemctl disable ${SSRUST_SERVICE_NAME}"
    rm -rf "${SSRUST_SERVICE_FILE}" && echo "rm -rf ${SSRUST_SERVICE_FILE}"
    filesList=(config.json sslocal ssmanager ssserver ssservice ssurl url_scheme.conf)
    for file in "${filesList[@]}"; do
        rm -rf "${SSRUST_ROOT_DIR:?}/${file}" && echo "rm -rf ${SSRUST_ROOT_DIR:?}/${file}"
    done
    if judge_folder_is_null "$SSRUST_ROOT_DIR"; then
        rm -rf "${SSRUST_ROOT_DIR}" && echo "rm -rf ${SSRUST_ROOT_DIR}"
    else
        info "The folder \033[0;33m${SSRUST_ROOT_DIR}\033[0m is not null skipped delete."
    fi
    rm -rf "${SCRIPT_ENV_DIR}" && echo "rm -rf ${SCRIPT_ENV_DIR}"
    info "Remove done."
}

install_dependencies(){
    if [ "${PKGMER}" = 'dnf' ] || [ "${PKGMER}" = 'yum' ]; then
        pkg_install "wget chrony"
    else
        pkg_install "wget ntpdate"
    fi
}

sync_time(){
    info "Start sync time.."
    if [ "$(command -v ntpdate)" ]; then
        ntpdate pool.ntp.org
        [ $? -eq 0 ] && info "Sync time Success. Now: $(date -R)"
    elif [ "$(command -v chronyc)" ]; then
        chronyc -a makestep
        [ $? -eq 0 ] && info "Sync time Success. Now: $(date -R)"
    fi
}

install_ssrust(){
    [ $EUID -ne 0 ] && error "This script must be run as root !" && exit 1
    disable_selinux
    [ -e "${SCRIPT_ENV_VARIABLES_FILE}" ] && error "Shadowsocks-rust is already installed." && exit 1
    clear -x && logo
    get_input_port
    get_input_cipher
    get_input_password
    get_input_dns
    firewall_status
    if [ "${FIREWALL_MANAGE_TOOL}" = 'iptables' ]; then
        is_enable_persistent
    fi
    info "Press any key to start... or Ctrl+C to cancel."
    get_char
    check_system
    install_dependencies
    download_ssrust
    if [ ! -d "${SSRUST_ROOT_DIR}" ]; then
        mkdir -p "${SSRUST_ROOT_DIR}"
        info "Creating shadowsocks-rust root directory: ${SSRUST_ROOT_DIR}"
    fi
    if [ ! -d "${SCRIPT_ENV_DIR}" ]; then
        mkdir -p "${SCRIPT_ENV_DIR}"
        info "Creating $(basename "$0") script env directory: ${SCRIPT_ENV_DIR}"
    fi
    info "Writing shadowsocks-rust install path into: ${SCRIPT_ENV_VARIABLES_FILE}"
    write_env_variable "SSRUST_ROOT_DIR=${SSRUST_ROOT_DIR}"
    info "Extract the tar.xz file: ${SSRUST_TARXZ_FILE_NAME}.tar.xz"
    tar -C "${SSRUST_ROOT_DIR}" -xvf "${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}".tar.xz
    rm -rf "${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}".tar.xz && echo "rm -rf ${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}.tar.xz"
    local ipv6First="false"
    local ssrustServer="\"0.0.0.0\""
    if get_ipv6; then
        ipv6First="true"
        ssrustServer="\"::\""
    fi
    config_ssrust
    config_firewall "${ssrustPort}"
    sync_time
    ssrust_service
    url_scheme
}

cover_install(){
    install_detect
    download_ssrust
    stop_cmd
    info "Extract the tar.xz file: ${SSRUST_TARXZ_FILE_NAME}.tar.xz"
    tar -C "${SSRUST_ROOT_DIR}" -xvf "${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}".tar.xz
    rm -rf "${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}".tar.xz && echo "rm -rf ${TEMP_PATH}/${SSRUST_TARXZ_FILE_NAME}.tar.xz"
    info "Shadowsocks-rust install done."
    start_cmd
}

specify_path_install(){
    local errorText exampleText
    local SSRUST_ROOT_DIR SSSERVICE_BIN_FILE SSRUST_CONFIG_FILE URL_SCHEME_CONF

    [ -e $SCRIPT_ENV_VARIABLES_FILE ] && error "Shadowsocks-rust is already installed." && exit 1
    exampleText="eg: ./$(basename "$0") -p /etc/ss-rust"
    errorText="After the -p option, you need to specify an absolute path as a parameter."
    [ -z "$1" ] && error "${errorText}\n\n  ${exampleText}\n" && exit 1
    SSRUST_ROOT_DIR="$1"
    SSSERVICE_BIN_FILE="${SSRUST_ROOT_DIR}/ssservice"
    SSRUST_CONFIG_FILE="${SSRUST_ROOT_DIR}/config.json"
    URL_SCHEME_CONF="${SSRUST_ROOT_DIR}/url_scheme.conf"
    install_ssrust
}

version_info(){
    echo -e "$(basename "$0") v${VERSION}"
}

update_script(){
    local API_URL LATEST_VERSION CURRENT_VERSION

    API_URL="https://api.github.com/repos/loyess/2022/tags"
    LATEST_VERSION=$(curl -s -m 10 ${API_URL} | grep 'name' | cut -d\" -f4 | head -n 1 | sed 's/v//g;s/\.//g')
    [ -z "${LATEST_VERSION}" ] && error "The network connection timed out and failed to obtain the ss-rust version number." && exit 1
    CURRENT_VERSION=${VERSION//./}
    if [[ ${LATEST_VERSION} > ${CURRENT_VERSION} ]]; then
        info "The script gets to the new version and starts to update."
        curl -OL https://github.com/loyess/2022/raw/main/2022script.sh
        info "Update done."
        exit 0
    else
        info "Already the latest version, no need to update."
    fi
}

enable_bbr(){
    # shellcheck disable=SC1090
    source <(curl -sL 'https://raw.githubusercontent.com/teddysun/across/master/bbr.sh')
}


if [[ $# -eq 0 ]]; then
    install_ssrust
fi
while [[ $# -ge 1 ]]; do
  case $1 in
    -i|--install)
      shift
      install_ssrust
      ;;
    -r|--remove)
      shift
      remove_ssrust
      ;;
    -f|--cover)
      shift
      cover_install
      ;;
    -p|--specifypi)
      shift
      specify_path_install "$1"
      shift
      ;;
    -u|--update-script)
      shift
      update_script
      ;;
    -l|--log)
      shift
      log_cat
      ;;
    -c|--config)
      shift
      config_cat
      ;;
    -s|--url-scheme)
      shift
      url_scheme_cat
      ;;
    -st|--start)
      shift
      start_cmd
      ;;
    -sp|--stop)
      shift
      stop_cmd
      ;;
    -rt|--restart)
      shift
      restart_cmd
      ;;
    -ss|--status)
      shift
      status_cmd
      ;;
    -b|--bbr)
      shift
      enable_bbr
      ;;
    -fw|--firewall)
      shift
      config_firewall_manual "$1" "$2"
      shift 2
      ;;
    -v|--version)
      shift
      version_info
      ;;
    -h|--help)
      shift
      usage
      ;;
    *)
      usage && exit 1
      ;;
  esac
done