#!/bin/bash
# Color Validation
DF='\e[39m'
Bold='\e[1m'
Blink='\e[5m'
yell='\e[33m'
red='\e[31m'
green='\e[32m'
blue='\e[34m'
PURPLE='\e[35m'
CYAN='\e[36m'
Lred='\e[91m'
Lgreen='\e[92m'
Lyellow='\e[93m'
NC='\e[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
CYAN='\e[36m'
LIGHT='\033[0;37m'
MYIP=$(wget -qO- ipinfo.io/ip);
echo "Checking VPS"
cek=$( curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access | awk '{print $2}'  | grep $MYIP )
if [ $cek = $MYIP ]; then
echo -e "${green}Permission Accepted...${NC}"
else
echo -e "${red}Permission Denied!${NC}";
echo "Your IP NOT REGISTER / EXPIRED | Contact me at Telegram @vpnlegasi to Unlock"
exit 0
fi
clear
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=$(date +"%Y-%m-%d" -d "$dateFromServer")
#########################

BURIQ() {
    curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access >/root/tmp
    data=($(cat /root/tmp | grep -E "^### " | awk '{print $4}'))
    for user in "${data[@]}"; do
        exp=($(grep -E "^### $user" "/root/tmp" | awk '{print $3}'))
        d1=($(date -d "$exp" +%s))
        d2=($(date -d "$biji" +%s))
        exp2=$(((d1 - d2) / 86400))
        if [[ "$exp2" -le "0" ]]; then
            echo $user >/etc/.$user.ini
        else
            rm -f /etc/.$user.ini >/dev/null 2>&1
        fi
    done
    rm -f /root/tmp
}

MYIP=$(wget -qO- ipinfo.io/ip)
Name=$(curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access | grep $MYIP | awk '{print $4}')
echo $Name >/usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman() {
    if [ -f "/etc/.$Name.ini" ]; then
        CekTwo=$(cat /etc/.$Name.ini)
        if [ "$CekOne" = "$CekTwo" ]; then
            res="Expired"
        fi
    else
        res="Permission Accepted..."
    fi
}

PERMISSION() {
    MYIP=$(wget -qO- ipinfo.io/ip)
    IZIN=$(curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access | awk '{print $2}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
        Bloman
    else
        res="Permission Denied!"
    fi
    BURIQ
}
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

add-dns() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m               • ADD DNS SERVER •                \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
if ! command -v resolvconf >/dev/null; then
    echo "Installing resolvconf"
    sudo apt install resolvconf -y >/dev/null
fi

sleep 1
clear -x
echo "AUTO SCRIPT BY VPN LEGASI"
echo "TELEGRAM : https://t.me/vpnlegasi / @vpnlegasi "
echo "PLEASE INPUT THE OPTION NUMBER CORRECTLY"
echo "   1 : INPUT DNS TEMPORARY.REBOOT VPS FOR RETURN TO INITIAL DNS"
echo "   2 : INPUT DNS PERMANENTLY"
read -p "OPTION NUMBER :" option
if [ $option = "1" ]; then
sudo systemctl enable resolvconf.service > /dev/null && clear -x && sudo systemctl start resolvconf.service > /dev/nul
clear -x
echo " "
read -p "KEY IN IP DNS: " ip1

echo "nameserver $ip1" > /etc/resolv.conf && systemctl start resolvconf.service
fi

if [ $option = "2" ]; then
sudo systemctl enable resolvconf.service > /dev/null && clear -x && sudo systemctl start resolvconf.service > /dev/null
clear -x
echo " "
read -p "KEY IN IP DNS: " ip2
sudo dd if=/dev/null of=/etc/resolvconf/resolv.conf.d/head
echo "nameserver $ip2" | sudo tee /etc/resolvconf/resolv.conf.d/head
clear -x
sudo systemctl restart resolvconf.service > /dev/null 
clear -x
sudo resolvconf --enable-updates > /dev/null 
clear -x
sudo resolvconf -u > /dev/null 
clear -x
fi
cat /etc/resolv.conf
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

cek-nf() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m                • CHECK DNS REGION •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36";
UA_Dalvik="Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)";
DisneyAuth="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJiNDAzMjU0NS0yYmE2LTRiZGMtOGFlOS04ZWI3YTY2NzBjMTIiLCJhdWQiOiJ1cm46YmFtdGVjaDpzZXJ2aWNlOnRva2VuIiwibmJmIjoxNjIyNjM3OTE2LCJpc3MiOiJ1cm46YmFtdGVjaDpzZXJ2aWNlOmRldmljZSIsImV4cCI6MjQ4NjYzNzkxNiwiaWF0IjoxNjIyNjM3OTE2LCJqdGkiOiI0ZDUzMTIxMS0zMDJmLTQyNDctOWQ0ZC1lNDQ3MTFmMzNlZjkifQ.g-QUcXNzMJ8DwC9JqZbbkYUSKkB1p4JGW77OON5IwNUcTGTNRLyVIiR8mO6HFyShovsR38HRQGVa51b15iAmXg&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice"
DisneyHeader="authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"
Font_Black="\033[30m";
Font_Red="\033[31m";
Font_Green="\033[32m";
Font_Yellow="\033[33m";
Font_Blue="\033[34m";
Font_Purple="\033[35m";
Font_SkyBlue="\033[36m";
Font_White="\033[37m";
Font_Suffix="\033[0m";
tele="https://t.me/vpnlegasi / search @vpnlegasi"
echo -e "${Font_Blue}SCRIPT EDIT MOD BY VPN LEGASI${Font_Suffix}"
echo -e "${Font_Blue}Sebarang pertanyaan sila hubungi saya di ${tele}${Font_Suffix}"
echo -e "${Font_Blue}Keputusan ujian adalah untuk rujukan sahaja, sila rujuk penggunaan sebenar${Font_Suffix}"
echo -e "Streaming Unlock Content Checker" 
echo -e "system time: $(date)" 

export LANG="en_US";
export LANGUAGE="en_US";

function InstallJQ() {
    #Install JQ
    if [ -e "/etc/redhat-release" ];then
        echo -e "${Font_Green} is installing dependencies: epel-release${Font_Suffix}"
        yum install epel-release -y -q > /dev/null;
        echo -e "${Font_Green} is installing dependencies: jq${Font_Suffix}";
        yum install jq -y -q > /dev/null;
        elif [[ $(cat /etc/os-release | grep '^ID=') =~ ubuntu ]] || [[ $(cat /etc/os-release | grep '^ID=') =~ debian ]];then
        echo -e "${Font_Green} is updating package list...${Font_Suffix}";
        apt-get update -y > /dev/null;
        echo -e "${Font_Green} is installing dependencies: jq${Font_Suffix}";
        apt-get install jq -y > /dev/null;
        elif [[ $(cat /etc/issue | grep '^ID=') =~ alpine ]];then
        apk update > /dev/null;
        echo -e "${Font_Green} is installing dependencies: jq${Font_Suffix}";
        apk add jq > /dev/null;
    else
        echo -e "${Font_Red}Please manually install jq${Font_Suffix}";
        exit;
    fi
}

function PharseJSON() {
    # Usage: PharseJSON "Original JSON text to parse" "Key value to parse"
    # Example: PharseJSON ""Value":"123456"" "Value" [Return result: 123456]
    echo -n $1 | jq -r .$2;
}

function GameTest_Steam(){
    echo -n -e " Steam Currency : \c";
    local result=`curl --user-agent "${UA_Browser}" -${1} -fsSL --max-time 30 https://store.steampowered.com/app/761830 2>&1 | grep priceCurrency | cut -d '"' -f4`;
    
    if [ ! -n "$result" ]; then
        echo -n -e "\r Steam Currency : ${Font_Red}Failed (Network Connection)${Font_Suffix}\n" 
    else
        echo -n -e "\r Steam Currency : ${Font_Green}${result}${Font_Suffix}\n" 
    fi
}


function MediaUnlockTest_Netflix() {
    echo -n -e " Netflix        :\c";
    local result=`curl -${1} --user-agent "${UA_Browser}" -sSL "https://www.netflix.com/" 2>&1`;
    if [ "$result" == "Not Available" ];then
        echo -n -e "\r Netflix        : ${Font_Red}Unsupport${Font_Suffix}\n"
        echo -n -e "\r Netflix        : ${Font_Green}Enjoy Your Movie${Font_Suffix}\n" 
        echo -n -e "\r Netflix        : ${Font_Green}PM @vpnlegasi for rent DNS Unlock Netflix SG + MY${Font_Suffix}\n"
        return;
    fi
    
    if [[ "$result" == "curl"* ]];then
        echo -n -e "\r Netflix        : ${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return;
    fi
    
    local result=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/80018499" 2>&1`;
    if [[ "$result" == *"page-404"* ]] || [[ "$result" == *"NSEZ-403"* ]];then
        echo -n -e "\r Netflix        : ${Font_Red}No${Font_Suffix}\n"
        echo -n -e "\r Netflix        : ${Font_Green}PM @vpnlegasi for rent DNS Unlock Netflix SG + MY${Font_Suffix}\n"
        return;
    fi
    
    local result1=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/70143836" 2>&1`;
    local result2=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/80027042" 2>&1`;
    local result3=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/70140425" 2>&1`;
    local result4=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/70283261" 2>&1`;
    local result5=`curl -${1} --user-agent "${UA_Browser}"-sL "https://www.netflix.com/title/70143860" 2>&1`;
    local result6=`curl -${1} --user-agent "${UA_Browser}" -sL "https://www.netflix.com/title/70202589" 2>&1`;

    if [[ "$result1" == *"page-404"* ]] && [[ "$result2" == *"page-404"* ]] && [[ "$result3" == *"page-404"* ]] && [[ "$result4" == *"page-404"* ]] && [[ "$result5" == *"page-404"* ]] && [[ "$result6" == *"page-404"* ]];then
        echo -n -e "\r Netflix        : ${Font_Yellow}Only Homemade Limited Movie :) ${Font_Suffix}\n"
        echo -n -e "\r Netflix        : ${Font_Purple}PM @vpnlegasi for rent DNS Unlock Netflix SG + MY ${Font_Suffix}\n"
        return;
    fi
    
    local region=`tr [:lower:] [:upper:] <<< $(curl -${1} --user-agent "${UA_Browser}" -fs --write-out %{redirect_url} --output /dev/null "https://www.netflix.com/title/80018499" | cut -d '/' -f4 | cut -d '-' -f1)` ;
    
    if [[ ! -n "$region" ]];then
        region="US";
    fi
        echo -n -e "\r Netflix        : ${Font_Red}IF YOU GET REGION US Maybe Yes/No,Please TRY UR NETFLIX${Font_Suffix}\n"
        echo -n -e "\r Netflix        : ${Font_Green}Yes(Region: ${region})${Font_Suffix}\n"
        echo -n -e "\r Netflix        : ${Font_Green}Enjoy Your Movie${Font_Suffix}\n" 
        echo -n -e "\r Netflix        : ${Font_Purple}PM @vpnlegasi for rent DNS Unlock Netflix SG + MY ${Font_Suffix}\n" 

    return;
}    


function MediaUnlockTest_YouTube_Region() {
    echo -n -e " YouTube Region : ->\c";
    local result=`curl --user-agent "${UA_Browser}" -${1} -sSL "https://www.youtube.com/" 2>&1`;
    
    if [[ "$result" == "curl"* ]];then
        echo -n -e "\r YouTube Region : ${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return;
    fi
    
    local result=`curl --user-agent "${UA_Browser}" -${1} -sL "https://www.youtube.com/red" | sed 's/,/\n/g' | grep "countryCode" | cut -d '"' -f4`;
    if [ -n "$result" ]; then
        echo -n -e "\r YouTube Region : ${Font_Green}${result}${Font_Suffix}\n" 
        return;
    fi
    
    echo -n -e "\r YouTube Region : ${Font_Red}No${Font_Suffix}\n"
    return;
}

function MediaUnlockTest_DisneyPlus() {
    echo -n -e " DisneyPlus     : \c";
    local result=`curl -${1} --user-agent "${UA_Browser}" -sSL "https://global.edge.bamgrid.com/token" 2>&1`;
    
    if [[ "$result" == "curl"* ]];then
        echo -n -e "\r DisneyPlus     : ${Font_Red}Failed (Network Connection)${Font_Suffix}\n" 
        return;
    fi
    
    local previewcheck=`curl -sSL -o /dev/null -L --max-time 30 -w '%{url_effective}\n' "https://disneyplus.com" 2>&1`;
    if [[ "${previewcheck}" == "curl"* ]];then
        echo -n -e "\r DisneyPlus     : ${Font_Red}Failed (Network Connection)${Font_Suffix}\n" 
        return;
    fi
    
    if [[ "${previewcheck}" == *"preview"* ]];then
        echo -n -e "\r DisneyPlus     : ${Font_Red}No${Font_Suffix}\n" 
        return;
    fi
    
    local result=`curl -${1} --user-agent "${UA_Browser}" -fs --write-out '%{redirect_url}\n' --output /dev/null "https://www.disneyplus.com" 2>&1`;
    if [[ "${website}" == "https://disneyplus.disney.co.jp/" ]];then
        echo -n -e "\r DisneyPlus     : ${Font_Green}Yes(Region: JP)${Font_Suffix}\n"
        return;
    fi
    
    local result=`curl -${1} -sSL --user-agent "$UA_Browser" -H "Content-Type: application/x-www-form-urlencoded" -H "${DisneyHeader}" -d "${DisneyAuth}" -X POST  "https://global.edge.bamgrid.com/token" 2>&1`;
    PharseJSON "${result}" "access_token" 2>&1 > /dev/null;
    if [[ "$?" -eq 0 ]]; then
        local region=$(curl -${1} -sSL https://www.disneyplus.com | grep 'region: ' | awk '{print $2}')
        if [ -n "$region" ];then
            echo -n -e "\r DisneyPlus     : ${Font_Green}Yes(Region: $region)${Font_Suffix}\n"
            return;
        fi
        echo -n -e "\r DisneyPlus     : ${Font_Green}Yes${Font_Suffix}\n" 
        return;
    fi
    echo -n -e "\r DisneyPlus     : ${Font_Red}No${Font_Suffix}\n" 
}

function ISP(){
    local result=`curl -sSL -${1} "https://api.ip.sb/geoip" 2>&1`;
    if [[ "$result" == "curl"* ]];then
        return
    fi
    local ip=$(wget -qO- ipinfo.io/ip);
    local isp=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
    if [ $? -eq 0 ];then
        echo " ** IP          : ${ip}"
        echo " ** ISP         : ${isp}"
    fi
}

function MediaUnlockTest() {
    ISP ${1};
    MediaUnlockTest_Netflix ${1};
    MediaUnlockTest_YouTube_Region ${1};
    MediaUnlockTest_DisneyPlus ${1};
    GameTest_Steam ${1};
}

curl -V > /dev/null 2>&1;
if [ $? -ne 0 ];then
    echo -e "${Font_Red}Please install curl${Font_Suffix}";
    exit;
fi

jq -V > /dev/null 2>&1;
if [ $? -ne 0 ];then
    InstallJQ;
fi
echo " ** Testing IPv4 unlocking"
check4=`ping 1.1.1.1 -c 1 2>&1`;
if [[ "$check4" != *"unreachable"* ]] && [[ "$check4" != *"Unreachable"* ]];then
    MediaUnlockTest 4;
else
    echo -e "${Font_SkyBlue}The current host does not support IPv4, skip...${Font_Suffix}"
fi
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

clear-log() {
clear
data=(`find /var/log/ -name *.log`);
for log in "${data[@]}"
do
echo "$log clear"
echo > $log
done
data=(`find /var/log/ -name *.err`);
for log in "${data[@]}"
do
echo "$log clear"
echo > $log
done
data=(`find /var/log/ -name mail.*`);
for log in "${data[@]}"
do
echo "$log clear"
echo > $log
done
echo > /var/log/syslog
echo > /var/log/btmp
echo > /var/log/messages
echo > /var/log/debug
menu
}

trial_ssh() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m               • TRIAL SSH USER •                \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    Login=Trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
    masaaktif="1"
    Pass=123
    IP=$(wget -qO- ipinfo.io/ip)
    hariini=$(date +%d-%m-%Y)
    domain=$(cat /root/domain)
    ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2 | sed 's/ //g')"
    sqd="$(cat ~/log-install.txt | grep -w "Squid Proxy" | cut -d: -f2 | sed 's/ //g')"
    ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    sleep 1
    echo Ping Host
    echo Cek Hak Akses...
    sleep 0.5
    echo Permission Accepted
    clear
    sleep 0.5
    echo Membuat Akun: $Login
    sleep 0.5
    echo Setting Password: $Pass
    sleep 0.5
    clear
    useradd -e $(date -d "$masaaktif days" +"%Y-%m-%d") -s /bin/false -M $Login
    exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
    echo -e "$Pass\n$Pass\n" | passwd $Login &>/dev/null
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Thank You For Using Our Services"
    echo -e "SSH & OpenVPN Account Info"
    echo -e "Username       : $Login "
    echo -e "Password       : $Pass"
    echo -e "Created date   : ${hariini}"
    echo -e "Expired On     : $exp"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "IP Server      : $IP"
    echo -e "Host           : ${domain}"
    echo -e "OpenSSH        : 22"
    echo -e "Dropbear       : 109, 143"
    echo -e "SSL/TLS        : $ssl"
    echo -e "Port Squid     : $sqd"
    echo -e "OpenVPN        : TCP $ovpn http://$IP:81/client-tcp-$ovpn.ovpn"
    echo -e "OpenVPN        : UDP $ovpn2 http://$IP:81/client-udp-$ovpn2.ovpn"
    echo -e "OpenVPN        : SSL 442 http://$IP:81/client-tcp-ssl.ovpn"
    echo -e "badvpn         : 7100-7300"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add_ssh() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m                • ADD SSH USER •                  \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -p "Username : " Login
    read -p "Password : " Pass
    read -p "Expired (hari): " masaaktif
    IP=$(wget -qO- ipinfo.io/ip)
    domain=$(cat /root/domain)
    hariini=$(date +%d-%m-%Y)
    ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2 | sed 's/ //g')"
    sqd="$(cat ~/log-install.txt | grep -w "Squid Proxy" | cut -d: -f2 | sed 's/ //g')"
    ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
    sleep 1
    echo Ping Host
    echo Cek Hak Akses...
    sleep 0.5
    echo Permission Accepted
    clear
    sleep 0.5
    echo Membuat Akun: $Login
    sleep 0.5
    echo Setting Password: $Pass
    sleep 0.5
    clear
    useradd -e $(date -d "$masaaktif days" +"%Y-%m-%d") -s /bin/false -M $Login
    exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
    echo -e "$Pass\n$Pass\n" | passwd $Login &>/dev/null
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Thank You For Using Our Services"
    echo -e "SSH & OpenVPN Account Info"
    echo -e "Username       : $Login "
    echo -e "Password       : $Pass"
    echo -e "Created date   : ${hariini}"
    echo -e "Expired On     : $exp"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "IP Server      : $IP"
    echo -e "Host           : ${domain}"
    echo -e "OpenSSH        : 22"
    echo -e "Dropbear       : 109, 143"
    echo -e "SSL/TLS        : $ssl"
    echo -e "Port Squid     : $sqd"
    echo -e "OpenVPN        : TCP $ovpn http://$IP:81/client-tcp-$ovpn.ovpn"
    echo -e "OpenVPN        : UDP $ovpn2 http://$IP:81/client-udp-$ovpn2.ovpn"
    echo -e "OpenVPN        : SSL 442 http://$IP:81/client-tcp-ssl.ovpn"
    echo -e "badvpn         : 7100-7300"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

all_ssh() {
    clear

    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo "USERNAME          EXP DATE          STATUS"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    while read expired; do
        AKUN="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
        status="$(passwd -S $AKUN | awk '{print $2}')"
        if [[ $ID -ge 1000 ]]; then
            if [[ "$status" = "L" ]]; then
                printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "${RED}LOCKED${NORMAL}"
            else
                printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "${GREEN}UNLOCKED${NORMAL}"
            fi
        fi
    done </etc/passwd
    JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo "Account number: $JUMLAH user"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu

}

del_ssh() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m              • DELETE SSH USER •                 \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -p "Username SSH to Delete : " Pengguna

    if getent passwd $Pengguna >/dev/null 2>&1; then
        userdel $Pengguna
        echo -e "User $Pengguna was removed."
    else
        echo -e "Failure: User $Pengguna Not Exist."
    fi
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

del_exp() {
    hariini=$(date +%d-%m-%Y)
    echo "Thank you for removing the EXPIRED USERS"
    echo "--------------------------------------"
    cat /etc/shadow | cut -d: -f1,8 | sed /:$/d >/tmp/expirelist.txt
    totalaccounts=$(cat /tmp/expirelist.txt | wc -l)
    for ((i = 1; i <= $totalaccounts; i++)); do
        tuserval=$(head -n $i /tmp/expirelist.txt | tail -n 1)
        username=$(echo $tuserval | cut -f1 -d:)
        userexp=$(echo $tuserval | cut -f2 -d:)
        userexpireinseconds=$(($userexp * 86400))
        tglexp=$(date -d @$userexpireinseconds)
        tgl=$(echo $tglexp | awk -F" " '{print $3}')
        while [ ${#tgl} -lt 2 ]; do
            tgl="0"$tgl
        done
        while [ ${#username} -lt 15 ]; do
            username=$username" "
        done
        bulantahun=$(echo $tglexp | awk -F" " '{print $2,$6}')
        echo "echo "Expired- User : $username Expire at : $tgl $bulantahun"" >>/usr/local/bin/alluser
        todaystime=$(date +%s)
        if [ $userexpireinseconds -ge $todaystime ]; then
            :
        else
            echo "echo "Expired- Username : $username are expired at: $tgl $bulantahun and removed : $hariini "" >>/usr/local/bin/deleteduser
            echo "Username $username that are expired at $tgl $bulantahun removed from the VPS $hariini"
            userdel $username
        fi
    done
    echo " "
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo "Script are successfully run"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_ssh() {
    if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log"
    fi
    if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure"
    fi

    data=($(ps aux | grep -i dropbear | awk '{print $2}'))
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo "-----=[ Dropbear User Login ]=-----"
    echo "ID  |  Username  |  IP Address"
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" >/tmp/login-db.txt
    for PID in "${data[@]}"; do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" >/tmp/login-db-pid.txt
        NUM=$(cat /tmp/login-db-pid.txt | wc -l)
        USER=$(cat /tmp/login-db-pid.txt | awk '{print $10}')
        IP=$(cat /tmp/login-db-pid.txt | awk '{print $12}')
        if [ $NUM -eq 1 ]; then
            echo "$PID - $USER - $IP"
        fi
    done
    echo "-----=[ OpenSSH User Login ]=-----"
    echo "ID  |  Username  |  IP Address"
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    cat $LOG | grep -i sshd | grep -i "Accepted password for" >/tmp/login-db.txt
    data=($(ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'))

    for PID in "${data[@]}"; do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" >/tmp/login-db-pid.txt
        NUM=$(cat /tmp/login-db-pid.txt | wc -l)
        USER=$(cat /tmp/login-db-pid.txt | awk '{print $9}')
        IP=$(cat /tmp/login-db-pid.txt | awk '{print $11}')
        if [ $NUM -eq 1 ]; then
            echo "$PID - $USER - $IP"
        fi
    done
    if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
        echo "-----=[ OpenVPN TCP User Login ]=-----"
        echo "Username  |  IP Address  |  Connected Since"
        echo ""
        cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' >/tmp/vpn-login-tcp.txt
        cat /tmp/vpn-login-tcp.txt
    fi
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

    if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
        echo "-----=[ OpenVPN UDP User Login ]=-----"
        echo "Username  |  IP Address  |  Connected Since"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' >/tmp/vpn-login-udp.txt
        cat /tmp/vpn-login-udp.txt
    fi
    read -n 1 -s -r -p "Press any key to back on menu"
    menu

}

extend_ssh() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m              • RENEW SSH USER •                  \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -p "         Username       :  " User
    egrep "^$User" /etc/passwd >/dev/null
    if [ $? -eq 0 ]; then
        read -p "         Day Extend     :  " Days
        Today=$(date +%s)
        Days_Detailed=$(($Days * 86400))
        Expire_On=$(($Today + $Days_Detailed))
        Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d)
        Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y')
        passwd -u $User
        usermod -e $Expiration $User
        egrep "^$User" /etc/passwd >/dev/null
        echo -e "$Pass\n$Pass\n" | passwd $User &>/dev/null
        clear
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e ""
        echo -e "    Username        :  $User"
        echo -e "    Renew date      :  ${hariini}"
        echo -e "    Days Added      :  $Days Days"
        echo -e "    Expires on      :  $Expiration_Display"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    else
        clear
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e ""
        echo -e "        Username Doesnt Exist        "
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    fi
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add_wg() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • ADD WIREGUARD USER •                 \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
source /etc/wireguard/params
source /var/lib/premium-script/ipvps.conf
if [[ "$IP" = "" ]]; then
SERVER_PUB_IP=$(wget -qO- ipinfo.io/ip);
else
SERVER_PUB_IP=$IP
fi
	echo ""
	echo "Tell me a name for the client."
	echo "Use one word only, no special characters."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -w $CLIENT_NAME /etc/wireguard/wg0.conf | wc -l)

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo "A client with the specified name was already created, please choose another name."
			exit 1
		fi
	done

	echo "IPv4 Detected"
	ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
	WG_CONFIG="/etc/wireguard/wg0.conf"
	LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
	if [[ "$LASTIP" = "" ]]; then
	CLIENT_ADDRESS="10.66.66.2"
	else
	CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
	fi

	# Adguard DNS by default
	CLIENT_DNS_1="176.103.130.130"

	CLIENT_DNS_2="176.103.130.131"
	MYIP=$(wget -qO- ipinfo.io/ip);
	read -p "Expired (days): " masaaktif
	exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
	hariini=`date -d "0 days" +"%Y-%m-%d"`
	read -p "Isi Bug Diakhiri Dot (.): " BUG
	domain=$(cat /root/domain)

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2
[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = ${BUG}$ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf"

	# Add the client as a peer to the server
	echo -e "### Client $CLIENT_NAME $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
    systemctl restart "wg-quick@$SERVER_WG_NIC"
    cp $HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf /home/vps/public_html/$CLIENT_NAME.conf
    clear
    sleep 0.5
    echo Generate PrivateKey
    sleep 0.5
    echo Generate PublicKey
    sleep 0.5
    echo Generate PresharedKey
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m         • WIREGUARD USER INFORMATION •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $CLIENT_NAME"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Wireguard Config Link  : "
    echo ""
    echo ""http://$MYIP:81/$CLIENT_NAME.conf""
    echo "" 
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    rm -f /root/wg0-client-$CLIENT_NAME.conf
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

renew_wg() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • RENEW WIREGUARD USER •               \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
clear
source /etc/wireguard/params
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		clear
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	clear
	echo ""
	echo "Select an existing client that you want to renew"
	echo " Press CTRL+C to return"
	echo -e "==============================="
	echo "     No  Expired   User"
	grep -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 3-4 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
        read -p "Expired (days): " masaaktif
        user=$(grep -E "^### Client" "/etc/wireguard/wg0.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
        exp=$(grep -E "^### Client" "/etc/wireguard/wg0.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p)
        now=$(date +%Y-%m-%d)
        d1=$(date -d "$exp" +%s)
        d2=$(date -d "$now" +%s)
        exp2=$(( (d1 - d2) / 86400 ))
        exp3=$(($exp2 + $masaaktif))
        exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
        sed -i "s/### Client $user $exp/### Client $user $exp4/g" /etc/wireguard/wg0.conf
        echo ""
        clear
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "\E[44;1;39m    Wireguard Account Was Successfully Renewe        \E[0m"
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        echo " Client Name  : $user"
 	echo " Created date : ${hariini}"
        echo " Expired On   : $exp4"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
}

del_wg() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • DELETE WIREGUARD USER •               \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    clear
    source /etc/wireguard/params
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
    clear
    echo ""
    echo "You have no existing clients!"
    exit 1
    fi
    clear
    echo ""
    echo " Select the existing client you want to remove"
    echo " Press CTRL+C to return"
    echo " ==============================="
    echo "     No  Expired   User"
    grep -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 3-4 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
    if [[ ${CLIENT_NUMBER} == '1' ]]; then
    read -rp "Select one client [1]: " CLIENT_NUMBER
    else
    read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
    fi
    done

    # match the selected number to a client name
    CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 3-4 | sed -n "${CLIENT_NUMBER}"p)
    user=$(grep -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    exp=$(grep -E "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p)

    # remove [Peer] block matching $CLIENT_NAME
    sed -i "/^### Client $user $exp/,/^AllowedIPs/d" /etc/wireguard/wg0.conf
    # remove generated client file
    rm -f "/home/vps/public_html/$user.conf"

    # restart wireguard to apply changes
    systemctl restart "wg-quick@$SERVER_WG_NIC"
    service cron restart
        echo ""
        clear
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "\E[44;1;39m   Wireguard Account Was Successfully Delete        \E[0m"
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        echo " Client Name  : $user"
    	echo " Created date : ${hariini}"
        echo " Expired On   : $exp"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
}

trial_wg() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • TRIAL WIREGUARD USER •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    clear
    source /etc/wireguard/params
    source /var/lib/premium-script/ipvps.conf
    CLIENT_NAME="Trial-$( </dev/urandom tr -dc 0-9A-Z | head -c4 )"
    if [[ "$IP" = "" ]]; then
    SERVER_PUB_IP=$(wget -qO- ipinfo.io/ip);
    else
    SERVER_PUB_IP=$IP
    fi
    # // Validate Input
    if [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; then 
    CLIENT_EXISTS=$(grep -w $CLIENT_NAME /etc/wireguard/wg0.conf | wc -l)
    fi
    if [[ ${CLIENT_EXISTS} == '1' ]]; then
    echo ""
    echo "A client with the specified name was already created, please choose another name."
    exit 1
    fi
    echo "IPv4 Detected"
    ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
    WG_CONFIG="/etc/wireguard/wg0.conf"
    LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
    if [[ "$LASTIP" = "" ]]; then
    CLIENT_ADDRESS="10.66.66.2"
    else
    CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
    fi

    # Adguard DNS by default
    CLIENT_DNS_1="176.103.130.130"

    CLIENT_DNS_2="176.103.130.131"
    MYIP=$(curl -s https://icanhazip.com);
    Jumlah_Hari=1
    exp=`date -d "$Jumlah_Hari days" +"%Y-%m-%d"`
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    read -p "Isi Bug Diakhiri Dot (.): " BUG
    domain=$(cat /root/domain)

    # Generate key pair for the client
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=$(wg genpsk)

    # Create client file and add the server as a peer
    echo "[Interface]
    PrivateKey = $CLIENT_PRIV_KEY
    Address = $CLIENT_ADDRESS/24
    DNS = $CLIENT_DNS_1,$CLIENT_DNS_2
    [Peer]
    PublicKey = $SERVER_PUB_KEY
    PresharedKey = $CLIENT_PRE_SHARED_KEY
    Endpoint = ${BUG}$ENDPOINT
    AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf"

	# Add the client as a peer to the server
    echo -e "### Client $CLIENT_NAME $exp
    [Peer]
    PublicKey = $CLIENT_PUB_KEY
    PresharedKey = $CLIENT_PRE_SHARED_KEY
    AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
    systemctl restart "wg-quick@$SERVER_WG_NIC"
    cp $HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf /home/vps/public_html/$CLIENT_NAME.conf
    clear
    sleep 0.5
    echo Generate PrivateKey
    sleep 0.5
    echo Generate PublicKey
    sleep 0.5
    echo Generate PresharedKey
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m         • WIREGUARD USER INFORMATION •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $CLIENT_NAME"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Wireguard Config Link  : "
    echo ""
    echo ""http://$MYIP:81/$CLIENT_NAME.conf""
    echo "" 
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    rm -f /root/wg0-client-$CLIENT_NAME.conf
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

cek_wg() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • Wireguard User Login •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    clear
    echo > /etc/wireguard/clients.txt
data=( `cat /etc/wireguard/wg0.conf | grep "### Client" | awk '{ print $3 }'`);
hr(){
    numfmt --to=iec-i --suffix=B "$1"
}
x=1
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • Wireguard User Login •             \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo "Name  Remote IP Virtual IP Bytes Received Bytes Sent Last Seen "
for akun in "${data[@]}"
do
pub=$(cat /etc/wireguard/wg0.conf | grep PublicKey | awk '{ print $3 }' | tr '\n' ' ' | awk '{print $'"$x"'}')
echo "$akun $pub" >> /etc/wireguard/clients.txt
x=$(( "$x" + 1 ))
done
CLIENTS_FILE="/etc/wireguard/clients.txt"
if [ ! -s "$CLIENTS_FILE" ]; then
    echo "::: There are no clients to list"
    exit 0
fi
listClients(){
    if DUMP="$(wg show wg0 dump)"; then
        DUMP="$(tail -n +2 <<< "$DUMP")"
    else
        exit 1
    fi

    printf "\e[1m::: Connected Clients List :::\e[0m\n"

    {
    printf "\e[4mName\e[0m  \t  \e[4mRemote IP\e[0m  \t  \e[4mVirtual IP\e[0m  \t  \e[4mBytes Received\e[0m  \t  \e[4mBytes Sent\e[0m  \t  \e[4mLast Seen\e[0m\n"

    while IFS= read -r LINE; do
        if [ -n "${LINE}" ]; then
            PUBLIC_KEY="$(awk '{ print $1 }' <<< "$LINE")"
            REMOTE_IP="$(awk '{ print $3 }' <<< "$LINE")"
            VIRTUAL_IP="$(awk '{ print $4 }' <<< "$LINE")"
            BYTES_RECEIVED="$(awk '{ print $6 }' <<< "$LINE")"
            BYTES_SENT="$(awk '{ print $7 }' <<< "$LINE")"
            LAST_SEEN="$(awk '{ print $5 }' <<< "$LINE")"
            CLIENT_NAME="$(grep "$PUBLIC_KEY" "$CLIENTS_FILE" | awk '{ print $1 }')"
            if [ "$HR" = 1 ]; then
                if [ "$LAST_SEEN" -ne 0 ]; then
                    printf "%s  \t  %s  \t  %s  \t  %s  \t  %s  \t  %s\n" "$CLIENT_NAME" "$REMOTE_IP" "${VIRTUAL_IP/\/32/}" "$(hr "$BYTES_RECEIVED")" "$(hr "$BYTES_SENT")" "$(date -d @"$LAST_SEEN" '+%b %d %Y - %T')"
                else
                    printf "%s  \t  %s  \t  %s  \t  %s  \t  %s  \t  %s\n" "$CLIENT_NAME" "$REMOTE_IP" "${VIRTUAL_IP/\/32/}" "$(hr "$BYTES_RECEIVED")" "$(hr "$BYTES_SENT")" "(not yet)"
                fi
            else
                if [ "$LAST_SEEN" -ne 0 ]; then
                    printf "%s  \t  %s  \t  %s  \t  %'d  \t  %'d  \t  %s\n" "$CLIENT_NAME" "$REMOTE_IP" "${VIRTUAL_IP/\/32/}" "$BYTES_RECEIVED" "$BYTES_SENT" "$(date -d @"$LAST_SEEN" '+%b %d %Y - %T')"
                else
                    printf "%s  \t  %s  \t  %s  \t  %'d  \t  %'d  \t  %s\n" "$CLIENT_NAME" "$REMOTE_IP" "${VIRTUAL_IP/\/32/}" "$BYTES_RECEIVED" "$BYTES_SENT" "(not yet)"
                fi
            fi
        fi
    done <<< "$DUMP"

    printf "\n"
    } | column -t -s $'\t'
 }
listClients
echo "-------------------------------";
echo -e "Script By VPN Legasi"

    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

trial-ws() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • TRIAL XRAY VMESS WS USER •         \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user=Trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=80
    email=${user}
    cat >/etc/vpnlegasi/xray/$user-tls.json <<EOF
      {
       "v": "2",
       "ps": "${user}",
       "add": "${domain}",
       "port": "${multi}",
       "id": "${uuid}",
       "aid": "0",
       "scy": "auto",
       "net": "ws",
       "type": "none",
       "host": "${BUG}",
       "path": "/xrayvws",
       "tls": "tls",
       "sni": "${BUG}"
}
EOF

    cat >/etc/vpnlegasi/xray/$user-none.json <<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "${none}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/xrayws",
      "type": "none",
      "host": "${BUG}",
      "tls": "none"
}
EOF
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","alterId": 0,"add": "'${domain}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$email""'"' /etc/vpnlegasi/xray/conf/vmess-nontls.json
    vmess_base641=$(base64 -w 0 <<<$vmess_json1)
    vmess_base642=$(base64 -w 0 <<<$vmess_json2)
    vmesslink1="vmess://$(base64 -w 0 /etc/vpnlegasi/xray/$user-tls.json)"
    vmesslink2="vmess://$(base64 -w 0 /etc/vpnlegasi/xray/$user-none.json)"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vmesslink1}
${vmesslink2}
EOF


    base64Result=$(base64 -w 0 /etc/vpnlegasi/config-user/${user})
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m     • TRIAL XRAY VMESS WS USER INFORMATION •     \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e " Port Non TLS       : $none"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "VMess TLS : "
    echo ""
    echo '```'$vmesslink1'```'
    echo ""
    echo -e "VMess Non TLS : "
    echo ""
    echo '```'$vmesslink2'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add-ws() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m              • ADD XRAY VMESS WS USER •         \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=80
    email=${user}
    cat >/etc/vpnlegasi/xray/$user-tls.json <<EOF
      {
       "v": "2",
       "ps": "${user}",
       "add": "${domain}",
       "port": "${multi}",
       "id": "${uuid}",
       "aid": "0",
       "scy": "auto",
       "net": "ws",
       "type": "none",
       "host": "${BUG}",
       "path": "/xrayvws",
       "tls": "tls",
       "sni": "${BUG}"
}
EOF

    cat >/etc/vpnlegasi/xray/$user-none.json <<EOF
      {
      "v": "2",
      "ps": "${user}",
      "add": "${domain}",
      "port": "${none}",
      "id": "${uuid}",
      "aid": "0",
      "net": "ws",
      "path": "/xrayws",
      "type": "none",
      "host": "${BUG}",
      "tls": "none"
}
EOF
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","alterId": 0,"add": "'${domain}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","alterId": '"0"',"email": "'""$email""'"' /etc/vpnlegasi/xray/conf/vmess-nontls.json
    vmess_base641=$(base64 -w 0 <<<$vmess_json1)
    vmess_base642=$(base64 -w 0 <<<$vmess_json2)
    vmesslink1="vmess://$(base64 -w 0 /etc/vpnlegasi/xray/$user-tls.json)"
    vmesslink2="vmess://$(base64 -w 0 /etc/vpnlegasi/xray/$user-none.json)"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vmesslink1}
${vmesslink2}
EOF


    base64Result=$(base64 -w 0 /etc/vpnlegasi/config-user/${user})
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m       • XRAY VMESS WS USER INFORMATION •        \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e " Port Non TLS       : $none"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "VMess TLS : "
    echo ""
    echo '```'$vmesslink1'```'
    echo ""
    echo -e "VMess Non TLS : "
    echo ""
    echo '```'$vmesslink2'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_vmessws() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

trial-vless() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m             • ADD XRAY VLESS WS USER •          \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user=Trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"` 
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=8000
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$email""'"' /etc/vpnlegasi/xray/vless-nontls.json
    cat /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json
    vlesslink1="vless://$uuid@wild$domain:$multi?encryption=none&security=tls&sni=${BUG}&type=ws&host=&path=/xrayws#$user"
    vlesslink2="vless://$uuid@$wild$domain:$none?encryption=none&security=none&sni=&type=ws&host=${BUG}&path=/xrayws#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vlesslink1}
${vlesslink2}
EOF
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    systemctl restart xray@n.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m     • TRIAL XRAY VLESS WS USER INFORMATION •    \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e " Port Non TLS       : $none"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "VLess TLS : "
    echo ""
    echo '```'$vlesslink1'```'
    echo ""
    echo -e "VLess Non TLS : "
    echo ""
    echo '```'$vlesslink2'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add-vless() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m             • ADD XRAY VLESS WS USER •          \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"` 
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=8000
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$email""'"' /etc/vpnlegasi/xray/vless-nontls.json
    cat /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json
    vlesslink1="vless://$uuid@wild$domain:$multi?encryption=none&security=tls&sni=${BUG}&type=ws&host=&path=/xrayws#$user"
    vlesslink2="vless://$uuid@$wild$domain:$none?encryption=none&security=none&sni=&type=ws&host=${BUG}&path=/xrayws#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vlesslink1}
${vlesslink2}
EOF
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    systemctl restart xray@n.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m        • XRAY VLESS WS USER INFORMATION •       \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e " Port Non TLS       : $none"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "VLess TLS : "
    echo ""
    echo '```'$vlesslink1'```'
    echo ""
    echo -e "VLess Non TLS : "
    echo ""
    echo '```'$vlesslink2'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_vlessws() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

trial_vlessgrpc() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m              • TRIAL VLess gRPC USER •          \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user=Trial`</dev/urandom tr -dc X-Z0-9 | head -c4`
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=8000
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$email""'"' /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json
    cat /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json
    vlesslinkgrpc="vless://$uuid@$wild$domain:$multi?mode=gun&security=tls&encryption=none&type=grpc&serviceName=directions&sni=$BUG#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vlesslinkgrpc}

EOF
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    systemctl restart xray@n.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m    •TRIAL XRAY VLess gRPC USER INFORMATION •    \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Xray VLess TLS gRPC : "
    echo ""
    echo '```'$vlesslinkgrpc'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add_vlessgrpc() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m              • ADD VLess gRPC USER •            \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    none=8000
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    sed -i '/#xray$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$email""'"' /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json
    cat /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json
    vlesslinkgrpc="vless://$uuid@$wild$domain:$multi?mode=gun&security=tls&encryption=none&type=grpc&serviceName=directions&sni=$BUG#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${vlesslinkgrpc}

EOF
    echo ${base64Result} >"/etc/vpnlegasi/config-url/${uuid}"
    systemctl restart xray.service
    systemctl restart xray@n.service
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m       • XRAY VLess gRPC USER INFORMATION •      \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Xray VLess TLS gRPC : "
    echo ""
    echo '```'$vlesslinkgrpc'```'
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_vlessgrpc() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

trial-trgrpc() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m         • TRIAL XRAY TROJAN gRPC USER •         \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user="Trial-$( </dev/urandom tr -dc 0-9A-Z | head -c4 )"
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json
    trgrpc="trojan://$uuid@$wild$domain:$multi??security=tls&type=grpc&serviceName=directions2&sni=$bugs#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${trgrpc}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m         • TRIAL XRAY TROJAN gRPC USER •        \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "XRAY TRojan gRPC  : "
    echo ""
    echo '```'$trgrpc'```'
    echo ""   
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add-trgrpc() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • ADD XRAY TROJAN gRPC USER •        \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    read -p "Wildcard  : " wild
    read -p "Bug Telco : " bugs
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json
    trgrpc="trojan://$uuid@$wild$domain:$multi??security=tls&type=grpc&serviceName=directions2&sni=$bugs#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${trgrpc}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m      • XRAY USER TROJAN gRPC INFORMATION •      \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Xray TRojan gRPC  : "
    echo ""
    echo '```'$trgrpc'```'
    echo "" 
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_trgrpc() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

trial-trojan() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m       • TRIAL XRAY TROJAN TCP & XTLS USER •     \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user="Trial-$( </dev/urandom tr -dc 0-9A-Z | head -c4 )"
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json
    tro="trojan://$uuid@$wild$domain:$multi?sni=$BUG#$user"
    troxtls="trojan://${uuid}@${wild}${domain}:${multi}?security=tls&type=tcp&flow=xtls-rprx-splice&sni=$BUG#$user"
    troxtlss="trojan://${uuid}@${wild}${domain}:${multi}?security=tls&type=tcp&flow=xtls-rprx-direct&sni=$BUG#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${tro}
${troxtlss}
${troxtlss}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m         • TRIAL TROJAN TCP & XTLS USER •        \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "TRojan TCP XTLS  : "
    echo ""
    echo '```'$tro'```'
    echo ""
    echo -e "TRojan TCP XTLS Splice : "    
    echo "" 
    echo '```'$troxtls'```'
    echo "" 
    echo -e "TRojan TCP XTLS Direct : "      
    echo "" 
    echo '```'$troxtlss'```'
    echo ""   
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add-trojan() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • TROJAN TCP & XTLS USER •           \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json | jq '.inbounds[0].settings.clients += [{"password": "'${uuid}'","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json
    tro="trojan://$uuid@$wild$domain:$multi?sni=$BUG#$user"
    troxtls="trojan://${uuid}@${wild}${domain}:${multi}?security=tls&type=tcp&flow=xtls-rprx-splice&sni=$BUG#$user"
    troxtlss="trojan://${uuid}@${wild}${domain}:${multi}?security=tls&type=tcp&flow=xtls-rprx-direct&sni=$BUG#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${tro}
${troxtlss}
${troxtlss}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m            • TROJAN TCP & XTLS USER •           \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "TRojan TCP XTLS  : "
    echo ""
    echo '```'$tro'```'
    echo ""
    echo -e "TRojan TCP XTLS Splice : "    
    echo "" 
    echo '```'$troxtls'```'
    echo "" 
    echo -e "TRojan TCP XTLS Direct : "      
    echo "" 
    echo '```'$troxtlss'```'
    echo ""   
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check_trojan_tcp() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

trial-xtls() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m    • TRIAL XRAY VLESS XTLS USER INFORMATION •   \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    user="Trial-$( </dev/urandom tr -dc 0-9A-Z | head -c4 )"
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    duration=1
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","add": "'${domain}'","flow": "xtls-rprx-direct","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json
    splice="vless://$uuid@$wild$domain:$multi?flow=xtls-rprx-splice&encryption=none&security=xtls&sni=$BUG&type=tcp&headerType=none&host=#$user"
    direct="vless://$uuid@$wild$domain:$multi?flow=xtls-rprx-direct&encryption=none&security=xtls&sni=$BUG&type=tcp&headerType=none&host=#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${splice}
${direct}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m    • TRIAL XRAY VLESS XTLS USER INFORMATION •   \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Splice : "
    echo ""
    echo '```'$splice'```'
    echo ""
    echo -e "Direct : "
    echo ""
    echo '```'$direct'```'
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

add-xtls() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m      • ADD XRAY VLESS XTLS USER INFORMATION •   \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -p "Username  : " user
    if grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m already exist"
        echo -e ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    read -p "Duration (day) : " duration
    read -p "Wildcard  : " wild
    read -p "Bug SNI / Host  : " BUG
    uuid=$(cat /proc/sys/kernel/random/uuid)
    hariini=`date -d "0 days" +"%Y-%m-%d"`
    exp=$(date -d +${duration}days +%Y-%m-%d)
    domain=$(cat /root/domain)
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    email=${user}
    echo -e "${user}\t${uuid}\t${exp}" >>/etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json | jq '.inbounds[0].settings.clients += [{"id": "'${uuid}'","add": "'${domain}'","flow": "xtls-rprx-direct","email": "'${email}'"}]' >/etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json
    splice="vless://$uuid@$wild$domain:$multi?flow=xtls-rprx-splice&encryption=none&security=xtls&sni=$BUG&type=tcp&headerType=none&host=#$user"
    direct="vless://$uuid@$wild$domain:$multi?flow=xtls-rprx-direct&encryption=none&security=xtls&sni=$BUG&type=tcp&headerType=none&host=#$user"
    cat <<EOF >>"/etc/vpnlegasi/config-user/${user}"
${splice}
${direct}
EOF
    systemctl restart xray
    echo -e "\033[32m[Info]\033[0m XRay Start Successfully !"
    sleep 1
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m        • XRAY VLESS XTLS USER INFORMATION •     \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo -e " Username           : $user"
    echo -e " Created date       : ${hariini}"
    echo -e " Expired date       : $exp"
    echo -e " Port TLS           : $multi"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "Splice : "
    echo ""
    echo '```'$splice'```'
    echo ""
    echo -e "Direct : "
    echo ""
    echo '```'$direct'```'
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

check-xtls() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

del-user() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m               • DELETE XRAY USER •               \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq
    echo -e ""
    read -p "Username : " user
    echo -e ""
    if ! grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m does not exist"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
    uuid="$(cat /etc/vpnlegasi/xray/user.txt | grep -w "$user" | awk '{print $2}')"
    exp=$(grep -E "###" "/etc/vpnlegasi/xray/conf/vmess-nontls.json" | grep -w "$user" | awk '{print $3}')
    cat /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/05_VMess_WS_inbounds.json
    sed -i "/^### $user $exp/,/^},{/d" /etc/vpnlegasi/xray/conf/vmess-nontls.json
    cat /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds_tmp.json /etc/vpnlegasi/xray/conf/03_VLESS_WS_inbounds.json
    sed -i "/^### $user $exp/,/^},{/d" /etc/vpnlegasi/xray/vless-nontls.json
    cat /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.id == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json
    cat /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.password == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_TCP_inbounds.json
    sed -i "/\b$user\b/d" /etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.password == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/04_trojan_gRPC_inbounds.json
    sed -i "/\b$user\b/d" /etc/vpnlegasi/xray/user.txt
    cat /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json | jq 'del(.inbounds[0].settings.clients[] | select(.password == "'${uuid}'"))' >/etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json
    mv -f /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds_tmp.json /etc/vpnlegasi/xray/conf/06_VLESS_gRPC_inbounds.json
    sed -i "/\b$user\b/d" /etc/vpnlegasi/xray/user.txt
    rm /etc/vpnlegasi/config-user/${user} >/dev/null 2>&1
    rm /etc/vpnlegasi/config-url/${uuid} >/dev/null 2>&1
    systemctl restart xray
    systemctl restart xray@n.service
    systemctl restart xray.service
    echo -e "\033[32m[Info]\033[0m xray Start Successfully !"
    echo ""
    echo -e "User \e[32m$user\e[0m deleted Successfully !"
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

extend_user() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m               • EXTEND XRAY USER •               \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq
    echo -e ""
    read -p "Username : " user
    if ! grep -qw "$user" /etc/vpnlegasi/xray/user.txt; then
        echo -e ""
        echo -e "User \e[31m$user\e[0m does not exist"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    else
        uuid=$(grep -wE "$user" "/etc/vpnlegasi/xray/user.txt" | awk '{print $2}')
        exp=$(grep -wE "$user" "/etc/vpnlegasi/xray/user.txt" | awk '{print $3}')
        echo "$user : $exp"
        read -p "Expired (days): " masaaktif
        now=$(date +%Y-%m-%d)
        d1=$(date -d "$exp" +%s)
        d2=$(date -d "$now" +%s)
        exp2=$(((d1 - d2) / 86400))
        exp3=$(($exp2 + $masaaktif))
        exp4=$(date -d "$exp3 days" +"%Y-%m-%d")
        sed -i "/$user/d" /etc/vpnlegasi/xray/user.txt
        echo -e "${user}\t${uuid}\t${exp4}" >>/etc/vpnlegasi/xray/user.txt
        systemctl restart xray >/dev/null 2>&1
        systemctl restart xray@n.service >/dev/null 2>&1
        systemctl restart xray.service >/dev/null 2>&1
        clear
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo -e "\E[44;1;39m     XRAY Account Was Successfully Renewed        \E[0m"
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        echo " Client Name : $user"
        echo " Expired On  : $exp4"
        echo ""
        echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
        echo ""
        read -n 1 -s -r -p "Press any key to back on menu"
        menu
    fi
}

change-domain() {
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m             • CHANGE DOMAIN VPS •                \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e ""
    echo "Please Input Your Pointing Domain In Cloudflare "
    read -rp "Domain/Host: " -e host
    rm /var/lib/premium-script/ipvps.conf
    rm /etc/vpnlegasi/xray/domain
    echo "$host" >>/etc/vpnlegasi/xray/domain
    echo "$host" >/root/domain
    echo "IP=$host" >> /var/lib/premium-script/ipvps.conf
    domain=$(cat /etc/vpnlegasi/xray/domain)
    #Update Sertificate SSL
    echo Starting Update SSL Sertificate
    sleep 3
    sudo pkill -f nginx &
    wait $!
    systemctl stop nginx
    systemctl stop xray.service
    systemctl stop xray@n.service
    sleep 2
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --server letsencrypt >>/etc/vpnlegasi/tls/$domain.log
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/vpnlegasi/xray/xray.crt --keypath /etc/vpnlegasi/xray/xray.key --ecc
    cat /etc/vpnlegasi/tls/$domain.log
    systemctl daemon-reload
    systemctl restart xray@n.service
    systemctl restart xray.service
    systemctl stop nginx
    rm /etc/nginx/conf.d/xasdhxzasd.conf
    touch /etc/nginx/conf.d/xasdhxzasd.conf
    cat <<EOF >>/etc/nginx/conf.d/xasdhxzasd.conf
server {
	listen 81;
	listen [::]:81;
	server_name ${domain};
	# shellcheck disable=SC2154
	return 301 https://${domain};
}
server {
		listen 127.0.0.1:31300;
		server_name _;
		return 403;
}
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/vpnlegasi/config-url/;
    }

    location /xraygrpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /xraytrojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
		add_header Content-Type text/plain;
		alias /etc/vpnlegasi/config-url/;
	}
	location / {
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF
    systemctl daemon-reload
    service nginx restart
    echo -e "\033[32m[Info]\033[0m nginx Start Successfully !"
    echo ""
    echo "Location Your Domain : /root/domain"
    echo ""
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

change_port() {
    multi="$(cat ~/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2 | sed 's/ //g')"
    echo -e "      Change Port $multi"
    read -p "New Port Trojan: " multi2
    if [ -z $multi2 ]; then
        echo "Please Input Port"
        exit 0
    fi
    cek=$(netstat -nutlp | grep -w $multi2)
    if [[ -z $cek ]]; then
        sed -i "s/$multi/$multi2/g" /etc/vpnlegasi/xray/conf/02_VLESS_TCP_inbounds.json
        sed -i "s/$multi/$multi2/g" /root/log-install.txt
        iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $multi -j ACCEPT
        iptables -D INPUT -m state --state NEW -m udp -p udp --dport $multi -j ACCEPT
        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $multi2 -j ACCEPT
        iptables -I INPUT -m state --state NEW -m udp -p udp --dport $multi2 -j ACCEPT
        iptables-save >/etc/iptables.up.rules
        iptables-restore -t </etc/iptables.up.rules
        netfilter-persistent save >/dev/null
        netfilter-persistent reload >/dev/null
        systemctl restart xray >/dev/null
        systemctl restart xray@n.service >/dev/null
        systemctl restart xray.service >/dev/null
        echo -e "\e[032;1mPort $multi2 modified successfully\e[0m"
    else
        echo "Port $multi2 is used"
    fi
}

check_login() {
    echo -n >/tmp/other.txt

    data=($(cat /etc/vpnlegasi/xray/user.txt | awk '{print $1}' | sort | uniq))

    echo "---------------------------------"
    echo "---=[  ALL Multiport Login  ]=---"
    echo "---------------------------------"

    for akun in "${data[@]}"; do
        if [[ -z "$akun" ]]; then
            akun="tidakada"
        fi
        echo -n >/tmp/user.txt
        data2=($(netstat -anp | grep ESTABLISHED | grep tcp6 | grep xray | awk '{print $5}' | cut -d: -f1 | sort | uniq))
        for ip in "${data2[@]}"; do
            jum=$(cat /var/log/xray/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
            if [[ "$jum" = "$ip" ]]; then
                echo "$jum" >>/tmp/user.txt
            else
                echo "$ip" >>/tmp/other.txt
            fi
            jum2=$(cat /tmp/user.txt)
            sed -i "/$jum2/d" /tmp/other.txt >/dev/null 2>&1
        done
        jum=$(cat /tmp/user.txt)
        if [[ -z "$jum" ]]; then
            echo >/dev/null
        else
            jum2=$(cat /tmp/user.txt | nl)
            echo "user : $akun"
            echo "$jum2"
            echo "---------------------------------"
        fi
        rm -rf /tmp/user.txt
    done
    rm -rf /tmp/other.txt

    echo ""
    read -n 1 -s -r -p "Press any key to back on menu"

    menu
}

restart_all() {
    clear
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\E[44;1;39m      • Restart ALL Service •      \E[0m"
    echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    systemctl restart stunnel4
    echo -e "[ ${green}ok${NC} ] Restarting stunnel4 "
    systemctl restart xray
    systemctl restart xray@n.service
    systemctl restart xray.service
    echo -e "[ ${green}ok${NC} ] Restarting Xray "
    systemctl restart dropbear
    echo -e "[ ${green}ok${NC} ] Restarting dropbear "
    read -n 1 -s -r -p "Press any key to back on menu"
    menu

}
check_port() {
    cat /root/log-install.txt
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

backup_vps() {
    green='\e[0;32m'
    NC='\e[0m'
    IP=$(wget -qO- ipinfo.io/ip);
    tokengit=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
    echo -e "[ ${green}INFO${NC} ] Create password for database"
    read -rp "Enter password : " -e InputPass
    sleep 1
    if [[ -z $InputPass ]]; then
        menu
    fi
    echo -e "[ ${green}INFO${NC} ] Processing... "
    mkdir -p /root/backup
    sleep 1

    cp /etc/passwd backup/
    cp /etc/group backup/
    cp /etc/shadow backup/
    cp /etc/gshadow backup/
    cp -r /var/lib/premium-script/ backup/premium-script
    cp /etc/vpnlegasi/xray/user.txt backup/
    cp -r /etc/vpnlegasi/xray/conf backup/conf
    cp -r /etc/wireguard backup/wireguard
    cd /root
    zip -rP $InputPass $IP-$Name.zip backup >/dev/null 2>&1

    ##############++++++++++++++++++++++++#############
    LLatest=$(date)
    Get_Data() {
        git clone https://github.com/vpnlegasi/backupclient.git /root/backupclient/ &>/dev/null
    }

    Mkdir_Data() {
        mkdir /root/backupclient/$Name
    }

    Input_Data_Append() {
        if [ ! -f "/root/backupclient/$Name/$IP-$Name-last-backup" ]; then
            touch /root/backupclient/$Name/$IP-$Name-last-backup
        fi
        echo -e "User         : $Name
last-backup : $LLatest
" >>/root/backupclient/$Name/$IP-$Name-last-backup
        mv /root/$IP-$Name.zip /root/backupclient/$Name/$IP-$Name.zip
    }

    Save_And_Exit() {
        cd /root/backupclient
        git config --global user.email "ovpnlegasi@gmail.com" &>/dev/null
        git config --global user.name "vpnlegasi" &>/dev/null
        rm -rf .git &>/dev/null
        git init &>/dev/null
        git add . &>/dev/null
        git commit -m backup &>/dev/null
        git branch -M main &>/dev/null
        git remote add origin https://github.com/vpnlegasi/backupclient.git
        git push -f https://${tokengit}@github.com/vpnlegasi/backupclient.git &>/dev/null
    }

    if [ ! -d "/root/user-backup/" ]; then
        sleep 1
        echo -e "[ ${green}INFO${NC} ] Getting database... "
        Get_Data
        Mkdir_Data
        sleep 1
        echo -e "[ ${green}INFO${NC} ] Getting info server... "
        Input_Data_Append
        sleep 1
        echo -e "[ ${green}INFO${NC} ] Processing updating server...... "
        Save_And_Exit
    fi
    link="https://github.com/vpnlegasi/backupclient/raw/main/$Name/$IP-$Name.zip"
    sleep 1
    echo -e "[ ${green}INFO${NC} ] Backup done "
    sleep 1
    echo
    sleep 1
    echo -e "[ ${green}INFO${NC} ] Generete Link Backup "
    echo
    sleep 2
    echo -e "The following is a link to your vps data backup file.
Your VPS IP $IP

$link
save the link pliss!

If you want to restore data, please enter the link above.
Thank You For Using Our Services"

    rm -rf /root/backup* >/dev/null 2>&1
    rm -rf /root/backupclient/$Name >/dev/null 2>&1
    echo
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

restore_vps() {
    clear
    green='\e[0;32m'
    NC='\e[0m'
    read -p "Link : " link
    read -p "Pass : " InputPass
    mkdir /root/backup
    wget -q -O /root/backup/backup.zip "$link" &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Getting your data..."
    unzip -P $InputPass /root/backup/backup.zip &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Starting to restore data..."
    rm -f /root/backup/backup.zip &>/dev/null
    sleep 1
    cd /root/backup
    echo -e "[ ${green}INFO${NC} ] • Restoring passwd data..."
    sleep 1
    cp /root/backup/passwd /etc/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring group data..."
    sleep 1
    cp /root/backup/group /etc/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring shadow data..."
    sleep 1
    cp /root/backup/shadow /etc/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring gshadow data..."
    sleep 1
    cp /root/backup/gshadow /etc/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring gshadow data..."
    sleep 1
    cp /root/backup/user.txt /etc/vpnlegasi/xray/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring admin data..."
    sleep 1
    cp -r /var/lib/premium-script/ backup/premium-script &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring admin data..."
    sleep 1
    cp -r wireguard /etc/ &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Restoring Wireguard data..."
    sleep 1  
    cp -r /root/backup/conf /etc/vpnlegasi/xray &>/dev/null
    rm -rf /root/backup &>/dev/null
    echo -e "[ ${green}INFO${NC} ] • Done..."
    sleep 1
    rm -f /root/backup/backup.zip &>/dev/null
    systemctl restart xray
    systemctl restart xray@n.service
    systemctl restart xray.service
    systemctl restart wg-quick@wg0
    echo
    read -n 1 -s -r -p "Press any key to back on menu"
    menu
}

Name=$(curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access | grep $MYIP | awk '{print $4}')
Exp=$(curl -sS https://raw.githubusercontent.com/vpnlegasi/client-ip-multi-v1/main/access | grep $MYIP | awk '{print $3}')
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"

chck_pid() {
    PID=$(ps -ef | grep -v grep | grep nginx | awk '{print $2}')
}

menu_sts() {
    chck_pid
    if [[ ! -z "${PID}" ]]; then
        echo -e "Current status: ${Green_font_prefix} Installed${Font_color_suffix} & ${Green_font_prefix}Running${Font_color_suffix}"
    else
        echo -e "Current status: ${Green_font_prefix} Installed${Font_color_suffix} but ${Red_font_prefix}Not Running${Font_color_suffix}"
    fi
}

clear
menu_ssh() {
clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;39m                   ⇱ SSH MENU ⇲                   \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
menu_sts
echo ""
echo -e " [\e[36m•1\e[0m ] Trial Ssh User"
echo -e " [\e[36m•2\e[0m ] Add Ssh User"
echo -e " [\e[36m•3\e[0m ] All Ssh User"
echo -e " [\e[36m•4\e[0m ] Delete Ssh"
echo -e " [\e[36m•5\e[0m ] Delete User Expired"
echo -e " [\e[36m•6\e[0m ] Extend Ssh"
echo -e " [\e[36m•7\e[0m ] Check User Login"
echo ""
echo -e "Press x or [ Ctrl+C ] • To-Exit"
echo -e ""
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Client Name   : $Name"
echo -e "Expiry script : $Exp"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
    clear
    trial_ssh
    ;;
2)
    clear
    add_ssh
    ;;
3)
    clear
    all_ssh
    ;;
4)
    clear
    del_ssh
    ;;
5)
    clear
    del_exp
    ;;
6)
    clear
    extend_ssh
    ;;
7)
    clear
    check_ssh
    ;;
x)  clear
    menu
    ;;
*)
    echo -e ""
    echo "Sila Pilih Semula"
    sleep 1
    menu_ssh
    ;;
esac
}

clear
menu_wg() {
clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;39m               ⇱ WIREGUARD MENU ⇲                 \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
menu_sts
echo ""
echo -e " [\e[36m•1\e[0m ] Trial Wireguard"
echo -e " [\e[36m•2\e[0m ] Add Wireguard"
echo -e " [\e[36m•3\e[0m ] Delete Wireguard"
echo -e " [\e[36m•4\e[0m ] Extend Wireguard"
echo -e " [\e[36m•5\e[0m ] Check User Login"
echo ""
echo -e "Press x or [ Ctrl+C ] • To-Exit"
echo -e ""
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Client Name   : $Name"
echo -e "Expiry script : $Exp"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
    clear
    trial_wg
    ;;
2)
    clear
    add_wg
    ;;
3)
    clear
    del_wg
    ;;
4)
    clear
    renew_wg
    ;;   
5)
    clear
    cek_wg
    ;;  
x)  clear
    menu
    ;;
*)
    echo -e ""
    echo "Sila Pilih Semula"
    sleep 1
    menu_wg
    ;;
esac
}


menu_xray() {
clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;39m                ⇱ MULTIPORT MENU ⇲                \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
menu_sts
echo ""
echo -e " [\e[36m•1\e[0m ] Trial XRay VMess WS"
echo -e " [\e[36m•2\e[0m ] Add XRay VMess WS"
echo -e " [\e[36m•3\e[0m ] Delete XRay VMess WS"
echo -e " [\e[36m•4\e[0m ] Extend XRay Vmess WS"
echo -e " [\e[36m•5\e[0m ] Check User Login"
echo -e ""
echo -e " [\e[36m•6\e[0m ] Trial XRay VLess WS"
echo -e " [\e[36m•7\e[0m ] Add XRay VLess WS"
echo -e " [\e[36m•8\e[0m ] Delete XRay VLess WS"
echo -e " [\e[36m•9\e[0m ] Extend XRay VLess WS"
echo -e " [\e[36m•10\e[0m] Check User Login"
echo -e ""
echo -e " [\e[36m•11\e[0m] Trial XRay VLess XTLS"
echo -e " [\e[36m•12\e[0m] Add XRay VLess XTLS"
echo -e " [\e[36m•13\e[0m] Delete XRay VLess XTLS"
echo -e " [\e[36m•14\e[0m] Extend XRay VLess XTLS"
echo -e " [\e[36m•15\e[0m] Check User Login"
echo -e ""
echo -e " [\e[36m•16\e[0m] Trial XRay VLess gRPC (SOON MAYBE)"
echo -e " [\e[36m•17\e[0m] Add XRay VLess gRPC (SOON MAYBE)"
echo -e " [\e[36m•18\e[0m] Delete XRay gRPC (SOON MAYBE)"
echo -e " [\e[36m•19\e[0m] Extend XRay gRPC (SOON MAYBE)"
echo -e " [\e[36m•20\e[0m] Check User (SOON MAYBE)"
echo -e ""
echo -e " [\e[36m•21\e[0m] Trial XRay Trojan TCP & XTLS"
echo -e " [\e[36m•22\e[0m] Add XRay Trojan TCP & XTLS"
echo -e " [\e[36m•23\e[0m] Delete XRay TRojan TCP & XTLS"
echo -e " [\e[36m•24\e[0m] Extend XRay TRojan TCP & XTLS"
echo -e " [\e[36m•25\e[0m] Check User Login"
echo -e ""
echo -e " [\e[36m•26\e[0m] Trial XRay Trojan gRPC (SOON MAYBE)"
echo -e " [\e[36m•27\e[0m] Add XRay Trojan gRPC (SOON MAYBE)"
echo -e " [\e[36m•28\e[0m] Delete XRay Trojan gRPC (SOON MAYBE)"
echo -e " [\e[36m•29\e[0m] Extend XRay Trojan gRPC (SOON MAYBE)"
echo -e " [\e[36m•30\e[0m] Check User Login (SOON MAYBE)"
echo ""
echo -e "Press x or [ Ctrl+C ] • To-Exit"
echo -e ""
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Client Name   : $Name"
echo -e "Expiry script : $Exp"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
    clear
    trial-ws
    ;;
2)
    clear
    add-ws
    ;;
3)
    clear
    del-user
    ;;
4)
    clear
    extend_user
    ;;
5)
    clear
    check_vmessws
    ;;
6)
    clear
    trial-vless
    ;;
7)
    clear
    add-vless
    ;;
8)
    clear
    del-user
    ;;
9)
    clear
    extend_user
    ;;
10)
    clear
    check_vlessws
    ;;
11)
    clear
    trial-xtls
    ;;
12)
    clear
    add-xtls
    ;;
13)
    clear
    del-user
    ;;
14)
    clear
    extend_user
    ;;
15)
    clear
    check-xtls
    ;;
16)
    clear
    trial_vlessgrpc
    ;;
17)
    clear
    add_vlessgrpc
    ;;
18)
    clear
    del-user
    ;;
19)
    clear
    extend_user
    ;;
20)
    clear
    check_vlessgrpc
    ;;
21)
    clear
    trial-trojan
    ;;
22)
    clear
    add-trojan
    ;;
23)
    clear
    del-user
    ;;
24)
    clear
    extend_user
    ;;
25)
    clear
    check_trojan_tcp
    ;;
26)
    clear
    trial-trgrpc
    ;;
27)
    clear
    add-trgrpc
    ;;
28)
    clear
    del-user
    ;;
29)
    clear
    extend_user
    ;;
30)
    clear
    check_trgrpc
    ;;
x)  clear
    menu
    ;;
*)
    echo -e ""
    echo "Sila Pilih Semula"
    sleep 1
    menu_xray
    ;;
esac
}

clear
menu_vps() {
clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;39m                    ⇱ VPS MENU ⇲                  \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
menu_sts
echo ""
echo -e " [\e[36m•1\e[0m ] Setup DNS"
echo -e " [\e[36m•2\e[0m ] Check DNS Region"
echo -e " [\e[36m•3\e[0m ] Change VPS Domain"
echo -e " [\e[36m•4\e[0m ] Change Service Port"
echo -e " [\e[36m•5\e[0m ] Restart All Service"
echo -e " [\e[36m•6\e[0m ] Check All Port"
echo -e " [\e[36m•7\e[0m ] Backup"
echo -e " [\e[36m•8\e[0m ] Restore"
echo -e " [\e[36m•9\e[0m ] Clear Log VPS"
echo ""
echo -e "Press x or [ Ctrl+C ] • To-Exit"
echo -e ""
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Client Name   : $Name"
echo -e "Expiry script : $Exp"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
    clear
    add-dns
    ;;
2)
    clear
    cek-nf
    ;;
3)
    clear
    change-domain
    ;;
4)
    clear
    change_port
    ;; 
5)
    clear
    restart_all
    ;;
6)
    clear
    check_port
    ;;
7)
    clear
    backup_vps
    ;;        
8)
    clear
    restore_vps
    ;;
9)
    clear
    clear-log
    ;; 
x)  clear
    menu
    ;;
*)
    echo -e ""
    echo "Sila Pilih Semula"
    sleep 1
    menu_vps
    ;;
esac
}

clear
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;39m             ⇱ MENU SCRIPT VPN LEGASI ⇲           \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
menu_sts
echo ""
echo -e " [\e[36m•1\e[0m ] Menu SSH"
echo -e " [\e[36m•2\e[0m ] Menu Wireguard"
echo -e " [\e[36m•3\e[0m ] Menu XRAY"
echo -e " [\e[36m•4\e[0m ] Menu VPS"
echo ""
echo -e "Press x or [ Ctrl+C ] • To-Exit"
echo -e ""
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "Client Name   : $Name"
echo -e "Expiry script : $Exp"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu : " opt
echo -e ""
case $opt in
1)
    clear
    menu_ssh
    ;;
2)
    clear
    menu_wg
    ;;
3)
    clear
    menu_xray
    ;;
4)
    clear
    menu_vps
    ;;
x) exit ;;
*)
    echo -e ""
    echo "Sila Pilih Semula"
    sleep 1
    menu
    ;;
esac
clear-log