#!/bin/bash

# CuckooInstall

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

source /etc/os-release

# Configuration variables. You can override these in config.
SUDO="sudo"
UPDATE="apt-get update -y"
INSTALL="sudo apt-get install -y"
HOME=/home/$USER/
LOGS=$HOME/CuckooInstall_LOGS
CWD=/home/$USER/.cuckoo
CONFIG=/home/$USER/.cuckoo/conf
vmshare=$HOME/VM/vmshare
GUEST="guest_profile = Win7SP1x86"  #Change the guest OS profile for Volatility after the second "=". Refernce: https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#selecting-a-profile
#vmname=WIN7 #search for WIN7 to change it in areas where the variable does not work.

#ICONS
OK="🚀" #${OK}    #"\e[32m✓\e[0m"
NOK="💀" #${NOK}  #"\e[31m✗\e[0m"
NL="\n" #${NL}

print_copy(){
printf "\033[1;32m
┌────────────────────────────────────────────────────────────┐
│############################################################│
│#################### Installation Script ###################│
│####################         For         ###################│
│####################  Cuckoo Sandbox     ###################│
│############################################################│
└────────────────────────────────────────────────────────────┘
\e[0m\n"
sleep 3
}
#Checks to make sure you can run as sudo and initial setup for the installation
check_viability(){
	    [[ $UID != 0 ]] && {
        type -f sudo || {
            echo "You're not root and you don't have sudo, please become root or install sudo before executing $0"
            exit
        }
    } || {
        SUDO=""
    }

    [[ ! -e /etc/debian_version ]] && {
        echo  "This script currently works only on debian-based (debian, ubuntu...) distros"
        exit 1
    }
	{
	cd $HOME
	mkdir CuckooInstall_LOGS
	cd $HOME
	sleep 3
	}
} &> /dev/null

#Updates and Upgrades the system
perform_update(){
	${SUDO} ${UPDATE}
	echo "####update completed###"
	${SUDO} apt-get upgrade -y
	${SUDO} apt-get upgrade -y --fix-missing
	echo "###upgrade completed###"
	sleep 3
	return 0
} &> $LOGS/update.log

#Installs Packages Packages installed individually to locate issues
install_packages(){
	${INSTALL} python-setuptools
	echo "####installed python-setuptools###"
	${INSTALL} python-pip  #lets see if this causes issues
	echo "####installed pip###"
	${INSTALL} python3-pip
	echo "####installed pip3###"
	#MAY NEED TO REVERT TO PIP 9.0.3
	#sudo python /usr/lib/python2.7/dist-packages/easy_install.py pip==9.0.3 #easy_install was removed but will work with this command
	#pip install pip==9.0.3 --force-reinstall ###should force install of older package
	${INSTALL} python-dev
	echo "####installed python-dev###"
	${INSTALL} python3-dev
	echo "####installed python3-dev###"
	${INSTALL} python-virtualenv
	echo "####installed python-virtualenv###"
	${INSTALL} python-magic
	echo "####installed python-magic###"
	${INSTALL} python-gridfs
	echo "####installed python-gridfs###"
	${INSTALL} python-libvirt
	echo "####installed python-livirt###"
	${INSTALL} python-bottle
	echo "####installed python-bottle###"
	${INSTALL} python-pefile
	echo "####installed python-pefile###"
	${INSTALL} python-chardet
	echo "####installed python-chardet###"
	${INSTALL} git
	echo "####installed git###"
	${INSTALL} build-essential
	echo "####installed build-essential###"
	${INSTALL} autoconf
	echo "####installed autoconf###"
	${INSTALL} automake
	echo "####installed automake###"
	${INSTALL} aptitude
	echo "####installed aptitude###"
	${INSTALL} python-sqlalchemy
	echo "####installed python-sqlalchemy###"
	${INSTALL} python-bson
	echo "####installed python-bson###"
	${INSTALL} python-dpkt
	echo "####installed python-dpkt###"
	${INSTALL} python-jinja2
	echo "####installed python-jinja2###"
	${INSTALL} libtool
	echo "####installed libtool###"
	${INSTALL} python-pyrex
	echo "####installed python-pyrex###"
	${INSTALL} unzip
	echo "####installed python-unzip###"
	${INSTALL} pgadmin3
	echo "####installed pgadmin3###"
	${INSTALL} python-setuptools-doc
	echo "####installed python-setuptools-doc###"
	${INSTALL} curl
	echo "####installed curl###"
	${SUDO} -H pip install IPython==5.5.0
	${SUDO} -H pip install jupyter
	${SUDO} -H pip install cryptography
	echo "####installed jupyter###"
	echo "####installed cryptograpy###"
	${SUDO} -H pip install --upgrade html5lib beautifulsoup4
	${SUDO} -H pip install --upgrade pip
	echo "####python prep completed###"
	${INSTALL} libxml2-dev
	echo "####installed libxm12-12###"
	${INSTALL} libxslt1-dev
	echo "####installed libxslt-dev###"
	${INSTALL} libjpeg-dev
	echo "####installed libjpeg-dev###"
	${INSTALL} zlib1g-dev
	echo "####installed zlib1g-dev###"
	${INSTALL} swig
	echo "####installed swig###"
	${INSTALL} subversion
	echo "####installed subversion###"
	${INSTALL} pcregrep
	echo "####installed pcregrep###"
	${INSTALL} libpcre++-dev
	echo "####installed libpcre++-dev###"
	${INSTALL} libffi-dev
	echo "####installed libffi-dev###"
	${INSTALL} libssl-dev
	echo "####installed libssl-dev###"
	${INSTALL} libcurl4-gnutls-dev
	echo "####installed libcurl4-gnutls-dev###"
	${INSTALL} libmagic-dev
	echo "####installed libmagic-dev###"
	${INSTALL} libcap2-bin
	echo "####installed libcap2-bin###"
	${INSTALL} libgnome2-bin
	echo "####installed libgnome2-bin###"
	${SUDO} apt install -y net-tools
	echo "####installed net-tools###"
	${INSTALL} debconf-utils
	echo "####installed debconf-utils####"
	${INSTALL} ssdeep
	echo "####installed ssdeep####"
	${INSTALL} p7zip-full p7zip-rar
	echo "####installed 7zip####"
	${INSTALL} gdebi libgtk2-perl-doc
	echo "####installed gdebi####"
	${SUDO} -H pip install ujson
	echo "####installed ujson###"
	${SUDO} -H pip install pycrypto
	echo "####installed pycrypto###"
	${SUDO} -H pip install openpyxl
	echo "####installed openpyxl###"
	${SUDO} ${UPDATE}
	sleep 3
	return 0
	${SUDO} ${UPDATE}
	sleep 3
	return 0
}  &> $LOGS/packages.log

#Install Virtualbox
install_virtualbox(){
	${INSTALL} virtualbox
	echo virtualbox-ext-pack virtualbox-ext-pack/license select true | ${SUDO} debconf-set-selections | ${INSTALL} virtualbox-ext-pack # Virtual Box PUEL https://www.virtualbox.org/wiki/VirtualBox_PUEL
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/vbox.log

#Creates "cuckoo" user and adds the user to vboxusers group
create_cuckoo_user(){
	${SUDO} adduser  --disabled-password -gecos "" cuckoo
  ${SUDO} usermod -G vboxusers cuckoo
	echo "####created cuckoo user###"
	cd $HOME
	${SUDO} ${UPDATE}
	sleep 3
    return 0
} &> $LOGS/users.log

#Installs Mongodb
install_mongodb(){
	cd $HOME
	${SUDO} apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
  echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | ${SUDO} tee /etc/apt/sources.list.d/mongodb-org-3.4.list
	${SUDO} apt-get update
	${INSTALL} mongodb-org
	echo "####installed mongodb###"
	cd $HOME
	${SUDO} mkdir -p /data/db/
	${SUDO} chown `id -u` /data/db
	${SUDO} systemctl status mongodb
	mongo --eval 'db.runCommand({ connectionStatus: 1 })'
	${SUDO} systemctl stop mongodb
	echo '####TO START MONGODB sudo systemctl start mongodb####'
	echo '####ALTERNATE START IS mongod####'
	echo '####TO STOP MONGODB sudo systemctl stop mongodb####'
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/mongodb.log

#Installs PostgreSQL
install_PostgreSQL(){
	${INSTALL} postgresql libpq-dev
	echo "####installed postgresql###"
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/postgresql.log

#Installs TCPdump
install_tcpdump(){
	${INSTALL} tcpdump apparmor-utils
	${SUDO} aa-disable /usr/sbin/tcpdump
	${INSTALL} libcap2-bin
	${SUDO} setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
	getcap /usr/sbin/tcpdump #used to verify results
	echo "####installed tcpdump###"
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/tcpdump.log

#Installs Distorm
install_distrom(){
	cd $HOME
	git clone https://github.com/gdabah/distorm.git
	cd distorm
	${SUDO} python setup.py build
    ${SUDO} python setup.py install
	echo "####installed distorm###"
	cd $HOME
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/distrom.log

#Installs Yara
install_yara(){
	cd $HOME
	${INSTALL} libyara-dev yara-dbg yara-doc python-yara python3-yara
	${INSTALL} automake libtool make gcc
	${INSTALL} gawk
	${INSTALL} libmagic-dev
	${INSTALL} libssl-dev
	${INSTALL} libbsd-dev
	${INSTALL} flex bison
	${INSTALL} zlib1g-dev
	${INSTALL} libbz2-dev
	${INSTALL} libarchive-dev
	${INSTALL} libpcre3-dev
	${INSTALL} uuid-dev
	${INSTALL} python-nose
	${INSTALL} libjansson-dev libjansson-doc libjansson4
	git clone https://github.com/VirusTotal/yara.git
	cd yara/
	./bootstrap.sh
	./configure --enable-cuckoo --enable-magic --enable-dotnet
	make
	${SUDO} make install
	make check
	#${SUDO} -i
	#echo "/usr/local/lib" >> /etc/ld.so.conf
	#exit
	#${SUDO} ldconfig
	${SUDO} echo "/usr/local/lib" >> /etc/ld.so.conf
	${SUDO} ldconfig
	echo "####installed yara###"
  ${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/yara.log

install_inetsim(){
	cd $HOME
	${INSTALL} cpanminus
	${INSTALL} iptables-dev libdigest-sha-perl
	${INSTALL} liblog-log4perl-perl libio-multiplex-perl libipc-shareable-perl libnet-cidr-perl libnet-server-perl iptables-dev libdigest-sha-perl
	${SUDO} cpanm IO::Socket::IP
	${SUDO} cpanm Net::Server
	${SUDO} cpanm Net::DNS
	${SUDO} cpanm Net::DNS::SEC
	${SUDO} cpanm IPC::Shareable
	${SUDO} cpanm Digest::SHA
	${SUDO} cpanm IO::Socket::SSL
	${INSTALL} nfqueue-bindings-perl
	wget https://www.inetsim.org/debian/binary/inetsim_1.2.8-1_all.deb
	${SUDO} dpkg -i /home/sandbox/inetsim_1.2.8-1_all.deb
	${INSTALL} -f
	cd /etc/inetsim
	${SUDO} sed -i 's/#service_bind_address/service_bind_address/' inetsim.conf
	${SUDO} sed -i 's/10.10.10.1/192.168.56.1/' inetsim.conf
	${SUDO} sed -i 's/#dns_bind_port/dns_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#dns_default_ip/dns_default_ip/' inetsim.conf
	${SUDO} sed -i 's/#http_bind_port/http_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#http_version/http_version/' inetsim.conf
	${SUDO} sed -i 's/#https_bind_port/https_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#https_version/https_version/' inetsim.conf
	${SUDO} sed -i 's/#smtp_bind_port/smtp_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#smtps_bind_port/smtps_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#smtps_banner/smtps_banner/' inetsim.conf
	${SUDO} sed -i 's/#pop3_bind_port/pop3_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#pop3_banner/pop3_banner/' inetsim.conf
	${SUDO} sed -i 's/#pop3_mbox_maxmails/pop3_mbox_maxmails/' inetsim.conf
	${SUDO} sed -i 's/#pop3_mbox_rebuild/pop3_mbox_rebuild/' inetsim.conf
	${SUDO} sed -i 's/#pop3_hostname/pop3_hostname/' inetsim.conf
	${SUDO} sed -i 's/#tftp_bind_port/tftp_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#ftp_bind_port/ftp_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#ftp_banner/ftp_banner/' inetsim.conf
	${SUDO} sed -i 's/#ftps_bind_port/ftps_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#ntp_bind_port/ntp_bind_port/' inetsim.conf
	${SUDO} sed -i 's/#ntp_server_ip/ntp_server_ip/' inetsim.conf
	${SUDO} sed -i 's/10.15.20.30/192.168.56.1/' inetsim.conf
	#cd /etc/default
	#${SUDO} sed -i 's/ENABLED=0/ENABLED=1/' inetsim
	${SUDO} ${UPDATE}
	echo "####installed inetsim###"
	echo "####inetsim reports are in /var/log/inetsim/report/###"
	cd $HOME
	# inetsim reports are in /var/log/inetsim/report/

} &> $LOGS/inetsim.log

#Installs MITMProxy
install_mitmproxy(){
	${SUDO} pip3 install mitmproxy
	echo "###mitmproxy cert directory /home/$USER/.mitmproxy###"
	gnome-terminal -- mitmproxy
	echo "###mitmproxy installed###"
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/mitmproxy.log

#Installs TOR
install_tor(){
	${INSTALL} tor
	${SUDO} sed -i '/#SOCKSPort 192.168.0.1:9100 # Bind to this address:port too./{ N; s/.*/#SOCKSPort 192.168.0.1:9100 # Bind to this address:port too.\nTransPort 192.168.56.1:9040\n/; }' /etc/tor/torrc
	${SUDO} sed -i '/TransPort 192.168.56.1:9040/{ N; s/.*/TransPort 192.168.56.1:9040\nDNSPort 192.168.56.1:5353\n/; }' /etc/tor/torrc
	echo "###TOR installed###"
	${SUDO} ${UPDATE}
	sleep 3
	return 0
} &> $LOGS/tor.log

#Inatalls ssdeep
install_ssdeep(){
	wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
	tar xzf ssdeep-2.14.1.tar.gz
	rm *tar.gz
	cd ssdeep-2.14.1
	./configure
	./bootstrap
	make
	${SUDO} make install
}

#Installs Suricata
install_suricata(){
	cd $HOME
	#/etc/suricata/suricata.yaml
	suricata_yaml='/etc/suricata/suricata.yaml'
	${INSTALL} libevent-core-2.0-5 libevent-pthreads-2.0-5 libhiredis0.13 libhtp2 libluajit-5.1-2 ibpcre3 libpcre3-dbg libpcre3-dev \
	libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev \
	libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev python-yaml rustc cargo
	apt-get install libjansson4 libjansson-dev python-simplejson
	${SUDO} add-apt-repository ppa:oisf/suricata-stable -y
	${SUDO} apt-get update -y
	${INSTALL} suricata
	echo 'alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)'  | sudo tee /etc/suricata/rules/cuckoo.rules
	${SUDO} suricata-update
	${SUDO} suricata -T
	${SUDO} suricata-update update-sources
	${SUDO} suricata-update enable-source oisf/trafficid
	${SUDO} suricata-update enable-source et/open
	${SUDO} suricata-update enable-source ptresearch/attackdetection
	${SUDO} suricata-update enable-source tgreen/hunting
	${SUDO} suricata-update enable-source sslbl/ssl-fp-blacklist
	${SUDO} cp ${suricata_yaml} /etc/suricata/suricata.backup
	${SUDO} sed -i 's/#EXTERNAL_NET: "any"/EXTERNAL_NET: "any"/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
  ${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: hold/' ${suricata_yaml}
	${SUDO} sed -i '0,/enabled: no/s//enabled: yes/' ${suricata_yaml}
	${SUDO} sed -i 's/enabled: hold/enabled: no/' ${suricata_yaml}

	${SUDO} ${UPDATE}
	echo "####installed suricata###"
	echo "####suricata config is in /etc/suricata/suricata.yaml###"
} &> $LOGS/suricata.log

#install Java
install_java(){
	cd $HOME
	git clone https://github.com/jhenriquez418/linux-java-jdk-installer.git
	sleep 5
	wget https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz -P /home/sandbox/linux-java-jdk-installer
	cd linux-java-jdk-installer
	chmod +x installJavaJDK.sh
	${SUDO} ./installJavaJDK.sh openjdk-11.0.2_linux-x64_bin.tar.gz 99be79935354f5c0df1ad293620ea36d13f48ec3ea870c838f20c504c9668b57
	${SUDO} ${UPDATE}
	echo "####installed java###"
	echo "####java -v will indicated versions installed###"
} &> $LOGS/java.log

#install ElasticSearch
install_elastic(){
	cd $HOME
	wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.6.7.deb
	wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.6.7.deb.sha512
	echo "a86976e14874244d58f45f31cd95259404a04d33928c33ead3e1d40a082b7186d9dda65bdad7f69544233efddec7c3df40b65fa42413ddf94d64bf5d315f1398 /home/$USER/elasticsearch-5.6.7.deb" | sha512sum -c
	${SUDO} gdebi -n elasticsearch-5.6.7.deb
	${SUDO} cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.backup
	${SUDO} cp /etc/elasticsearch/elasticsearch.yml /home/$USER/Desktop/elasticsearch.backup
	${SUDO} sed -i 's/#cluster.name: my-application/cluster.name: cuckoo-cluster/' /etc/elasticsearch/elasticsearch.yml
	${SUDO} sed -i 's/#node.name: node-1/node.name: cuckoo-node1/' /etc/elasticsearch/elasticsearch.yml
	${SUDO} sed -i 's/#network.host: 192.168.0.1/network.host: 127.0.0.1/' /etc/elasticsearch/elasticsearch.yml
	${SUDO} /bin/systemctl daemon-reload
	${SUDO} update-rc.d elasticsearch defaults 95 10
	${SUDO} systemctl start elasticsearch.service
	${SUDO} ${UPDATE}
	echo "####installed elasticsearch###"
	echo "####elastic config is in /etc/elasticsearch/elasticsearch.yml###"
	echo "####command to start elastic servic is: sudo -i service elasticsearch start###"
	echo "####command to stop elastic servic is: sudo -i service elasticsearch stop###"
} &> $LOGS/elastic.log

install_moloch(){

	wget https://files.molo.ch/builds/ubuntu-16.04/moloch_0.50.1-1_amd64.deb
	sudo gdebi -n moloch_0.50.1-1_amd64.deb
	sudo /data/moloch/bin/Configure <<< $'vboxnet0\nno\n\n\no\n\yes\n'
	/data/moloch/bin/moloch_add_user.sh admin "admin" password --admin
	/data/moloch/db/db.pl http://127.0.0.1:9200 init <<< $'INIT\n'
	sudo systemctl start molochviewer.service
	sudo systemctl start molochcapture.service
} &> $LOGS/moloch.log

#Installs Volatility
install_volatility(){
	cd $HOME
	wget http://downloads.volatilityfoundation.org/releases/2.6/volatility-2.6.zip  #sudo apt install volatility (older version)
	unzip volatility-2.6.zip
	cd volatility-master
	${SUDO} python setup.py build
	${SUDO} python setup.py install
	${INSTALL} volatility
	${SUDO} ${UPDATE}
	echo "####installed volatility###"
	cd $HOME
	sleep 3
	return 0
} &> $LOGS/volatility.log

install_guacamole(){
	#still working to get this to work correctly with cuckoo
	wget https://raw.githubusercontent.com/MysticRyuujin/guac-install/master/guac-install.sh
	chmod +x guac-install.sh
	${SUDO} ./guac-install.sh --mysqlpwd password --guacpwd password
}  > $LOGS/guac.log

# Installs Cuckoo
install_cuckoo(){
	cd $HOME
	${INSTALL} python python-pip python-dev libffi-dev libssl-dev
	${INSTALL} python-virtualenv python-setuptools
	${INSTALL} libjpeg-dev zlib1g-dev swig
	${INSTALL} postgresql libpq-dev
	${INSTALL} swig
	${SUDO} -H pip install m2crypto==0.24.0
	${SUDO} -H pip install -U pip setuptools
  ${SUDO} -H pip install -U cuckoo --ignore-installed
	cuckoo -d
	${SUDO} ${UPDATE}
	cd $HOME
	sleep 3
	return 0
	echo "####installed cuckoo###"
} &> $LOGS/cuckoo.log

#Installs ClamAV
install_ClamAV(){
	cd $HOME
	${INSTALL} clamav
	git clone https://github.com/kojibhy/cuckoo-yara-auto.git && cd cuckoo-yara-auto
	wget http://database.clamav.net/main.cvd
	sudo sigtool -u main.cvd
	python clamav_to_yara.py -f main.ndb -o /home/$USER/.cuckoo/yara/calmav.yara
	ython3 -m pip install -r requirements.txt
	python3 yara-rules.py -d /home/$USER/.cuckoo/yara
	sleep 3
	return 0
} &> $LOGS/ClamAV.log

# Sets routing tables and then makes them permanent. Enables communication with Cuckoo and guest vm.
create_hostonly_iface(){
	vboxmanage hostonlyif create
	vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0  #if routing is not working eth0 many not be the primary interface.
  ${SUDO} iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.56.0/24 -j MASQUERADE #eth0
	${SUDO} iptables -P FORWARD DROP
  ${SUDO} iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	${SUDO} iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	${SUDO} iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
  ${SUDO} iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ${SUDO} iptables -A FORWARD -j LOG
	#sudo bash -c echo 1 > sudo tee -a /proc/sys/net/ipv4/ip_forward
	#sudo sysctl -w net.ipv4.ip_forward=1
	echo iptables-persistent iptables-persistent/autosave_v4 boolean true | ${SUDO} debconf-set-selections
	echo iptables-persistent iptables-persistent/autosave_v6 boolean true | ${SUDO} debconf-set-selections
	${SUDO} debconf-get-selections | grep iptables
	${SUDO} apt-get -y install iptables-persistent
	clear
	${SUDO} ${UPDATE}
	echo "####iptables information http://www.microhowto.info/howto/make_the_configuration_of_iptables_persistent_on_debian.html####"
	echo "####installed iptables-persistent###"

} &> $LOGS/iptables.log

# Downloads a WIN7 ISO and python to run the Cuckoo agent.
create_vm(){
	mkdir $HOME/VM
	mkdir $HOME/VM/vmshare
	cd $HOME/VM
	wget https://az792536.vo.msecnd.net/vms/VMBuild_20180102/VirtualBox/IE11/IE11.Win7.VirtualBox.zip -P $HOME/VM  #This could be made a variable
	#cp '/media/sf_vmshare/IE11 - Win7.zip' '/home/sandbox/VM/IE11 - Win7.zip' #For Testing
  wget https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi -P /$vmshare
	python_download="python-2.7.14.msi"
	wget https://bootstrap.pypa.io/get-pip.py -P /$vmshare
	cd $HOME/VM
	unzip *.zip
	#rm *.zip
	vboxmanage import *.ova --dry-run
	#vboxmanage import "Win7.ova" --dry-run #For testing
	vboxmanage import *.ova
	#vboxmanage import "Win7.ova" #For testing
	vboxmanage modifyvm "IE11 - Win7" --name $vmname --memory 2048
	#vboxmanage modifyvm "WIN7_PRO" --name $vmname --memory 2048 #For testing
	vboxmanage startvm $vmname --type headless
	vboxmanage controlvm $vmname clipboard bidirectional
	vboxmanage controlvm $vmname draganddrop hosttoguest
	vboxmanage controlvm $vmname poweroff
	sleep 3
	vboxmanage modifyvm $vmname --vrde on
	vboxmanage modifyvm $vmname --vrdeport 5000-5050
	vboxmanage setproperty vrdeauthlibrary "VBoxAuthSimple"
	vboxmanage modifyvm $vmname --vrdeauthtype external
	vboxmanage setextradata $vmname "VBoxAuthSimple/users/$vmuser" $vboxpass
	vboxmanage modifyvm $vmname --vrdemulticon on
	vboxmanage sharedfolder add $vmname --name vm_share --hostpath $vmshare --automount
	cp /home/$USER/.cuckoo/agent/agent.py /home/$USER/VM/vmshare/agent.pyw  #.pyw extension does not bring up a terminal while running. Change to a .py extension if you would like the terminal to display
	cp /home/$USER/.mitmproxy/mitmproxy-ca-cert.p12 /home/$USER/.cuckoo/analyzer/windows/bin/cert.p12

	###This creates a batch file to quickly set up the guest host###
		{
			printf '@echo off\r\n' > /$vmshare/configuration.bat
			printf 'color 0a\r\n' >> /$vmshare/configuration.bat
			printf 'echo install the following programs > %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo install Adobe PDF Reader "https://get.adobe.com/reader/" >> %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo install Adobe Flash Player "https://get.adobe.com/flashplayer/" >> %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo install Java "https://java.com/en/download/" >> %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo install Microsoft Office if you have a license or Libreoffice >> %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo install other browsers such as FireFox and Chrome >> %%USERPROFILE%%\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo Install additional programs. Refer to Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'echo Press enter when you have installed additional programs\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Disabling Windows Defender \r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'sc stop WinDefend\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Disabling Firewall\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'NetSh Advfirewall set allprofiles state off\r\n' >> /$vmshare/configuration.bat
			printf 'netsh interface teredo set state disabled\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Disabling Windows Updates..\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f\r\n' >> /$vmshare/configuration.bat
			printf 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Installing Python. Confirm Python.msi is on the Desktop? \r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cd %%USERPROFILE%%\Desktop\r\n' >> /$vmshare/configuration.bat
			printf "msiexec /i ${python_download} ALLUSERS=1 /qn\r\n" >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Installing Pip.\r\n' >> /$vmshare/configuration.bat
			printf 'cd C:\Python27\r\n' >> /$vmshare/configuration.bat
			printf 'python %%USERPROFILE%%\Desktop\get-pip.py\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Installing Pillow...\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cd C:\Python27\Scripts\r\n' >> /$vmshare/configuration.bat
			printf 'pip install Pillow\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Editing the registry\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\/xplorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f\r\n' >> /$vmshare/configuration.bat
			printf 'reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\/xplorer\Advanced /v Hidden /t REG_DWORD /d 1 /f\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Placing Cuckoo Agent in Startup Folder\r\n' >> /$vmshare/configuration.bat
			printf 'cd %%USERPROFILE%%\Desktop\r\n' >> /$vmshare/configuration.bat
			printf 'COPY /V /Y agent.pyw "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"\r\n' >> /$vmshare/configuration.bat
			printf 'echo Additional_Downloads on the Desktop is a list of additional programs to install\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Setting the IP\r\n' >> /$vmshare/configuration.bat
			printf 'netsh interface ip set address name="Local Area Connection" static 192.168.56.101 255.255.255.0 192.168.56.1\r\n' >> /$vmshare/configuration.bat
			printf 'netsh interface ip set dns "Local Area Connection" static 192.168.56.1\r\n' >> /$vmshare/configuration.bat #GUEST DNS
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'set PATH=%%PATH%%;C:\Python27;C:\Python27\Scipts\r\n' >> /$vmshare/configuration.bat
			printf 'echo removing files \r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'DEL /Q %%USERPROFILE%%\Desktop\python-2.7.14.msi\r\n' >> /$vmshare/configuration.bat
			printf 'DEL /Q %%USERPROFILE%%\Desktop\get-pip.py\r\n' >> /$vmshare/configuration.bat
			printf 'DEL /Q %%USERPROFILE%%\Desktop\\agent.pyw\r\n' >> /$vmshare/configuration.bat
			printf 'DEL /Q %%USERPROFILE%%\Desktop\\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Have you installed all the additional programs?\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'echo Windows is now set up!\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'cls\r\n' >> /$vmshare/configuration.bat
			printf 'echo Press enter to restart the VM\r\n' >> /$vmshare/configuration.bat
			printf 'echo Wait until the VM has restarted to continue with the Scipt\r\n' >> /$vmshare/configuration.bat
			printf 'echo Continue with the Installation Script\r\n' >> /$vmshare/configuration.bat
			printf 'pause \r\n' >> /$vmshare/configuration.bat
			printf 'shutdown /r /t 10' >> /$vmshare/configuration.bat
		cd $vmshare
		sed -i '0,/\/xplorer/s//Explorer/' configuration.bat
		sed -i '0,/\/xplorer/s//Explorer/' configuration.bat
		}

	} &> $LOGS/vmcomponents.log

# Configures Cuckoo .conf files
set_config(){
	cd $CONFIG
	cp cuckoo.conf cuckoo.backup
	cp auxiliary.conf auxiliary.backup
	cp processing.conf processing.backup
	cp reporting.conf reporting.backup
	cp memory.conf memory.backup
	cp routing.config routing.backup
	cp virtualbox.conf virtualbox.backup
	${SUDO} sed -i 's/memory_dump = no/memory_dump = yes/' cuckoo.conf
	# Enable for remote control of analysis machines inside the web interface.
	${SUDO} sed -i '/# Enable for remote control of analysis machines inside the web interface./{ N; s/.*/\# Enable for remote control of analysis machines inside the web interface.\nenabled = yes/; }' cuckoo.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = yes/' auxiliary.conf #enables mitmproxy
	{
	${SUDO} sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = yes/' processing.conf
  ${SUDO} sed -i 's/enabled = hold/enabled = no/' processing.conf
	${SUDO} sed -i '/\[suricata\]/{ N; s/.*/\[suricata\]\nenabled = yes/; }' processing.conf
	}
	{
	${SUDO} sed -i '/\[mongodb\]/{ N; s/.*/\[mongodb\]\nenabled = yes/; }' reporting.conf
	${SUDO} sed -i '/\[elasticsearch\]/{ N; s/.*/\[elasticsearch\]\nenabled = yes/; }' reporting.conf
	}
	{
	${SUDO} sed -i 's/guest_profile = WinXPSP2x86/guest_profile = Win7SP1x86/' memory.conf
	}
	{
	${SUDO} sed -i 's/internet = none/internet = enp0s3/' routing.conf
	${SUDO} sed -i '0,/drop = no/s//drop = yes/' routing.conf
	${SUDO} sed -i '0,/enabled = no/s//enabled = yes/' routing.conf
	sed -i '/# documentation)./{ N; s/.*/# documentation).\nenabled = yes/; }' routing.conf
	}
	{
	#Specific configurations for the Virtual Machine information
	#sed -i 's/headless/gui/' virtualbox.conf  #uncomment if you want a GUI analysis machine
	sed -i "0,/label = cuckoo1/s//label = $vmname/" virtualbox.conf #Label should be the VM Name
	sed -i '0,/snapshot =/s//snapshot = Cuckoo_Snapshot/' virtualbox.conf
	}
	{
	printf 'Creating Cuckoo Help File\n'
	cuckoo --help > $HOME/Desktop/Cuckoo_Help.txt
	}
	${SUDO} ${UPDATE}
} &> $LOGS/cuckooconf.log

# Configures the guest vm to perform analysis.
configure_vm(){
	vboxmanage startvm $vmname --type gui
	read -p "Press [Enter] when you have completed all of the steps..."
  vboxmanage controlvm $vmname poweroff
	sleep 5
	vboxmanage modifyvm $vmname --nic1 hostonly
	sleep 5
	vboxmanage modifyvm $vmname --hostonlyadapter1 vboxnet0
	sleep 15
	clear
	vboxmanage startvm $vmname --type gui
	sleep 15
	read -p "Press [Enter] when the VM is fully booted up..."
	sleep 10
	vboxmanage snapshot $vmname take Cuckoo_Snapshot --pause
	sleep 5
	vboxmanage snapshot $vmname showvminfo Cuckoo_Snapshot
	sleep 5
	vboxmanage controlvm $vmname poweroff
	#${SUDO} ${UPDATE}
} > $LOGS/snapshot.log

# Creates a start-up script for launching Cuckoo
cuckoo_start(){
	printf 'Cuckoo Start-up Script location is /home/$USER/\n'
	sleep 10
	cd /home/$USER
	printf '#!/bin/bash\n' > /home/$USER/start_cuckoo.bash
	printf 'vmname=WIN7\n' >> /home/$USER/start_cuckoo.bash #change $vname if you change the variable
	#printf 'sudo rm /var/lib/mongodb/mongod.lock\n' >> /home/$USER/start_cuckoo.bash
	printf 'sudo service mongod start\n' >> /home/$USER/start_cuckoo.bash
	printf 'sudo service elasticsearch start\n'  >> /home/$USER/start_cuckoo.bash
	printf 'sudo service guacd start\n' >> /home/$USER/start_cuckoo.bash
	printf 'vboxmanage startvm $vmname --type headless\n' >> /home/$USER/start_cuckoo.bash #change --type to gui if you want a gui
	printf 'cuckoo community\n' >> /home/$USER/start_cuckoo.bash
	printf "printf 'starting mitmproxy in new terminal\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'gnome-terminal -- mitmproxy\n' >> /home/$USER/start_cuckoo.bash
  printf "printf 'starting inetsim in new terminal\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 10\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-terminal -- sudo inetsim\n' >> /home/$USER/start_cuckoo.bash
  printf "printf 'starting cuckoo rooter in new terminal\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 10\n' >> /home/$USER/start_cuckoo.bash
	printf "gnome-terminal -- sudo cuckoo rooter -g $USER\n" >> /home/$USER/start_cuckoo.bash
	printf "printf 'starting cuckoo in new terminal\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 10\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-terminal -- cuckoo\n' >> /home/$USER/start_cuckoo.bash
  printf "printf 'starting cuckoo webserver in new terminal\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 3\n' >> /home/$USER/start_cuckoo.bash
	printf "gnome-terminal -- cuckoo web runserver\n" >> /home/$USER/start_cuckoo.bash
	printf "printf 'Opening cuckoo analysis webpage, HAPPY HUNTING!!!\n'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 3\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-open http://127.0.0.1:8000/\n' >> /home/$USER/start_cuckoo.bash
	chmod +x start_cuckoo.bash
} &> $LOGS/cuckoo_startup.log

cuckoo_kill(){
	printf 'Cuckoo kill Script location is /home/$USER/\n'
	sleep 10
	cd /home/$USER
	printf '#!/bin/bash\n' > /home/$USER/kill_cuckoo.bash
	printf 'vmname=WIN7\n' >> /home/$USER/kill_cuckoo.bash
	printf 'read -p "Press [Enter] key to Kill Cuckoo or [Ctrl + C] to exit..."\n' >> kill_cuckoo.bash
	printf "sudo runuser -l cuckoo -c 'cuckoo api --host 0.0.0.0 --port 8090' &\n" >> kill_cuckoo.bash
	printf "sudo pkill -f \'cuckoo web runserver\'\n" >> kill_cuckoo.bash
	printf 'sudo killall cuckoo\n' >> kill_cuckoo.bash
	printf 'vboxmanage controlvm $vmname poweroff\n' >> kill_cuckoo.bash
	printf 'sudo service mongod stop\n' >> kill_cuckoo.bash
	printf 'sudo service elasticsearch stop\n' >> kill_cuckoo.bash
	printf 'sudo service guacd stop\n' >> kill_cuckoo.bash
	chmod +x kill_cuckoo.bash
} &> $LOGS/cuckoo_kill.log


# Cleanse up the Cuckoo Install folder
clean_up(){
	cd $HOME
	${SUDO} rm -rf *.tar.gz
	${SUDO} rm -rf *.zip
	${SUDO} rm -rf *.deb
	sudo apt autoremove -y
	cuckoo community
	${SUDO} ${UPDATE}
	sleep 3
} &> $LOGS/cleanup.log

the_distance(){
	sleep 10
	clear
}

pretty_begin(){
	printf ${NOK}"System Check"${NL}
	printf ${NOK}"Update System"${NL}
	printf ${NOK}"Install Packages"${NL}
	printf ${NOK}"Install Virtualbox"${NL}
	printf ${NOK}"Create Cuckoo User"${NL}
	printf ${NOK}"Install Mongodb"${NL}
	printf ${NOK}"Install Prostgresql"${NL}
	printf ${NOK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
	}

pretty_check(){
	#SYSTEMCHECK
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${NOK}"Update System"${NL}
	printf ${NOK}"Install Packages"${NL}
	printf ${NOK}"Install Virtualbox"${NL}
	printf ${NOK}"Create Cuckoo User"${NL}
	printf ${NOK}"Install Mongodb"${NL}
	printf ${NOK}"Install Prostgresql"${NL}
	printf ${NOK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_update(){
	#UPDATE
  printf ${NL}
  printf ${OK}"System Check"${NL}
  printf ${OK}"Update System"${NL}
  printf ${NOK}"Install Packages"${NL}
  printf ${NOK}"Install Virtualbox"${NL}
  printf ${NOK}"Create Cuckoo User"${NL}
  printf ${NOK}"Install Mongodb"${NL}
  printf ${NOK}"Install Prostgresql"${NL}
  printf ${NOK}"Install TCPdump"${NL}
  printf ${NOK}"Install Distrom"${NL}
  printf ${NOK}"Install Yara"${NL}
  printf ${NOK}"Install Inetsim"${NL}
  printf ${NOK}"Install Mitmproxy"${NL}
  printf ${NOK}"Install Tor"${NL}
  printf ${NOK}"Install SSdeep"${NL}
  printf ${NOK}"Install Suricata"${NL}
  printf ${NOK}"Install Java"${NL}
  printf ${NOK}"Install ElasticSearch"${NL}
  printf ${NOK}"Install Volatility"${NL}
  printf ${NOK}"Install Gaucamole"${NL}
  printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
  printf ${NOK}"Configure IP tables"${NL}
  printf ${NOK}"Create VM"${NL}
  printf ${NOK}"Set Configuration Files"${NL}
  printf ${NOK}"Configure VM"${NL}
  printf ${NOK}"Create Cuckoo Start-up Script"${NL}
  printf ${NOK}"Create Cuckoo Kill Script"${NL}
  printf ${NL}
}

pretty_packages(){
	#PACKAGES
  printf ${NL}
  printf ${OK}"System Check"${NL}
  printf ${OK}"Update System"${NL}
  printf ${OK}"Install Packages"${NL}
  printf ${NOK}"Install Virtualbox"${NL}
  printf ${NOK}"Create Cuckoo User"${NL}
  printf ${NOK}"Install Mongodb"${NL}
  printf ${NOK}"Install Prostgresql"${NL}
  printf ${NOK}"Install TCPdump"${NL}
  printf ${NOK}"Install Distrom"${NL}
  printf ${NOK}"Install Yara"${NL}
  printf ${NOK}"Install Inetsim"${NL}
  printf ${NOK}"Install Mitmproxy"${NL}
  printf ${NOK}"Install Tor"${NL}
  printf ${NOK}"Install SSdeep"${NL}
  printf ${NOK}"Install Suricata"${NL}
  printf ${NOK}"Install Java"${NL}
  printf ${NOK}"Install ElasticSearch"${NL}
  printf ${NOK}"Install Volatility"${NL}
  printf ${NOK}"Install Gaucamole"${NL}
  printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
  printf ${NOK}"Configure IP tables"${NL}
  printf ${NOK}"Create VM"${NL}
  printf ${NOK}"Set Configuration Files"${NL}
  printf ${NOK}"Configure VM"${NL}
  printf ${NOK}"Create Cuckoo Start-up Script"${NL}
  printf ${NOK}"Create Cuckoo Kill Script"${NL}
  printf ${NL}
}

pretty_virtualbox(){
	#VIRTUALBOX
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${NOK}"Create Cuckoo User"${NL}
	printf ${NOK}"Install Mongodb"${NL}
	printf ${NOK}"Install Prostgresql"${NL}
	printf ${NOK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_user(){
	#CUCKOO USER
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${NOK}"Install Mongodb"${NL}
	printf ${NOK}"Install Prostgresql"${NL}
	printf ${NOK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_mongodb(){
	#MONGODB
  printf ${NL}
  printf ${OK}"System Check"${NL}
  printf ${OK}"Update System"${NL}
  printf ${OK}"Install Packages"${NL}
  printf ${OK}"Install Virtualbox"${NL}
  printf ${OK}"Create Cuckoo User"${NL}
  printf ${OK}"Install Mongodb"${NL}
  printf ${NOK}"Install Prostgresql"${NL}
  printf ${NOK}"Install TCPdump"${NL}
  printf ${NOK}"Install Distrom"${NL}
  printf ${NOK}"Install Yara"${NL}
  printf ${NOK}"Install Inetsim"${NL}
  printf ${NOK}"Install Mitmproxy"${NL}
  printf ${NOK}"Install Tor"${NL}
  printf ${NOK}"Install SSdeep"${NL}
  printf ${NOK}"Install Suricata"${NL}
  printf ${NOK}"Install Java"${NL}
  printf ${NOK}"Install ElasticSearch"${NL}
  printf ${NOK}"Install Volatility"${NL}
  printf ${NOK}"Install Gaucamole"${NL}
  printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
  printf ${NOK}"Configure IP tables"${NL}
  printf ${NOK}"Create VM"${NL}
  printf ${NOK}"Set Configuration Files"${NL}
  printf ${NOK}"Configure VM"${NL}
  printf ${NOK}"Create Cuckoo Start-up Script"${NL}
  printf ${NOK}"Create Cuckoo Kill Script"${NL}
  printf ${NL}
}

pretty_postgresql(){
	#POSTGRESQL
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${NOK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_tcpdump(){
	#TCPDUMP
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${NOK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_distrom(){
	#DISTROM
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${NOK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_yara(){
	#YARA
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${NOK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_inetsim(){
	#INETSIM
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${NOK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_mitmproxy(){
	#MITMPROXY
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${NOK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_tor(){
	#TOR
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${NOK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_ssdeep(){
	#ssdeep
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${NOK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_suricata(){
	#SURICATA
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${NOK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_java(){
	#JAVA
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${NOK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_elastic(){
	#ELASTICSEARCH
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${NOK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_volatility(){
	#VOLATILITY
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${NOK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_guac(){
	#GAUCAMOLE
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${NOK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_cuckoo(){
	#CUCKOO
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${NOK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_ClamAV(){
	#CLAMAV
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${NOK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_iptables(){
	#IPTABLES
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${NOK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_create(){
	#CREATE VM
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${OK}"Create VM"${NL}
	printf ${NOK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_config(){
	#CONFIG
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${OK}"Create VM"${NL}
	printf ${OK}"Set Configuration Files"${NL}
	printf ${NOK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_vm(){
	#CONFIG VM
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${OK}"Create VM"${NL}
	printf ${OK}"Set Configuration Files"${NL}
	printf ${OK}"Configure VM"${NL}
	printf ${NOK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_start(){
	#START SCRIPT
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${OK}"Create VM"${NL}
	printf ${OK}"Set Configuration Files"${NL}
	printf ${OK}"Configure VM"${NL}
	printf ${OK}"Create Cuckoo Start-up Script"${NL}
	printf ${NOK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

pretty_kill(){
	#KILL SCRIPT
	printf ${NL}
	printf ${OK}"System Check"${NL}
	printf ${OK}"Update System"${NL}
	printf ${OK}"Install Packages"${NL}
	printf ${OK}"Install Virtualbox"${NL}
	printf ${OK}"Create Cuckoo User"${NL}
	printf ${OK}"Install Mongodb"${NL}
	printf ${OK}"Install Prostgresql"${NL}
	printf ${OK}"Install TCPdump"${NL}
	printf ${OK}"Install Distrom"${NL}
	printf ${OK}"Install Yara"${NL}
	printf ${OK}"Install Inetsim"${NL}
	printf ${OK}"Install Mitmproxy"${NL}
	printf ${OK}"Install Tor"${NL}
	printf ${OK}"Install SSdeep"${NL}
	printf ${OK}"Install Suricata"${NL}
	printf ${OK}"Install Java"${NL}
	printf ${OK}"Install ElasticSearch"${NL}
	printf ${OK}"Install Volatility"${NL}
	printf ${OK}"Install Gaucamole"${NL}
	printf ${OK}"Install Cuckoo"${NL}
	printf ${OK}"Install ClamAV"${NL}
	printf ${OK}"Configure IP tables"${NL}
	printf ${OK}"Create VM"${NL}
	printf ${OK}"Set Configuration Files"${NL}
	printf ${OK}"Configure VM"${NL}
	printf ${OK}"Create Cuckoo Start-up Script"${NL}
	printf ${OK}"Create Cuckoo Kill Script"${NL}
	printf ${NL}
}

the_loop(){
  while [[ "$REPLY" != "yes" ]]
do
  clear
  getting_started
  read -p 'Is this correct (yes/no)? ' REPLY
done
}

install_moloch(){
	#still working to get this to work with cuckoo
	wget https://files.molo.ch/builds/ubuntu-16.04/moloch_0.50.1-1_amd64.deb
	sudo gdebi -n moloch_0.50.1-1_amd64.deb
	sudo /data/moloch/bin/Configure <<< $'vboxnet0\nno\n\n\no\n\yes\n'
	/data/moloch/bin/moloch_add_user.sh admin "admin" password --admin
	/data/moloch/db/db.pl http://127.0.0.1:9200 init
	sudo systemctl start molochcapture.service
	sudo systemctl start molochviewer.service
}


getting_started(){
clear
printf "We will start with a few questions to customize the installation"
sleep 3
#printf "If you do not already have a VM built to import in to Virtualbox and would like to download one"${NL}
#printf "Copy the link address from Microsofts virtual machines"${NL}
#gnome-open https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
#gnome-open https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#sele$
#read -p "Paste link for VM to download during install process: "  vmlink
clear
read -p "Enter the name of your analysis machine i.e. WIN7 or WIN10: "  vmname
clear
read -p "Enter VM username: " vmuser
clear
read -s -p "Enter VM password: " vmpass
clear
vboxpass=$(echo -n $vmpass | sha256sum | awk '{print $1}')
#gnome-open https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#sele$
#read -p "Enter the Volatility OS profile of your analysis VM: "  GUEST ${NL}
clear

printf "You selected the following for your analysis VM: "${NL}
printf ${vmname}${NL}${NL}
printf ${vmuser}${NL}${NL}
printf ${vmpass}${NL}${NL}
}


# Init.
print_copy
sleep 3
printf "\033[1;32mThe install will take approximatly 30+ minutes to complete!\e[0m\n"
printf "\033[1;32mConsider setting a longer timeout period for sudo by editing visudo\e[0m\n"
printf "\033[1;93mUser Input is Required to configure the VM for Cuckoo, however you can just hit enter and complete the configuration later\e[0m\n"
printf "\033[1;93mInstallation output is saved to /home/$USER/CuckooInstall_LOGS\e[0m\n"
read -p "Press [Enter] key to start install or [Ctrl + C] to exit..."
clear

the_loop
clear
pretty_begin
the_distance

printf "Checking System for Install...\n"
check_viability
pretty_check
the_distance

printf "Updating the System...\n"
perform_update
pretty_update
the_distance

printf "Installing packages for build...\n"
install_packages
pretty_packages
the_distance

printf "Installing VirtualBox...\n"
install_virtualbox
pretty_virtualbox
the_distance

printf "Creating User "cuckoo"...\n"
create_cuckoo_user
pretty_user
the_distance

printf "Installing Mongodb...\n"
install_mongodb
pretty_mongodb
the_distance

printf "Installing PostgreSQL...\n"
install_PostgreSQL
pretty_postgresql
the_distance

printf "Installing TCPdump...\n"
install_tcpdump
pretty_tcpdump
the_distance

printf "Installing Distrom...\n"
install_distrom
pretty_distrom
the_distance

printf "Installing Yara...\n"
install_yara
pretty_yara
the_distance

printf "Installing Inetsim...\n"
install_inetsim
pretty_inetsim
the_distance

printf "Installing Mitmproxy...\n"
install_mitmproxy
pretty_mitmproxy
the_distance

printf "Installing TOR...\n"
install_tor
pretty_tor
the_distance

printf "Installing SSDeep...\n"
install_ssdeep
pretty_ssdeep
the_distance

printf "Installing Suricata...\n"
install_suricata
pretty_suricata
the_distance

printf "Installing Java...\n"
install_java
pretty_java
the_distance

printf "Installing ElasticSearch...\n"
install_elastic
pretty_elastic
the_distance

printf "Installing Volatility...\n"
install_volatility
pretty_volatility
the_distance

printf "Installing Gaucamole...\n"
#install_guacamole
pretty_guac
the_distance

printf "Installing Cuckoo...\n"
install_cuckoo
pretty_cuckoo
the_distance

printf "Installing ClamAV...\n"
install_ClamAV
pretty_ClamAV
the_distance

printf "Configuring Cuckoo IP Tables...\n"
create_hostonly_iface
pretty_iptables
the_distance

printf "Downloading VM Components\n"
create_vm
pretty_create
the_distance

printf "Configuring Cuckoo\n"
set_config
pretty_config
the_distance

printf "Now to configure the VM...\n"
sleep 3
printf ${NL}
printf ${NL}
printf "\033[1;32m
Follow the steps below to configure the $vmname VM for Cuckoo
1. Copy the all the files located at /$vmshare/ to the desktop of the VM. Network Share should be loaded.
2. Install additional programs before the restart. Refer to the Additional_Downloads.txt on the desktop.
3. Execute the configuration.bat as an administrator This will restart the VM at the end of the script.
\e[0m\n"
sleep 10
configure_vm
printf 'A snapshot "Cuckoo_Snapshot" will be completed once the VM is configured\n'
printf 'Taking the snapshot will shutdown the VM\n'
sleep 10
pretty_vm
the_distance

printf "Creating Cuckoo Startup Script...\n"
cuckoo_start
printf "Script location is /home/$USER/\n"
pretty_start
the_distance

printf "Creating Cuckoo Kill Script...\n"
cuckoo_kill
printf 'Script location is /home/$USER/\n'
pretty_kill
the_distance

clean_up

printf 'Refer to the Documentation for instructions on running Cuckoo\n'
sleep 3
printf 'The Script is complete\n'
printf 'Restarting the Computer\n'
install_moloch
printf 'Check Moloch installation\n'
read -p 'Press [Enter] when you have completed all of the steps...'
sleep 120
shutdown -r now
