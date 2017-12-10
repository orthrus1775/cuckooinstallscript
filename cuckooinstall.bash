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

# Configuration variables. You can override these in config.

source /etc/os-release

# Configuration variables. You can override these in config.
SUDO="sudo"
HOME=/home/$USER
DOWNLOAD=/home/$USER/CuckooInstall
LOGS=/home/$USER/CuckooInstall/LOGS
INSTALL=/home/$USER/CuckooInstall/Cuckoo
CWD=/home/$USER/.cuckoo
CONFIG=/home/$USER/.cuckoo/conf
vmshare=/home/$USER/CuckooInstall/VM/vmshare
GUEST="guest_profile = Win7SP1x86"  #Change the guest OS profile for Volatility after the second "=". Refernce: https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#selecting-a-profile
vmname=WIN7 #search for WIN7 to change it in areas where the variable does not work.

# Pretty icons
log_icon="\e[31m✓\e[0m"
log_icon_ok="\e[32m✓\e[0m"
log_icon_nok="\e[31m✗\e[0m"
#\033[0;92m✓\e[0m

print_copy(){
printf "\033[1;32m
┌────────────────────────────────────────────────────────────┐
│############################################################│
│####################Installation Script ####################│
│####################         For        ####################│
│####################  Cuckoo Sandbox    ####################│
│############################################################│
└────────────────────────────────────────────────────────────┘
\e[0m\n"
sleep 5
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
	cd /home/$USER
	mkdir CuckooInstall
	cd $DOWNLOAD
	wget http://download.virtualbox.org/virtualbox/5.2.0/UserManual.pdf -P /home/$USER/CuckooInstall
	mkdir LOGS
	cd $HOME
	sleep 3
	}
} &> /dev/null

#Updates and Upgrades the system
perform_update(){
	sudo apt-get update -y 
	echo "####update completed###"
	sudo apt-get upgrade -y
	sudo apt-get upgrade -y --fix-missing
	echo "###upgrade completed###"
	sleep 3
	return 0 
} > $LOGS/update.txt

#Installs Packages Packages installed individually to locate issues
prepare_python(){
	sudo apt-get install -y python-pip
	echo "####installed pip###"
	sudo apt-get install -y python3-pip
	echo "####installed python-pip###"
	sudo apt-get install -y python-setuptools
	echo "####installed python-setuptools###"
	sudo apt-get install -y python-dev
	echo "####installed python-dev###"
	sudo apt-get install -y python-virtualenv
	echo "####installed python-virtualenv###"
	sudo apt-get install -y python-magic
	echo "####installed python-magic###"
	sudo apt-get install -y python-gridfs
	echo "####installed python-gridfs###"
	sudo apt-get install -y python-libvirt
	echo "####installed python-livirt###"
	sudo apt-get install -y python-bottle
	echo "####installed python-bottle###"
	sudo apt-get install -y python-pefile
	echo "####installed python-pefile###"
	sudo apt-get install -y python-chardet
	echo "####installed python-chardet###"
	sudo apt-get install -y git
	echo "####installed git###"
	sudo apt-get install -y build-essential
	echo "####installed build-essential###"
	sudo apt-get install -y autoconf
	echo "####installed autoconf###"
	sudo apt-get install -y automake
	echo "####installed automake###"
	sudo apt-get install -y aptitude
	echo "####installed aptitude###"
	sudo apt-get install -y python-sqlalchemy
	echo "####installed python-sqlalchemy###"
	sudo apt-get install -y python-bson
	echo "####installed python-bson###"
	sudo apt-get install -y python-dpkt
	echo "####installed python-dpkt###"
	sudo apt-get install -y python-jinja2
	echo "####installed python-jinja2###"
	sudo apt-get install -y libtool
	echo "####installed libtool###"
	sudo apt-get install -y dkms 
	echo "####installed dkms###"
	sudo apt-get install -y python-pyrex
	echo "####installed python-pyrex###"
	sudo apt-get install -y unzip 
	echo "####installed python-unzip###"
	sudo apt-get install -y pgadmin3
	echo "####installed pgadmin3###"
	sudo apt-get install -y python-setuptools-doc
	echo "####installed python-setuptools-doc###"
	pip install IPython==5.5.0
	#wget https://pypi.python.org/packages/14/7c/bbc1e749e1739208324af3f05ac7256985e21fc5f24d3c8da20aae844ad0/ipython-5.5.0.tar.gz#md5=61f627b9365f630887beb30a002f76fd -P /home/$USER/CuckooInstall
	#cd $DOWNLOAD
	#tar -xzf ipython-5.5.0.tar.gz
	#cd ipython-5.5.0
	#sudo python setup.py build
	#sudo python setup.py install
	#cd $DOWNLOAD
	#rm ipython-5.5.0.tar.gz
	#cd $HOME
	sudo -H pip install jupyter cryptography
	sudo -H pip install --upgrade html5lib beautifulsoup4
	pip install --upgrade pip
	sleep 3
	return 0
} > $LOGS/prepare_python.txt

#Installs Librarires Libraries installed individually to locate issues
install_lib(){
	sudo apt-get install -y libxml2-dev 
	echo "####installed libxm12-12###"  
	sudo apt-get install -y libxslt1-dev 
	echo "####installed libxslt-dev###"
	sudo apt-get install -y libjpeg-dev
	echo "####installed libjpeg-dev###"
	sudo apt-get install -y zlib1g-dev
	echo "####installed zlib1g-dev###"
	sudo apt-get install -y swig
	echo "####installed swig###"
	sudo apt-get install -y subversion
	echo "####installed subversion###"
	sudo apt-get install -y pcregrep 
	echo "####installed pcregrep###"
	sudo apt-get install -y libpcre++-dev
	echo "####installed libpcre++-dev###"
	sudo apt-get install -y libffi-dev
	echo "####installed libffi-dev###"
	sudo apt-get install -y libssl-dev
	echo "####installed libssl-dev###"
	sudo apt-get install -y libcurl4-gnutls-dev
	echo "####installed libcurl4-gnutls-dev###"
	sudo apt-get install -y libmagic-dev
	echo "####installed libmagic-dev###"
	sudo apt-get install -y libcap2-bin
	echo "####installed libcap2-bin###"
	sudo apt-get install -y libgnome2-bin
	echo "####installed libgnome2-bin###"
	sleep 3
	return 0
} > $LOGS/lib.txt

#Install Virtualbox
install_virtualbox(){
	sudo apt-get install -y virtualbox
	echo virtualbox-ext-pack virtualbox-ext-pack/license select true | sudo debconf-set-selections | sudo apt-get install -y virtualbox-ext-pack # Virtual Box PUEL https://www.virtualbox.org/wiki/VirtualBox_PUEL
	sleep 3
	return 0
} > $LOGS/vbox.txt

#Creates "cuckoo" user and adds the user to vboxusers group
create_cuckoo_user(){
	sudo adduser  --disabled-password -gecos "" cuckoo
    sudo usermod -G vboxusers cuckoo
	
	cd $HOME
	sleep 3
    return 0
} > $LOGS/users.txt

#Installs Mongodb
install_mongodb(){
	cd $DOWNLOAD
	sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6
    echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list
	sudo apt update
	sudo apt-get install -y mongodb-org
	cd $HOME
	sleep 3
	return 0
} > $LOGS/mongodb.txt	

#Installs PostgreSQL
install_PostgreSQL(){
	sudo apt-get install -y postgresql libpq-dev
	sleep 3
	return 0
} > $LOGS/PostgreSQL.txt	

#Installs TCPdump
install_tcpdump(){
	sudo apt-get install -y tcpdump apparmor-utils
	sudo aa-disable /usr/sbin/tcpdump
	sudo apt-get install -y libcap2-bin
	sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
	getcap /usr/sbin/tcpdump #used to verify results
	sleep 3
	return 0
} > $LOGS/tcpdump.txt	

#Installs Distorm
install_distrom(){
	wget https://github.com/gdabah/distorm/archive/v3.3.4.tar.gz -P /home/$USER/CuckooInstall | sudo apt-key add 
	cd $DOWNLOAD
	#pip install distorm3
	tar -xvzf v3.3.4.tar.gz
    cd distorm-3.3.4
	sudo python setup.py build
    sudo python setup.py install
	cd $DOWNLOAD
	cd $HOME
	sleep 3
	return 0
} > $LOGS/distrom.txt

#Installs Yara
install_yara(){
	sudo apt-get install -y yara libyara-dev yara-dbg yara-doc python-yara python3-yara
	sleep 3
	return 0
} > $LOGS/yara.txt

#Installs Pycrypto
install_pycrypto(){
	sudo -H pip install pycrypto
	#alternate install#
	#wget https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz -P /home/$USER/CuckooInstall
	#cd $DOWNLOAD
	#tar -xzf pycrypto-2.6.1.tar.gz
	#cd pycrypto-2.6.1
	#sudo python setup.py build
	#sudo python setup.py install
	#cd $DOWNLOAD
	#m pycrypto-2.6.1.tar.gz
	cd $HOME
	sleep 3
	return 0
} > $LOGS/pycrypto.txt

#Installs Openpyxl
install_openpyxl(){
	sudo -H pip install openpyxl
	#alternate install#
	#wget https://pypi.python.org/packages/ab/2b/6cdededfa87c2761a0fd50d64859d8e5fb9d51c2d969b05599441974a3e5/openpyxl-2.5.0a3.tar.gz -P /home/$USER/CuckooInstall
	#cd $DOWNLOAD
	#tar -xzf openpyxl-2.5.0a3.tar.gz
	#cd openpyxl-2.5.0a3
	#sudo python setup.py build
	#sudo python setup.py install
	#cd $DOWNLOAD
	#rm openpyxl-2.5.0a3.tar.gzcd
	#cd $HOME
	sleep 3
	return 0
} > $LOGS/openpyxl.txt

#Installs UJSON
install_ujson(){
	sudo -H pip install ujson
	#alternate install#
	#wget https://pypi.python.org/packages/16/c4/79f3409bc710559015464e5f49b9879430d8f87498ecdc335899732e5377/ujson-1.35.tar.gz -P /home/$USER/CuckooInstall
	#cd $DOWNLOAD
	#tar -xzf ujson-1.35.tar.gz
	#cd ujson-1.35
	#sudo python setup.py build
	#sudo python setup.py install
	#cd $DOWNLOAD
	#rm ujson-1.35.tar.gz
	#cd $HOME
	sleep 3
	return 0
} > $LOGS/ujson.txt

#Installs MITMProxy
install_mitmproxy(){
	sudo apt-get install -y python3-pip python3-dev libssl-dev libtiff5-dev libjpeg8-dev zlib1g-dev libwebp-dev
	sudo -H pip3 install mitmproxy
	sleep 3
	return 0
} > $LOGS/mitmproxy.txt

#Installs Volatility 
install_volatility(){
	cd $DOWNLOAD
	wget http://downloads.volatilityfoundation.org/releases/2.6/volatility-2.6.zip  -P /home/$USER/CuckooInstall  #sudo apt install volatility (older version)
	unzip volatility-2.6.zip
	cd volatility-master
	sudo python setup.py build
	sudo python setup.py install
	sudo apt-get install -y volatility
	cd $DOWNLOAD
	rm volatility-2*
	cd $HOME	
	sleep 3
	return 0
} > $LOGS/volatility.txt	

# Installs Cuckoo 
install_cuckoo(){
	cd $DOWNLOAD
	mkdir Cuckoo
	cd $INSTALL
	pip download cuckoo	
	pip install *.tar.gz
	sudo apt-get install -y swig
	sudo -H pip install m2crypto
	sudo -H pip install -U pip setuptools
    sudo -H pip install -U cuckoo
	cd $HOME
	sleep 3
	return 0
} > $LOGS/cuckoo.txt

# Sets routing tables and then makes them permanent. Enables communication with Cuckoo and guest vm.
create_hostonly_iface(){
	vboxmanage hostonlyif create
	vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0  #if routing is not working eth0 many not be the primary interface.
    sudo iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.56.0/24 -j MASQUERADE #eth0
	sudo iptables -P FORWARD DROP
    sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
	sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
    sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A FORWARD -j LOG
	sudo bash -c echo 1 > sudo tee -a /proc/sys/net/ipv4/ip_forward
	sudo sysctl -w net.ipv4.ip_forward=1
	gnome-terminal -e sudo apt-get install iptables-persistent
	clear
	read -p "select yes to all, press [Enter] when complete..."
	echo "####installed iptables-persistent###"
    
} > $LOGS/iptables.txt


# Downloads a WIN7 ISO and python to run the Cuckoo agent.
create_vm(){
	cd $DOWNLOAD
	mkdir VM
	cd $DOWNLOAD/VM/
	mkdir vmshare
	cd $DOWNLOAD/VM
	read -p "Press [Enter] when you have transfered the ISO..."
	#wget https://az412801.vo.msecnd.net/vhd/VMBuild_20141027/VirtualBox/IE11/Windows/IE11.Win7.For.Windows.VirtualBox.zip -P /home/$USER/CuckooInstall/VM  #This could be made a variable
	wget https://www.python.org/ftp/python/2.7.14/python-2.7.14.msi -P /$vmshare
	wget https://bootstrap.pypa.io/get-pip.py -P /$vmshare
	cd $DOWNLOAD/VM
	unzip IE11.Win7.For.Windows.VirtualBox.zip
	cd $vmshare
	unzip master.zip
	rm master.zip 
	vboxmanage import "IE11 - Win7.ova" --dry-run > $LOGS/image.txt
	vboxmanage import "IE11 - Win7.ova"
	vboxmanage modifyvm "IE11 - Win7" --name $vmname
	vboxmanage sharedfolder add $vmname --name VM --hostpath /home/test/CuckooInstall/VM --automount
	vboxmanage startvm $vmname --type headless
	vboxmanage controlvm $vmname clipboard bidirectional
	vboxmanage controlvm $vmname draganddrop hosttoguest
	vboxmanage controlvm $vmname poweroff
	cd /home/$USER/.cuckoo/agent
	gnome-terminal -e cuckoo
	gnome-terminal -e mitmproxy #Opens MITMProxy to enable copying of the cert.
	cp /home/$USER/.cuckoo/agent/agent.py /home/$USER/CuckooInstall/VM/vmshare/agent.pyw #.pyw extension does not bring up a terminal while running. Change to a .py extension if you would like the terminal to display
	cp /home/test/.mitmproxy/mitmproxy-ca-cert.p12 /home/test/.cuckoo/analyzer/windows/bin/mitmproxy-ca-cert.p12 #used for mitmproxy
	
	###This creates a batch file to quickly set up the guest host###
		{
		printf '@echo off\r\n' > /$vmshare/configuration.bat
		printf 'color 0a\r\n' >> /$vmshare/configuration.bat 
		printf 'echo Disabling Windows Defender \r\n' >> /$vmshare/configuration.bat
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'sc stop WinDefend\r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo Disabling Firewall\r\n' >> /$vmshare/configuration.bat 
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'NetSh Advfirewall set allprofiles state off\r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo Disabling Windows Updates..\r\n' >> /$vmshare/configuration.bat
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f\r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo Installing Python. Confirm Python.msi is on the Desktop? \r\n' >> /$vmshare/configuration.bat
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'cd C:\\Users\IEUSer\Desktop\r\n' >> /$vmshare/configuration.bat
		printf 'python-2.7.14.msi\r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo Installing Pip.\r\n' >> /$vmshare/configuration.bat 
		printf 'cd C:\Python27\r\n' >> /$vmshare/configuration.bat 
		printf 'python C:\\Users\IEUser\Desktop\get-pip.py\r\n' >> /$vmshare/configuration.bat 
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
		printf 'cd C:\\Users\IEUser\Desktop\r\n' >> /$vmshare/configuration.bat
		printf 'COPY /V /Y agent.pyw "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"\r\n' >> /$vmshare/configuration.bat
		printf 'echo Additional_Downloads on the Desktop is a list of additional programs to install\r\n' >> /$vmshare/configuration.bat 
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo Setting the IP\r\n' >> /$vmshare/configuration.bat
		printf 'netsh interface ip set address name="Local Area Connection 2" static 192.168.56.101 255.255.255.0 192.168.56.1\r\n' >> /$vmshare/configuration.bat
		printf 'netsh interface ip set dns "Local Area Connection 2" static 192.168.56.1 8.8.8.8\r\n' >> /$vmshare/configuration.bat #GUEST DNS 
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'cls\r\n' >> /$vmshare/configuration.bat
		printf 'echo install the following programs > C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'echo install Adobe PDF Reader "https://get.adobe.com/reader/" >> C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'echo install Adobe Flash Player "https://get.adobe.com/flashplayer/" >> C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'echo install Java "https://java.com/en/download/" >> C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'echo install Microsoft Office if you have a license >> C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'echo install other browsers such as FireFox and Chrome >> C:\\Users\IEUser\Desktop\Additional_Downloads.txt\r\n' >> /$vmshare/configuration.bat
		printf 'set PATH=%%PATH%%;C:\Python27;C:\Python27\Scipts\r\n' >> /$vmshare/configuration.bat
		printf 'echo removing files \r\n' >> /$vmshare/configuration.bat
		printf 'pause \r\n' >> /$vmshare/configuration.bat
		printf 'DEL /Q C:\\Users\IEUser\Desktop\python-2.7.14.msi C:\\Users\IEUser\Desktop\get-pip.py\r\n' >> /$vmshare/configuration.bat
		printf 'DEL /Q C:\\Users\IEUser\Desktop\get-pip.py\r\n' >> /$vmshare/configuration.bat
		printf 'DEL /Q C:\\Users\IEUser\Desktop\agent.pyw\r\n' >> /$vmshare/configuration.bat
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
	
} > $LOGS/vmcomponents.txt

# Configures Cuckoo .conf files
set_config(){
	cd $CONFIG
	sudo sed -i 's/memory_dump = no/memory_dump = yes/' cuckoo.conf
	sed -i '0,/enabled = no/s//enabled = yes/' auxiliary.conf #sed -i '0,/enabled = no/s//enabled = hold/' auxiliary.conf sed -i '0,/enabled = no/s//enabled = yes/' auxiliary.conf sed -i '0,/enabled = hold/s//enabled = no/' auxiliary.conf
	{
	sed -i '0,/enabled = no/s//enabled = hold/' processing.conf 
	sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	sed -i '0,/enabled = no/s//enabled = hold/' processing.conf
	sed -i '0,/enabled = no/s//enabled = yes/' processing.conf 
    sed -i 's/enabled = hold/enabled = no/' processing.conf	
	}
	sudo sed -i '/\[mongodb\]/{ N; s/.*/\[mongodb\]\nenabled = yes/; }' reporting.conf
	sudo sed -i 's/guest_profile = WinXPSP2x86/guest_profile = Win7SP1x86/' memory.conf
	{
	#Specific configurations for the Virtual Machine information
	sed -i 's/headless/gui/' virtualbox.conf
	sed -i '0,/label = cuckoo1/s//label = WIN7/' virtualbox.conf #Label should be the VM Name
	sed -i '0,/snapshot =/s//snapshot = Cuckoo_Snapshot/' virtualbox.conf
	}
	{
	printf 'Creating Cuckoo Help File\n'
	cuckoo --help > $HOME/Cuckoo_Help.txt
	}
	
} > $LOGS/cuckooconf.txt


# Configures the guest vm to perform analysis. 
configure_vm(){
	vboxmanage startvm $vmname --type gui
{
printf "\033[1;32m
Follow the steps below to configure the $vmname VM for Cuckoo
1. Copy the all the files located at /$vmshare/ to the desktop of the VM. Network Share should be loaded.
2. Execute the configuration.bat as an administrator This will restart the VM at the end of the script.
3. Install additional programs after the restart. Refer to the Additional_Downloads.txt on the desktop.
\e[0m\n"
sleep 60
printf 'A snapshot "Cuckoo_Snapshot" will be completed once the VM is configured\n'
printf 'Taking the snapshot will shutdown the VM\n'
sleep 60
}
	read -p "Press [Enter] when you have completed all of the steps..."
		{
		vboxmanage controlvm $vmname poweroff
		vboxmanage modifyvm $vmname --hostonlyadapter1 vboxnet0
		vboxmanage modifyvm $vmname --nic1 hostonly
		vboxmanage startvm $vmname
		clear
		read -p "Press [Enter] when the VM is fully booted up..."
		sleep 10
		vboxmanage snapshot $vmname take Cuckoo_Snapshot --pause
		vboxmanage snapshot $vmname showvminfo Cuckoo_Snapshot > $LOGS/Cuckoo_Snapshot_info.txt
		vboxmanage controlvm $vmname poweroff
		vboxmanage controlvm $vmname restorecurrent
		}
}

# Creates a start-up script for launching Cuckoo
cuckoo_start(){
	printf 'Cuckoo Start-up Script location is /home/$USER/\n'
	sleep 10
	cd /home/$USER
	printf '#!/bin/bash\n' > /home/$USER/start_cuckoo.bash
	printf 'vmname=WIN7' >> /home/$USER/start_cuckoo.bash #change $vname if you change the variable
	printf 'sudo rm /var/lib/mongodb/mongod.lock\n' >> /home/$USER/start_cuckoo.bash
	printf 'sudo service mongod restart\n' >> /home/$USER/start_cuckoo.bash
	printf 'vboxmanage startvm $vmname --type headless\n' >> /home/$USER/start_cuckoo.bash #change --type to gui if you want a gui
	printf 'cuckoo community\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-terminal -e mitmproxy\n' >> /home/$USER/start_cuckoo.bash
	printf 'sleep 3\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-terminal -e cuckoo\n' >> /home/$USER/start_cuckoo.bash
	printf 'sleep 3\n' >> /home/$USER/start_cuckoo.bash
	printf "gnome-terminal -e \'cuckoo web runserver\'\n" >> /home/$USER/start_cuckoo.bash
	printf 'sleep 3\n' >> /home/$USER/start_cuckoo.bash
	printf 'gnome-open http://127.0.0.1:8000/\n' >> /home/$USER/start_cuckoo.bash
	chmod +x start_cuckoo.bash
	} > $LOGS/cuckoo_startup.txt


	
# Cleanse up the Cuckoo Install folder
clean_up(){
	cd /home/$USER/CuckooInstall
	rm -rf *tar.gz
	cd $HOME
	sleep 3
} > $LOGS/cleanup.txt

the_distance(){
	sleep 5
	clear
}

# Init.
print_copy 
sleep 3
printf "\033[1;32mThe install will take approximatly 30+ minutes to complete!\e[0m\n"
printf "\033[1;93mUser Input is Required to configure the VM for Cuckoo, however you can just hit enter and complete the configuration later\e[0m\n"
printf "\033[1;93mOutput is saved to /home/$USER/CuckooInstall/LOGS\e[0m\n"
read -p "Press [Enter] key to start install or [Ctrl + C] to exit..."
clear

printf "\033[1;93mPreparing to Install...\e[0m\n"
check_viability 
printf "\033[1;92m✓\e[0m\033[1;92mSystem is Ready for Install\e[0m\n"
printf '\033[1;37m 0%%.......................................................................\e[0m\n' 
the_distance

printf "\033[1;93mUpdating the System...\e[0m\n"
perform_update 
printf "\033[1;92m✓\e[0m\033[1;92mSuccessfully Updated the System\e[0m\n"
the_distance

printf "\033[1;93mUpdating Python...\e[0m\n"
prepare_python  
printf "\033[1;92m✓\e[0m\033[1;92mUpdated Python\e[0m\n"
printf '\033[1;37m 0%%...10%%................................................................\e[0m\n'
the_distance

printf "\033[1;93mUpdating Libraries...\e[0m\n"
install_lib 
printf "\033[1;92m✓\e[0m\033[1;92mUpdated Libraries\e[0m\n"
the_distance 

printf "\033[1;93mInstalling VirtualBox...\e[0m\n"
install_virtualbox 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled VirtualBox\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%..................................................\e[0m\n'
the_distance

printf "\033[1;93mCreating User "cuckoo"...\e[0m\n"
create_cuckoo_user 
printf "\033[1;92m✓\e[0m\033[1;92mUser cuckoo Added\e[0m\n" 
the_distance

printf "\033[1;93mInstalling Mongodb...\e[0m\n"
install_mongodb 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Mongodb\e[0m\n" 
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...........................................\e[0m\n'
the_distance

printf "\033[1;93mInstalling PostgreSQL...\e[0m\n"
install_PostgreSQL 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled PostgreSQL\e[0m\n"
the_distance

printf "\033[1;93mInstalling TCPdump...\e[0m\n"
install_tcpdump
printf "\033[1;92m✓\e[0m\033[1;92mInstalled TCPdump\e[0m\n"
the_distance

printf "\033[1;93mInstalling Distrom...\e[0m\n"
install_distrom 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Distrom\e[0m\n" 
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%....................................\e[0m\n'
the_distance

printf "\033[1;93mInstalling Yara...\e[0m\n"
install_yara
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Yara\e[0m\n" 
the_distance

printf "\033[1;93mInstalling Pycrypto...\e[0m\n"
install_pycrypto 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Pycrypto\e[0m\n"
the_distance

printf "\033[1;93mInstalling Openpyxl...\e[0m\n"
install_openpyxl
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Openpyxl\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%...60%%.............................\e[0m\n'
the_distance

printf "\033[1;93mInstalling UJSON...\e[0m\n"
install_ujson 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled UJSON\e[0m\n" 
the_distance

printf "\033[1;93mInstalling Mitmproxy...\e[0m\n"
install_mitmproxy 
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Mitmproxy\e[0m\n"
the_distance

printf "\033[1;93mInstalling Volatility...\e[0m\n"
install_volatility
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Volatility\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%...60%%...70%%......................\e[0m\n'
the_distance

printf "\033[1;93mInstalling Cuckoo...\e[0m\n"
install_cuckoo
printf "\033[1;92m✓\e[0m\033[1;92mInstalled Cuckoo\e[0m\n"
the_distance

printf "\033[1;93mConfiguring Cuckoo IP Tables...\e[0m\n"
create_hostonly_iface
printf "\033[1;92m✓\e[0m\033[1;92mConfigured Cuckoo IP Tables\e[0m\n"
the_distance

printf "\033[1;93mDownloading VM Components\e[0m\n"
create_vm 
printf "\033[1;92m✓\e[0m\033[1;92mDownloaded VM Components\e[0m\n"
the_distance

printf "\033[1;93mConfiguring Cuckoo\e[0m\n"
set_config
printf "\033[1;92m✓\e[0m\033[1;92mConfigured Cuckoo\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%...60%%...70%%...80%%...............\e[0m\n'
the_distance

printf "\033[1;93mNow to configure the VM...\e[0m\n"
configure_vm
printf "\033[1;92m✓\e[0m\033[1;92mConfigured Guest VM\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%...60%%...70%%...80%%...90%%........\e[0m\n'
the_distance

printf "\033[1;93mCreating Cuckoo Startup Script...\e[0m\n"
cuckoo_start
printf "\033[1;92m✓\e[0m\033[1;92mConfigured Cuckoo IP Tables\e[0m\n"
printf "\033[1;93mScript location is /home/$USER/\e[0m\n"
printf '\033[1;37m 0%%...10%%...20%%...30%%...40%%...50%%...60%%...70%%...80%%...90%%...100%%\e[0m\n'
the_distance

clean_up

printf "Refer to the Documentation for instructions on running Cuckoo\n"
sleep 3
printf 'The Script is complete\n'
printf 'Restarting the Computer\n'
read -p "Press [Enter] key to restart or [Ctrl + C] to exit..."
shutdown -r now 

 





