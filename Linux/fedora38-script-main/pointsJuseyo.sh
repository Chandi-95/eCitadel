#!/bin/bash
echo "Please Stop Throwing"

USERS=./users.txt
ADMINS=./admins.txt

unleashHell(){
	starter
	dns
	verify
	users
	firewall
	misc
	checkPackages
	filePriv
 	comparison
	mediaFiles
	lastMinuteChecks
}

#STARTER
starter(){
	checkCredentials
	backups
	saveLogs
	aliases
}

#Check for required files and credentials
checkCredentials(){
	if [[ $EUID -ne 0 ]]; then
   		echo "User is not root. Shutting down script."
   		exit 1
	fi

	if [ ! -f "$USERS" ]; then
    		echo "Necessary text files for users and admins are not present. Shutting down script."
    		exit 1
	fi

	if [ ! -f "$ADMINS" ]; then
    		echo "Necessary text files [admins] for users and admins are not present. Shutting down script."
    		exit 1
	fi
}

backups() {
    # BACKUPS AUTHOR: Smash (https://github.com/smash8tap)
    # Make Secret Dir
    echo "Making backups..."
    hid_dir="/usr/share/fonts/roboto-mono"
    mkdir -p "$hid_dir"

    declare -A dirs
    dirs[etc]="/etc"
	dirs[home]="/home"
    dirs[www]="/var/www"
    dirs[log]="/var/log"

    for key in "${!dirs[@]}"; do
        dir="${dirs[$key]}"
        if [ -d "$dir" ]; then
            echo "Backing up $key..."
            tar -czvf "$hid_dir/$key.tar.gz" -C "$dir" . > /dev/null 2>&1
            # Rogue backups
            tar -czvf "/var/backups/$key.bak.tar.gz" -C "$dir" . > /dev/null 2>&1
        fi
    done

    echo "Finished backups."
}

aliases(){
	#cat configs/bashrc > ~/.bashrc
	for user in $(cat users.txt); do
        	cat configs/bashrc > /home/$user/.bashrc;
	done;
	cat configs/bashrc > /root/.bashrc
	cat configs/profile > /etc/profile
}

saveLogs(){
	cp -r /var/log varLogBackups
}

#DNS
dns(){
	# hosts // commented because it was breaking connections
	systemctl restart NetworkManager
}

hosts(){
	echo "Configuring /etc/hosts file"
	echo "ALL:ALL" > /etc/hosts.deny
	echo "sshd:ALL" > /etc/hosts.allow
	echo "resolver checks for spoofing"
	echo "order hosts,bind" > /etc/host.conf
}


verify(){
	dnf check-update > /dev/null
	dnf clean all
	dnf install -y bash
	dnf install -y curl
	dnf install -y net-tools
	dnf install -y dnf
	echo "fixing corrupt packages"
	rpm -qf $(rpm -Va 2>&1 | grep -vE '^$|prelink:' | sed 's|.* /|/|') | sort -u
	dnf install -y firewalld
	dnf install -y pam
 	dnf install -y libpam_pwquality
  	dnf install -y libpam_faillock
	dnf install -y sudo
	dnf install -y firefox
 	dnf install -y e2fsprogs
  	chattr -ia /etc/passwd
   	chattr -ia /etc/group
    	chattr -ia /etc/shadow
     	chattr -ia /etc/passwd-
   	chattr -ia /etc/group-
    	chattr -ia /etc/shadow-
}

users(){
	configCmds
	checkAuthorized
	passwords
	lockAll
	extensions
	sudoers
	passPolicy
}

configCmds(){
	cat configs/adduser.conf > /etc/adduser.conf
	cat configs/deluser.conf > /etc/deluser.conf
}

#Creates all required users and deletes those that aren't
checkAuthorized(){
	#For everyone in users.txt file, creates the user
	for user in $(cat users.txt); do
		grep -q $user /etc/passwd || useradd -m -s /bin/bash $user
		crontab -u $user -r
		echo "$user checked for existence"
	done
	echo "Finished adding users"

	#Delete bad users
	for user in $(grep "bash" /etc/passwd | cut -d':' -f1); do
		grep -q $user users.txt || (userdel $user 2> /dev/null)
	done
	echo "Finished deleting bad users"


	#this script is kinda wack
	#but basically, it will delete admins, including correct ones, and then add them back in
	#Goes and makes users admin/not admin as needed for every user with UID above 500 that has a home directory
	for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1); do
		#If the user is supposed to be a normal user but is in the wheel group, remove them from wheel
		BadUser=0
		if [[ $( grep -ic $i $(pwd)/users.txt ) -ne 0 ]]; then
			if [[ $( echo $( grep "wheel" /etc/group) | grep -ic $i ) -ne 0 ]]; then
				#if username is in wheel when shouldn’t
				gpasswd -d $i wheel;
			fi
			if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -ne 0 ]]; then
				#if username is in adm when shouldn’t
				gpasswd -d $i adm;
			fi
		else
			BadUser=$((BadUser+1));
		fi
		#If user is supposed to be an adm but isn’t, raise privilege.

		if [[ $( grep -ic $i $(pwd)/admins.txt ) -ne 0 ]]; then
			if [[ $( echo $( grep "wheel" /etc/group) | grep -ic $i ) -eq 0 ]]; then
				#if username isn't in wheel when should
				usermod -a -G "wheel" $i
			fi
			if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -eq 0 ]]; then
				#if username isn't in adm when should
				usermod -a -G "adm" $i
			fi
		else
			BadUser=$((BadUser+1));
		fi

		if [[ $BadUser -eq 2 ]]; then
			echo "WARNING: USER $i HAS AN ID THAT IS CONSISTENT WITH A NEWLY ADDED USER YET IS NOT MENTIONED IN EITHER THE admins.txt OR users.txt FILE. LOOK INTO THIS."
		fi
	done

	echo "Finished changing users"
}

passwords()
{
	echo "settings password and locking root"
	echo 'root:Password1234!@#$' | chpasswd;
	passwd -l root;
	echo "change all user passwords"
	for user in $(cat users.txt); do
		passwd -x 85 $user > /dev/null;
		passwd -n 15 $user > /dev/null;
		echo $user:'Password1234!@#$' | chpasswd;
		chage --maxdays 15 --mindays 6 --warndays 7 --inactive 5 $user;
	done;
}

lockAll()
{
	echo "locking all system accounts"
	for user in $(cat /etc/passwd | cut -d ':' -f 1); do
		echo $user;
		grep -q $user users.txt || grep -q $user admins.txt || passwd -l $user;
	done;
}

extensions()
{
	echo "deleting rhosts, shosts, forward, netrc files"
	find / -name ".rhosts" -exec rm -rf {} \;
 	find / -name "hosts.equiv" -exec rm -rf {} \;
     	find / -iname '*.shosts' -delete
    	find / -iname '*.shosts.equiv' -delete
        find / -iname '*.forward' -delete
    	find / -iname '*.netrc' -delete
}

sudoers(){
	echo "Resetting sudoers file and README"
	cat configs/sudoers > /etc/sudoers
	cat configs/README > /etc/sudoers.d/README
	rm -f /etc/sudoers.d/*
}

greeterConfig(){
	echo "Disabling guest account"
	    cat configs/custom.conf > /etc/gdm3/custom.conf
}

passPolicy(){
	echo "Setting password policy"
	cat configs/login.defs > /etc/login.defs
	cat configs/pwquality.conf > /etc/security/pwquality.conf
	echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
	echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su-l
	echo "password required pam_unix.so sha512 shadow nullok rounds=65536" >> /etc/pam.d/passwd
	cat configs/password-auth > /etc/pam.d/password-auth
 	cat configs/system-auth > /etc/pam.d/system-auth
	echo "Password policy has been set"
	
}

firewall()
{
	echo "setting firewall"
	systemctl unmask firewalld
	systemctl start firewalld
	systemctl enable firewalld
}

filePriv()
{
	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
	bash helperScripts/perms.sh
}

misc()
{
	dconfSettings
	echo "* hard core 0" > /etc/security/limits.conf
	echo "* soft core 0" > /etc/security/limits.conf
	echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
	echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
	echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
 	echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab
	echo "LABEL=/boot /boot ext2 defaults,ro 1 2" >> /etc/fstab
	prelink -ua
	dnf remove -y prelink
	systemctl mask ctrl-alt-del.target
	systemctl daemon-reload
	update-crypto-policies --set DEFAULT
  	echo "+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0" >> /etc/crypto-policies/back-ends/gnutls.config
   	echo "include /etc/crypto-policies/back-ends/libreswan.config" >> /etc/ipsec.conf
	echo "tty1" > /etc/securetty
	echo "TMOUT=900" >> /etc/profile
	echo "readonly TMOUT" >> /etc/profile
	echo "export TMOUT" >> /etc/profile
 	echo "declare -xr TMOUT=900" > /etc/profile.d/tmout.sh
	#dont prune shit lol
	echo "" > /etc/updatedb.conf
	echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
	echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
	cat configs/environment > /etc/environment
	cat configs/control-alt-delete.conf > /etc/init/control-alt-delete.conf
	dnf install -y audit > /dev/null
	auditctl -e 1
 	echo configs/auditd.conf > /etc/audit/auditd.conf
  	echo configs/audit.rules > /etc/audit/audit.rules
 	echo 0 > /proc/sys/kernel/unprivileged_userns_clone
	cat configs/sysctl.conf > /etc/sysctl.conf
	sysctl -ep
	rm -f /usr/lib/gvfs/gvfs-trash
	rm -f /usr/lib/svfs/*trash
	# sudo find / -iname '*password.txt' -delete
	# sudo find / -iname '*passwords.txt' -delete
	# sudo find /root -iname 'user*' -delete
	# sudo find / -iname 'users.csv' -delete
	# sudo find / -iname 'user.csv' -delete
	rm -f /usr/share/wordpress/info.php
	rm -f /usr/share/wordpress/wp-admin/webroot.php
	rm -f /usr/share/wordpress/index.php
	rm -f /usr/share/wordpress/r57.php
	rm -f /usr/share/wordpress/phpinfo.php
	rm -f /var/www/html/phpinfo.php
	rm -f /var/www/html/webroot.php
	rm -f /var/www/html/index.php
	rm -f /var/www/html/info.php
	rm -f /var/www/html/r57.php
	rm -f /usr/lib/gvfs/gvfs-trash
	rm -f /usr/lib/gvfs/*trash
	rm -f /var/timemachine
	rm -f /bin/ex1t
	rm -f /var/oxygen.html
}	

dconfSettings()
{
	dconf reset -f /
	gsettings set org.gnome.desktop.privacy remember-recent-files false
	gsettings set org.gnome.desktop.media-handling automount false
	gsettings set org.gnome.desktop.media-handling automount-open false
	gsettings set org.gnome.desktop.search-providers disable-external true
	dconf update /

}
checkPackages()
{
	echo "----------- Trying to Find and Remove Malware -----------"
    REMOVE="john* netcat* iodine* kismet* medusa* hydra* fcrackzip* ayttm* empathy* nikto* logkeys* rdesktop* vinagre* openarena* openarena-server* minetest* minetest-server* ophcrack* crack* ldp* metasploit* wesnoth* freeciv* zenmap* knocker* bittorrent* torrent* p0f aircrack* aircrack-ng ettercap* irc* cl-irc* rsync* armagetron* postfix* nbtscan* cyphesis* endless-sky* hunt snmp* snmpd dsniff* lpd vino* netris* bestat* remmina netdiag inspircd* up.time uptimeagent chntpw* nfs* nfs-kernel-server* abc sqlmap acquisition bitcomet* bitlet* bitspirit* armitage airbase-ng* qbittorrent* ctorrent* ktorrent* rtorrent* deluge* tixati* frostwise vuse irssi transmission-gtk utorrent* exim4* crunch tomcat tomcat6 vncserver* tightvnc* tightvnc-common* tightvncserver* vnc4server* nmdb dhclient cryptcat* snort pryit gameconqueror* weplab lcrack dovecot* pop3 ember manaplus* xprobe* openra* ipscan* arp-scan* squid* heartbleeder* linuxdcpp* cmospwd* rfdump* cupp3* apparmor nis* ldap-utils prelink rsh-client rsh-redone-client* rsh-server quagga gssproxy iprutils sendmail nfs-utils ypserv tuned" 
    for package in $REMOVE; do
		removed=$(dnf remove $package -y) 
    done
	sudo dnf install policycoreutils policycoreutils-python-utils selinux-policy selinux-policy-devel -y
	systemctl start selinux
}

comparison()
# comparison script - credits to hal
{
	bash helperScripts/dircomp/getDirs.sh
 	bash helperScripts/dircomp/getDiff.sh
}
mediaFiles()
{
    find / -name '*.mp3' -type f -delete
    find / -name '*.mov' -type f -delete
    find / -name '*.mp4' -type f -delete
    find / -name '*.avi' -type f -delete
    find / -name '*.mpg' -type f -delete
    find / -name '*.mpeg' -type f -delete
    find / -name '*.flac' -type f -delete
    find / -name '*.m4a' -type f -delete
    find / -name '*.flv' -type f -delete
    find / -name '*.ogg' -type f -delete
    find /home -name '*.gif' -type f -delete
    find /home -name '*.png' -type f -delete
    find /home -name '*.jpg' -type f -delete
    find /home -name '*.jpeg' -type f -delete
    find / -iname '*.m4b' -delete
    find /home -iname '*.wav' -delete
    find /home -iname '*.wma' -delete
    find /home -iname '*.aac' -delete
    find /home -iname '*.bmp' -delete
    find /home -iname '*.img' -delete
    find /home -iname '*.exe' -delete
    find /home -iname '*.csv' -delete
    find /home -iname '*.bat' -delete
    find / -iname '*.xlsx' -delete

}
lastMinuteChecks()
{
	yum install scap-security-guide -y # install and run scap compliance check
 	oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cusp_fedora --results-arf arf.xml --report report.html --oval-results /usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml
 	
	dmesg | grep "Kernel/User page tables isolation: enabled" && echo "patched" || echo "unpatched"

	cat /etc/default/grub | grep "selinux" && echo "check /etc/default/grub for selinux" || echo "/etc/default/grub does not disable selinux"

	cat /etc/default/grub | grep "enforcing=0" && echo "check /etc/default/grub for enforcing" || echo "/etc/default/grub does not contain enforcing=0"
}



unleashHell
