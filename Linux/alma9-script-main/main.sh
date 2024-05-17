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
    filePriv
    mediaFiles
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
    #dirs[home]="/home"
    dirs[www]="/var/www"
    #dirs[log]="/var/log"

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

saveRepos(){
    cp -r /etc/yum.repos.d yumRepoBackups
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
    cp -TR configs/repos /etc/yum.repos.d
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
    cat configs/useradd > /etc/default/useradd
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

    # This script will delete admins, including correct ones, and then add them back in
    # Goes and makes users admin/not admin as needed for every user with UID above 500 that has a home directory
    for i in $(cat /etc/passwd | cut -d: -f 1,3,6 | grep -e "[5-9][0-9][0-9]" -e "[0-9][0-9][0-9][0-9]" | grep "/home" | cut -d: -f1); do
        # If the user is supposed to be a normal user but is in the wheel group, remove them from wheel
        BadUser=0
        if [[ $( grep -ic $i $(pwd)/users.txt ) -ne 0 ]]; then
            if [[ $( echo $( grep "wheel" /etc/group) | grep -ic $i ) -ne 0 ]]; then
                # if username is in wheel when shouldn’t
                gpasswd -d $i wheel;
            fi
            if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -ne 0 ]]; then
                # if username is in adm when shouldn’t
                gpasswd -d $i adm;
            fi
        else
            BadUser=$((BadUser+1));
        fi
        # If user is supposed to be an adm but isn’t, raise privilege.

        if [[ $( grep -ic $i $(pwd)/admins.txt ) -ne 0 ]]; then
            if [[ $( echo $( grep "wheel" /etc/group) | grep -ic $i ) -eq 0 ]]; then
                # if username isn't in wheel when should
                usermod -a -G "wheel" $i
            fi
            if [[ $( echo $( grep "adm" /etc/group) | grep -ic $i ) -eq 0 ]]; then
                # if username isn't in adm when should
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

passwords(){
    echo "settings password and locking root"
    echo 'root:qwerQWER1234!@#$' | chpasswd;
    passwd -l root;
    echo "change all user passwords"
    for user in $(cat users.txt); do
        passwd -x 85 $user > /dev/null;
        passwd -n 15 $user > /dev/null;
        echo $user:'qwerQWER1234!@#$' | chpasswd;
        chage --maxdays 15 --mindays 6 --warndays 7 --inactive 5 $user;
    done;
}

lockAll(){
    echo "locking all system accounts"
    for user in $(cat /etc/passwd | cut -d ':' -f 1); do
        echo $user;
        grep -q $user users.txt || grep -q $user admins.txt || passwd -l $user;
    done;
}

extensions(){
    echo "deleting rhosts, shosts, forward, netrc files"
    find / -name ".rhosts" -exec rm -rf {} \;
    find / -name ".shosts" -exec rm -rf {} \;
    find / -name ".netrc" -exec rm -rf {} \;
    find / -name ".forward" -exec rm -rf {} \;
	find / -name ".hosts.equiv" -exec rm -rf {} \;
	find / -name ".shosts.equiv" -exec rm -rf {} \;

}

sudoers(){
    cp /etc/sudoers /etc/sudoers.orig
    cp configs/sudoers /etc/sudoers
    echo "users in sudoers file but not admins:"
    for user in $(grep -oP '(?<=^User_Alias ADMINS = ).*' /etc/sudoers | tr ',' '\n'); do
        grep -q $user admins.txt || echo $user
    done
}

passPolicy(){
    echo "configuring password policies"
    cp configs/system-auth /etc/pam.d/system-auth
    cp configs/password-auth /etc/pam.d/password-auth
    cp configs/login.defs /etc/login.defs
    echo "* hard core 0" > /etc/security/limits.conf
	echo "* soft core 0" > /etc/security/limits.conf
}

#FIREWALL
firewall(){
    configFW
    ports
    services
    zones
}

configFW(){
    systemctl start firewalld
    systemctl enable firewalld
}

ports(){
    echo "Configuring firewall ports"
    ports=("CHANGEME")
    for port in "${ports[@]}"; do
        firewall-cmd --permanent --add-port=$port/tcp
        firewall-cmd --permanent --add-port=$port/udp
    done
    firewall-cmd --reload
}

services(){
    echo "Configuring firewall services"
    services=("CHANGEME")
    for service in "${services[@]}"; do
        firewall-cmd --permanent --add-service=$service
    done
    firewall-cmd --reload
}

zones(){
    echo "Configuring firewall zones"
    firewall-cmd --set-default-zone=drop
    firewall-cmd --zone=trusted --add-interface=lo
    firewall-cmd --reload
}

#MISC
misc(){
    echo "Running miscellaneous tasks"
    denyRootSSH
    auditLogs
    cronJobs
    setNTP
    grubChanges
    motdBanner
    cupsd
	configSelinux
	configDNF
	configFstab
	greeterConfig
	miscFiles
	checkPackages
}

denyRootSSH(){
    echo "Denying root SSH access"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

auditLogs(){
    echo "Setting up audit logs"
    dnf install -y audit
    systemctl start auditd
    systemctl enable auditd
    cp configs/audit.rules /etc/audit/rules.d/audit.rules
    systemctl restart auditd
}

cronJobs(){
    echo "Configuring cron jobs"
    rm -f /etc/cron.deny
    echo "root" > /etc/cron.allow
    echo "ALL:ALL" > /etc/cron.deny
    chown root:root /etc/cron.allow
    chmod 400 /etc/cron.allow
}

setNTP(){
    echo "Setting up NTP"
    dnf install -y chrony
    systemctl start chronyd
    systemctl enable chronyd
    cp configs/chrony.conf /etc/chrony.conf
    systemctl restart chronyd
}

grubChanges(){
    echo "Configuring GRUB"
    cp configs/grub /etc/default/grub
	cat configs/40_custom > /etc/grub.d/40_custom
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

motdBanner(){
    echo "Setting up MOTD and issue banner"
    echo "" > /etc/motd
    cp configs/issue /etc/issue
    cp configs/issue.net /etc/issue.net
}

cupsd(){
    echo "Disabling CUPS"
    systemctl stop cups
    systemctl disable cups
}

checkPackages()
{
	echo "----------- Trying to Find and Remove Malware -----------"
    REMOVE="john* netcat* iodine* kismet* medusa* hydra* fcrackzip* ayttm* empathy* nikto* logkeys* rdesktop* vinagre* openarena* openarena-server* minetest* minetest-server* ophcrack* crack* ldp* metasploit* wesnoth* freeciv* zenmap* knocker* bittorrent* torrent* p0f aircrack* aircrack-ng ettercap* irc* cl-irc* rsync* armagetron* postfix* nbtscan* cyphesis* endless-sky* hunt snmp* snmpd dsniff* lpd vino* netris* bestat* remmina netdiag inspircd* up.time uptimeagent chntpw* nfs* nfs-kernel-server* abc sqlmap acquisition bitcomet* bitlet* bitspirit* armitage airbase-ng* qbittorrent* ctorrent* ktorrent* rtorrent* deluge* tixati* frostwise vuse irssi transmission-gtk utorrent* exim4* crunch tomcat tomcat6 vncserver* tightvnc* tightvnc-common* tightvncserver* vnc4server* nmdb dhclient cryptcat* snort pryit gameconqueror* weplab lcrack dovecot* pop3 ember manaplus* xprobe* openra* ipscan* arp-scan* squid* heartbleeder* linuxdcpp* cmospwd* rfdump* cupp3* apparmor nis* ldap-utils prelink rsh-client rsh-redone-client* rsh-server quagga gssproxy iprutils sendmail nfs-utils ypserv tuned" 
    for package in $REMOVE; do
		removed=$(dnf remove $package -y) 
    done
	sudo dnf install selinux-policy-targeted -y
}

configSelinux(){
    echo "Configuring SELinux"
    setenforce 1
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
}

configDNF(){
	echo "Setting configurations for DNF"
	cp configs/dnf.conf /etc/dnf/dnf.conf
	dnf install dnf-automatic -y
	cp configs/automatic.conf /etc/dnf/automatic.conf
	systemctl enable dnf-automatic.timer
}

configFstab(){
	echo "editing /etc/fstab configuration"
	echo "tmpfs /run/shm tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
	echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
	echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
 	echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab
}

greeterConfig(){
	echo "Setting configurations for GDM"
	cat configs/custom.conf > /etc/gdm/custom.conf
}

miscFiles(){
	cp configs/sysctl.conf /etc/sysctl.conf
	cp configs/secure.conf /etc/modprobe.d/secure.conf
	sysctl -ep
	update-crypto-policies --set DEFAULT
  	echo "+VERS-ALL:-VERS-DTLS0.9:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0" >> /etc/crypto-policies/back-ends/gnutls.config
   	echo "include /etc/crypto-policies/back-ends/libreswan.config" >> /etc/ipsec.conf
	echo "tty1" > /etc/securetty
	echo "TMOUT=900" >> /etc/profile
	echo "readonly TMOUT" >> /etc/profile
	echo "export TMOUT" >> /etc/profile
 	echo "declare -xr TMOUT=900" > /etc/profile.d/tmout.sh
	echo "" > /etc/updatedb.conf
	echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
	echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
	cp configs/environment /etc/environment
}

filePriv(){
	bash helperScripts/perms.sh
}

mediaFiles(){
    echo "Searching for media files"
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

unleashHell
