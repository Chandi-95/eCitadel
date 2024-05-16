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
    #dirs[home]="/home"
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
    yum check-update > /dev/null
    yum clean all
    yum install -y bash
    yum install -y curl
    yum install -y net-tools
    yum install -y yum
    echo "fixing corrupt packages"
    rpm -qf $(rpm -Va 2>&1 | grep -vE '^$|prelink:' | sed 's|.* /|/|') | sort -u
    yum install -y firewalld
    yum install -y pam
    yum install -y libpwquality
    yum install -y faillock
    yum install -y sudo
    yum install -y firefox
    yum install -y e2fsprogs
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
    cat configs/adduser.conf > /etc/default/useradd
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
    echo 'root:$Be@ch5Sun!L0ng3rPass' | chpasswd;
    passwd -l root;
    echo "change all user passwords"
    for user in $(cat users.txt); do
        passwd -x 85 $user > /dev/null;
        passwd -n 15 $user > /dev/null;
        echo $user:'$Be@ch5Sun!L0ng3rPass' | chpasswd;
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
    cp configs/login.defs /etc/login.defs
    cp configs/limits.conf /etc/security/limits.conf
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
    ports=(20 21 22 23 25 53 67 68 69 80 110 123 137 138 139 143 443 445 873 902 993 995 3389 6566 6660 6661 6662 6663 6664 6665 6666 6667 6668 6669 6679 6697 7000 8000 8008 8080 8081 8082 8088 8443 8888)
    for port in "${ports[@]}"; do
        firewall-cmd --permanent --add-port=$port/tcp
        firewall-cmd --permanent --add-port=$port/udp
    done
    firewall-cmd --reload
}

services(){
    echo "Configuring firewall services"
    services=("ftp" "telnet" "ssh" "smtp" "dns" "dhcp" "tftp" "http" "pop3" "ntp" "imap" "https" "microsoft-ds" "rsync" "vnc-server" "mysql" "postgresql" "samba" "squid" "libvirt" "kadmin")
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
    setUmask
    configSelinux
    auditLogs
    cronJobs
    setNTP
    grubChanges
    motdBanner
    cupsd
}

denyRootSSH(){
    echo "Denying root SSH access"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

setUmask(){
    echo "Setting UMASK"
    echo "umask 027" >> /etc/bashrc
    echo "umask 027" >> /etc/profile
}

configSelinux(){
    echo "Configuring SELinux"
    setenforce 1
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
}

auditLogs(){
    echo "Setting up audit logs"
    yum install -y audit
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
    yum install -y chrony
    systemctl start chronyd
    systemctl enable chronyd
    cp configs/chrony.conf /etc/chrony.conf
    systemctl restart chronyd
}

grubChanges(){
    echo "Configuring GRUB"
    cp configs/grub /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

motdBanner(){
    echo "Setting up MOTD and issue banner"
    cp configs/motd /etc/motd
    cp configs/issue /etc/issue
    cp configs/issue.net /etc/issue.net
}

cupsd(){
    echo "Disabling CUPS"
    systemctl stop cups
    systemctl disable cups
}

checkPackages(){
    echo "Checking and removing unnecessary packages"
    yum remove -y xinetd ypserv tftp tftp-server talk telnet-server rsh-server rsh ypbind
}

filePriv(){
    echo "Setting file permissions"
    chmod 640 /etc/passwd
    chmod 640 /etc/shadow
    chmod 640 /etc/group
    chmod 640 /etc/gshadow
    chmod 750 /root
    chmod 640 /var/log/btmp
    chmod 640 /var/log/wtmp
    chmod 640 /var/log/lastlog
}

comparison(){
    echo "Performing file comparisons"
    diff /etc/passwd.orig /etc/passwd
    diff /etc/group.orig /etc/group
    diff /etc/shadow.orig /etc/shadow
}

mediaFiles(){
    echo "Searching for media files"
    find / -name "*.mp3" -exec rm -f {} \;
    find / -name "*.mp4" -exec rm -f {} \;
    find / -name "*.avi" -exec rm -f {} \;
    find / -name "*.mov" -exec rm -f {} \;
    find / -name "*.jpg" -exec rm -f {} \;
    find / -name "*.jpeg" -exec rm -f {} \;
    find / -name "*.png" -exec rm -f {} \;
    find / -name "*.gif" -exec rm -f {} \;
}

lastMinuteChecks(){
    echo "Performing last minute checks"
    getent passwd | awk -F: '$3 > 999 { print $1 }' | while read user; do
        if ! grep -q "^$user$" users.txt && ! grep -q "^$user$" admins.txt; then
            echo "Warning: User $user exists but is not in users.txt or admins.txt"
        fi
    done

    getent group | awk -F: '$3 > 999 { print $1 }' | while read group; do
        if ! grep -q "^$group$" groups.txt; then
            echo "Warning: Group $group exists but is not in groups.txt"
        fi
    done
}

unleashHell
