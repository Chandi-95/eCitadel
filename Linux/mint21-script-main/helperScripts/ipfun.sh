#!/bin/bash

set -e

. /lib/init/vars.sh
. /lib/lsb/init-functions

IPT="/sbin/iptables" 
INET_IFACE="ens33"
LO_IFACE="lo"
LO_IP="127.0.0.1"

echo 0 > /proc/sys/net/ipv4/ip_forward

([ -f /var/lock/subsys/ipchains ] && /etc/init.d/ipchains stop) >/dev/null 2>&1 || true
(rmmod ipchains) >/dev/null 2>&1 || true

/sbin/modprobe ip_tables
/sbin/modprobe ipt_state
/sbin/modprobe iptable_filter
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp

$IPT -F
$IPT -X
$IPT -Z
$IPT -t nat -F
$IPT -t nat -X
$IPT -t nat -Z
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t mangle -Z

case "$1" in
    stop|open|clear|reset)
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT    
    $IPT -A INPUT -j ACCEPT
    $IPT -A OUTPUT -j ACCEPT
    $IPT -A FORWARD -j ACCEPT
    exit 0
    ;;
esac
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

$IPT -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A INPUT -p all -m state --state INVALID -j DROP

$IPT -A OUTPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -p tcp ! --syn -m state --state NEW -j DROP
$IPT -A OUTPUT -p all -m state --state INVALID -j DROP

$IPT -A INPUT --fragment -p ICMP -j DROP

$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

$IPT -A INPUT -p all -i $LO_IFACE -j ACCEPT
$IPT -A OUTPUT -p all -o $LO_IFACE -j ACCEPT
$IPT -A OUTPUT -p all -s $LO_IP -j ACCEPT

# SSH
$IPT -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
$IPT -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j REJECT --reject-with tcp-reset
$IPT -A INPUT -p tcp --dport 22 -j ACCEPT


# SSH
$IPT -A OUTPUT -p tcp --dport 22 -j ACCEPT

$IPT -A INPUT -p tcp -m multiport --dports 80,443 -s 10.120.0.111 -j ACCEPT
$IPT -A OUTPUT -p tcp -m multiport --sports 80,443 -d 10.120.0.111 -j ACCEPT"

$IPT -A INPUT -j DROP
$IPT -A OUTPUT -j DROP
$IPT -A FORWARD -j DROP

$IPT -L -n
