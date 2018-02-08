#!/bin/bash

if [ $# != 3 ]; then
	cat << EOT

Usage: $0 TCP-Port Seconds IP-Address

This script manages an iptables chain in the filter table. Add something like

	iptables -N td2
	iptables -A INPUT -j td2
	iptables -A td2 --state ESTABLISHED,RELATED -j ACCEPT

to your network/firewalling start scripts and running this script will allow
new connections from the given IP address for the given number of seconds.

EOT
	exit 1
fi

/sbin/iptables -A td2 -s "$3" -p tcp --dport "$1" -j ACCEPT

(
	exec < /dev/null &> /dev/null; sleep "$2"
	/sbin/iptables -D td2 -s "$3" -p tcp --dport "$1" -j ACCEPT
) &

