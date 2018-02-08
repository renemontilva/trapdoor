#!/bin/sh

server=${1}
cookie=${2}

if [ -z "$server" ]; then
	echo "Usage: $0 server:port [cookie]"
	exit 1
fi

if [ -z "$cookie" ]; then
	read -rsp "Cookie: " cookie
	echo
fi

if curl -s -k -d c="$cookie" "https://$server/" | \
		grep -q 'Request Authenticated'
then
	echo "Request Authenticated"
	exit 0
else
	echo "Authentication failed"
	exit 1
fi

