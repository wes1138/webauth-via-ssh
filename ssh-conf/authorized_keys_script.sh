#!/bin/bash

read -t1 KEY

database='/home/wes/repos/projects/webauth-ssh/ssh-conf/db-of-keys'
# lines in our flat file are just like openssh authorized_keys.  So there's
# the type, then the key, then a comment, which we use as the username.
user=""
while read line; do
	IFS=' ' read -a row <<< "$line"
	if [[ $KEY == ${row[0]}" "${row[1]} ]]; then
		user=${row[2]}
		break
	fi
done < $database

# normally, we would want to do:
# [[ -z $user ]] && exit 1
# but for the fake test app:
if [[ -z $user ]]; then
	# add user to database with fabricated userid.
	user="user"$(md5sum <<<"$KEY" | head -c 16)
	# yes, I realize this is ridiculous.  It's just a test.
	echo $KEY $user >> $database
fi

echo -n "command=\"/tmp/token-gen -u '$user'\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty"
exit 0
