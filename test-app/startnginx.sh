#!/bin/bash

# use local config file to run nginx as non-root user
# if $1 is 'stop' nginx will be shut down.
# if $1 is 'clean' all the temp files will be removed.

config=$(readlink -f ./nginx/nginx.conf)
fcgimain="main.fcgi"
if [[ $1 == 'stop' ]]; then
	nginx -c "$config" -s stop
	pkill -x "$fcgimain"
elif [[ $1 == 'clean' ]]; then
	[[ -f /tmp/nginx.pid ]] && \
		echo "nginx is still running. probably bad to rm its files." && \
		exit 1
	rm -r /tmp/nginx/
else
	mkdir -p /tmp/nginx/
	# spawn-fcgi -a127.0.0.1 -p9000 -n ./fcgi/$fcgimain &
	spawn-fcgi -s/tmp/fcgi-sock -n ./fcgi/$fcgimain &
	nginx -c "$config"
fi
