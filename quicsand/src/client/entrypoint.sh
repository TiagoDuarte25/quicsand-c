#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting client container...'

server_ip=$(getent hosts server | awk '{ print $1 }')

echo "Server IP address: $server_ip"

trap 'exit 0' INT

sleep 2

echo $1 >> /tmp/log

echo "Launched!"
#host=$(hostname)
#n=$((${#host}-1))
host_id="$2"

#obtain the service identifier
service="$1-$KOLLAPS_UUID"

echo ID $host_id >> /tmp/log
echo Service $service >> /tmp/log

#find out the IP of the servers through the experiment UUID 
#nth client should connect to nth server
server_ip_k=$(host $service | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | sed -n "${host_id}p")
echo SERVER_IP $server_ip_k >> /tmp/log

# # port plus the host id
# port=$((4567 + $host_id))
# echo PORT $port >> /tmp/log

sleep 2

# Start a shell to keep the container running
./bin/client -i "$server_ip_k" -p 4567