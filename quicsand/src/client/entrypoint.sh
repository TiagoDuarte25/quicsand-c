#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting client container...'
#/app/quicsand/src/client/build.sh >/dev/null 2>&1
# /app/quicsand/src/client/build.sh msquic

# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

# cmake -S . -B build -DIMPL=msquic

# cd build

# make

# cp /app/quicsand/config.yaml /app/build/config.yaml

# cp /app/quicsand/certs/ /app/build/certs/ -r

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
server_ip_k=$(host "$service" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | sed -n "${host_id}p")
echo SERVER_IP $server_ip_k >> /tmp/log

# Start a shell to keep the container running
./bin/client $server_ip_k