#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting client container...'
#/app/quicsand/src/client/build.sh >/dev/null 2>&1
/app/quicsand/src/client/build.sh $1

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

server_ip=$(getent hosts server | awk '{ print $1 }')

echo "----"
echo "Server IP address: $server_ip"
echo "----"

# Start a shell to keep the container running
./bin/client $server_ip