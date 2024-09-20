#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting server container...'
#/app/quicsand/src/server/build.sh >/dev/null 2>&1
# /app/quicsand/src/server/build.sh msquic

# cmake -S . -B build -DIMPL=$1

# cd build

# make

# cp /app/quicsand/config.yaml /app/build/config.yaml

# cp /app/quicsand/certs/ /app/build/certs/ -r

# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

server_ip=$(getent hosts server | awk '{ print $1 }')

echo "Server IP address: $server_ip"

# Start server
./bin/server -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i "0.0.0.0" -p 4567