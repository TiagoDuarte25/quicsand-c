#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting server container...'
#/app/quicsand/src/server/build.sh >/dev/null 2>&1
/app/quicsand/src/server/build.sh

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/msquic/build/bin/Release/:/app/quicsand/lib

# Start server
./bin/server/server