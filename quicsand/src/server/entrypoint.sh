#!/bin/bash

# Run build.sh in the background, redirecting output to /dev/null
echo 'Starting server container...'
#/app/quicsand/src/server/build.sh >/dev/null 2>&1
/app/quicsand/src/server/build.sh msquic

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

# Start server
./bin/server