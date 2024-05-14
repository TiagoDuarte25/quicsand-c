#!/bin/bash

# Install basic build tools
apt-get update && apt-get install -y gcc g++ make libc6-dev dpkg-dev cmake git

# Install additional packages for quic version
apt-get install -y liblttng-ust-dev lttng-tools

# Install package for binaries
apt-get install -y libyaml-dev

# Implementation pushed from git repo
#cd /app
#git clone --recurse-submodules --remote-submodules https://github.com/microsoft/msquic.git
#cd msquic
# Build msquic
#mkdir build
#cd build
#cmake -G 'Unix Makefiles' ..
#cmake --build .
#cmake --install .

# Change working directory
cd /app

make IMPLEMENTATION=msquic msquic
