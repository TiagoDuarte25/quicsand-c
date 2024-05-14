#!/bin/bash

# Update and install dependencies
apt-get update
apt-get install -y gcc apt-utils cmake build-essential git software-properties-common zlib1g-dev libevent-dev make

# Add Golang backports repository and install Golang
add-apt-repository -y ppa:longsleep/golang-backports
apt-get update
apt-get install -y golang-1.21-go
cp /usr/lib/go-1.21/bin/go* /usr/bin/.

# Install libyaml-dev package
apt-get install -y libyaml-dev

# Set GOROOT environment variable
export GOROOT=/usr/lib/go-1.21

# Clone and build BoringSSL
cd /app
git clone https://github.com/google/boringssl.git
cd boringssl
git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
cmake .
make

# Set extra CFLAGS
export EXTRA_CFLAGS=-DLSQUIC_QIR=1

# Build LSQUIC
#cd /app/lsquic
#cmake -DBORINGSSL_DIR=/app/boringssl .
#make

# Build LSQUIC using Makefile
#make IMPLEMENTATION=lsquic lsquic