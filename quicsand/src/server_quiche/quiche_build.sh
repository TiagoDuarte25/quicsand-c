#!/bin/bash

# Install basic build tools
apt-get update && apt-get install -y gcc g++ make libc6-dev dpkg-dev cmake git

# Install additional packages for quic version
apt-get install -y liblttng-ust-dev lttng-tools

# Install package for binaries
apt-get install -y libyaml-dev 

apt-get install -y libc6-dev-i386 libbpf-dev libnl-3-dev

# Install additional packages for xdp-tools
apt-get install -y pkg-config llvm clang m4 libpcap-dev

mkdir -p /tools
cd /tools
git clone https://github.com/xdp-project/xdp-tools.git
cd xdp-tools
make install

cp /usr/local/include/xdp/* /usr/include/

# Change working directory
cd /app

echo "Building $1"

cmake -S . -B build -DIMPL=$1

cd build

make

cp /app/quicsand/config.yaml /app/build/config.yaml

cp /app/quicsand/certs/ /app/build/certs/ -r
