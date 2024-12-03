# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ubuntu:latest

ARG IMPLEMENTATION
ENV IMPLEMENTATION=$IMPLEMENTATION
ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/msquic/build/bin/Release/

# COPY implementations /app/implementations
# COPY implementations/libev /app/implementations/libev
# COPY implementations/C-Thread-Pool /app/implementations/C-Thread-Pool
COPY quicsand /app/quicsand
COPY CMakeLists.txt /app/CMakeLists.txt
COPY resources/testing_files /app/resources/testing_files

# Common dependencies
RUN apt update && \
    apt install -y bash gcc g++ make libc6-dev dpkg-dev cmake git liblttng-ust-dev lttng-tools && \
    apt install -y libyaml-dev libc6-dev-i386 libbpf-dev libnl-3-dev pkg-config llvm clang m4 libpcap-dev && \
    apt install -y libnuma-dev software-properties-common wget libglib2.0-dev rustc cargo

# Download the Microsoft repository GPG keys
# RUN wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# # Register the Microsoft repository GPG keys
# RUN dpkg -i packages-microsoft-prod.deb

# # Enable the "universe" repositories
# RUN add-arepository universe

# # Install PowerShell
# RUN apt install -y powershell

# # Create the /tools directory
# RUN mkdir -p /tools

# # Clone the Git repository
# RUN git clone https://github.com/xdp-project/xdp-tools.git /tools/xdp-tools

# # Set the working directory
# WORKDIR /tools/xdp-tools

# # Build and install the tools
# RUN make install

# # Copy xdp headers to /usr/include
# RUN cp /usr/local/include/xdp/* /usr/include/

# Add Golang backports repository and install Golang
RUN add-apt-repository -y ppa:longsleep/golang-backports && \
    apt update && \
    apt install -y golang-1.21-go && \
    cp /usr/lib/go-1.21/bin/go* /usr/bin/.

# Set GOROOT environment variable
ENV GOROOT=/usr/lib/go-1.21

# Install DNS utilities
RUN apt update && apt install -y bind9 bind9utils bind9-doc dnsutils

WORKDIR /app

# building the implementation
RUN cmake -S . -B build -DIMPL=$IMPLEMENTATION

WORKDIR /app/build

RUN make

RUN cp /app/quicsand/config.yaml /app/build/config.yaml

RUN cp /app/quicsand/certs/ /app/build/certs/ -r

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/app/quicsand/src/client/entrypoint.sh"]