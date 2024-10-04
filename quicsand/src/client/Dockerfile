# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ubuntu:latest

ARG IMPLEMENTATION
ENV DEBIAN_FRONTEND=noninteractive
ENV IMPLEMENTATION=msquic
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

# COPY implementations /app/implementations
COPY implementations/libev /app/implementations/libev
COPY implementations/C-Thread-Pool /app/implementations/C-Thread-Pool
COPY quicsand /app/quicsand
COPY CMakeLists.txt /app/CMakeLists.txt
COPY resources/testing_files /app/resources/testing_files

ARG IMPLEMENTATION
ENV IMPLEMENTATION=$IMPLEMENTATION

# Common dependencies
RUN apt update && \
    apt install -y bash gcc g++ make libc6-dev dpkg-dev cmake git liblttng-ust-dev lttng-tools && \
    apt install -y libyaml-dev libc6-dev-i386 libbpf-dev libnl-3-dev pkg-config llvm clang m4 libpcap-dev && \
    apt install -y libnuma-dev software-properties-common

# Create the /tools directory
RUN mkdir -p /tools

# Clone the Git repository
RUN git clone https://github.com/xdp-project/xdp-tools.git /tools/xdp-tools

# Set the working directory
WORKDIR /tools/xdp-tools

# Build and install the tools
RUN make install

# Copy xdp headers to /usr/include
RUN cp /usr/local/include/xdp/* /usr/include/

# Add Golang backports repository and install Golang
RUN add-apt-repository -y ppa:longsleep/golang-backports && \
    apt update && \
    apt install -y golang-1.21-go && \
    cp /usr/lib/go-1.21/bin/go* /usr/bin/.

# Set GOROOT environment variable
ENV GOROOT=/usr/lib/go-1.21

# Conditional installation based on implementation
RUN if [ "$IMPLEMENTATION" = "msquic" ]; then \
        echo "Building msquic implementation..."; \
        # Add msquic specific build steps here
        # Example:
        mkdir -p /app/implementations && \
        cd /app/implementations && \
        git clone https://github.com/microsoft/msquic.git && \
        cd msquic && \
        git submodule update --init --recursive; \
    elif [ "$IMPLEMENTATION" = "lsquic" ]; then \
        echo "Building lsquic implementation..."; \
        # Clone and build BoringSSL
        mkdir -p /app/implementations && \
        cd /app/implementations && \
        git clone https://github.com/google/boringssl.git && \
        cd boringssl && \
        git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd && \
        cmake . && \
        make; \
    else \
        echo "Unknown implementation: $IMPLEMENTATION"; \
        exit 1; \
    fi

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