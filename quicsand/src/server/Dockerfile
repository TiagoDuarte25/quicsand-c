# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ubuntu:latest

ARG IMPLEMENTATION
ENV DEBIAN_FRONTEND=noninteractive
ENV IMPLEMENTATION=msquic
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/build/implementations/msquic/build/bin/Release/

COPY implementations /app/implementations
COPY quicsand /app/quicsand
COPY CMakeLists.txt /app/CMakeLists.txt
COPY resources/testing_files /app/resources/testing_files

RUN apt update

RUN apt install -y bash gcc g++ make libc6-dev dpkg-dev cmake git liblttng-ust-dev lttng-tools

RUN apt install -y libyaml-dev libc6-dev-i386 libbpf-dev libnl-3-dev pkg-config llvm clang m4 libpcap-dev

RUN apt install -y libnuma-dev

# Create the /tools directory
RUN mkdir -p /tools

# Clone the Git repository
RUN git clone https://github.com/xdp-project/xdp-tools.git /tools/xdp-tools

# Set the working directory
WORKDIR /tools/xdp-tools

# Build and install the tools
RUN make install

RUN apt update && apt install bind9 bind9utils bind9-doc dnsutils -y

# Copy xdp headers to /usr/include
RUN cp /usr/local/include/xdp/* /usr/include/

WORKDIR /app

# building the implementation
RUN cmake -S . -B build -DIMPL=$IMPLEMENTATION

WORKDIR /app/build

RUN make

RUN cp /app/quicsand/config.yaml /app/build/config.yaml

RUN cp /app/quicsand/certs/ /app/build/certs/ -r

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/app/quicsand/src/server/entrypoint.sh"]