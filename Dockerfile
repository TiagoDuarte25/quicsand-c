#----------------------MSQUIC---------------------#
# Use an official lightweight Alpine image with glibc compatibility as a parent image
#FROM ghcr.io/rikorose/gcc-cmake:latest

# Set the working directory in the container to /app
#WORKDIR /app

#Copy sources of the quic implementation
#COPY implementations/msquic /app/msquic

#Install basic build tools
#RUN apt-get update && apt-get install -y g++ make libc6-dev dpkg-dev
#Install additional packages for quic version
#RUN apt-get install -y liblttng-ust-dev lttng-tools

#RUN cd msquic && mkdir build
#RUN cd /app/msquic/build && cmake -G 'Unix Makefiles' .. && cmake --build . && cmake --install .

#-------------------------------------------------#

#----------------------LSQUIC---------------------#

FROM ubuntu:20.04 as build-lsquic

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y apt-utils build-essential git cmake software-properties-common \
    zlib1g-dev libevent-dev

RUN add-apt-repository ppa:longsleep/golang-backports && \
    apt-get update && \
    apt-get install -y golang-1.21-go && \
    cp /usr/lib/go-1.21/bin/go* /usr/bin/.

ENV GOROOT /usr/lib/go-1.21

RUN mkdir /app
WORKDIR /app

RUN mkdir /app/lsquic
COPY ./ /app/lsquic/

RUN git clone https://github.com/google/boringssl.git && \
    cd boringssl && \
    git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd && \
    cmake . && \
    make

ENV EXTRA_CFLAGS -DLSQUIC_QIR=1
RUN cd /app/lsquic && \
    cmake -DBORINGSSL_DIR=/src/boringssl . && \
    make

#-------------------------------------------------#

# Copy the client binary into the container
COPY quicsand /app/quicsand

#Install package for binaries
RUN apt-get install -y libyaml-dev

# Make the client binary executable
RUN cd /app/quicsand && make clean && make all 

# Run the client binary when the container launches
CMD ["/bin/bash"]
