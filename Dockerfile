# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ghcr.io/rikorose/gcc-cmake:latest

# Set the working directory in the container to /app
WORKDIR /app

#Copy sources of the quic implementation
COPY implementations/msquic /app/msquic

#Install basic build tools
RUN apt-get update && apt-get install -y g++ make libc6-dev dpkg-dev
#Install additional packages for quic version
RUN apt-get install -y liblttng-ust-dev lttng-tools

#RUN cd msquic && mkdir build
#RUN cd /app/msquic/build && cmake -G 'Unix Makefiles' .. && cmake --build . && cmake --install .

# Copy the client binary into the container
COPY quicsand /app/quicsand

#Install package for binaries
RUN apt-get install -y libyaml-dev

# Make the client binary executable
RUN cd /app/quicsand && make clean && make all 

# Run the client binary when the container launches
CMD ["/bin/bash"]
