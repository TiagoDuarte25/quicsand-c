# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ubuntu:latest

ARG IMPLEMENTATION
ENV DEBIAN_FRONTEND=noninteractive
ENV IMPLEMENTATION=msquic

COPY implementations /app/implementations
COPY quicsand /app/quicsand
COPY CMakeLists.txt /app/CMakeLists.txt

RUN apt update && apt install bind9 bind9utils bind9-doc dnsutils -y

# # Copy msquic implementation into the container
# COPY implementations/$IMPLEMENTATION /app/$IMPLEMENTATION

# # Create the directory structure
# RUN mkdir -p /app/quicsand/src/client
# RUN mkdir -p /app/quicsand/include

# # Copy the sources into the container
# COPY quicsand/src/*.c /app/quicsand/src
# COPY quicsand/src/server /app/quicsand/src/server
# COPY quicsand/src/server_$IMPLEMENTATION/*.c /app/quicsand/src/server
# COPY quicsand/config.yaml /app/quicsand
# COPY quicsand/server.* /app/quicsand
# COPY quicsand/include /app/quicsand/include

# # Copy the Makefile into the container
# COPY quicsand/src/server/Makefile /app/Makefile

WORKDIR /app/build

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/app/quicsand/src/server/entrypoint.sh"]