# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM ubuntu:latest

ARG IMPLEMENTATION

ENV DEBIAN_FRONTEND noninteractive

# Copy msquic implementation into the container
COPY implementations/$IMPLEMENTATION /app/$IMPLEMENTATION

# Create the directory structure
RUN mkdir -p /app/quicsand/src/client
RUN mkdir -p /app/quicsand/include

# Copy the sources into the container
COPY quicsand/src/*.c /app/quicsand/src
COPY quicsand/src/client /app/quicsand/src/client
COPY quicsand/src/client_$IMPLEMENTATION/*.c /app/quicsand/src/client
COPY quicsand/config.yaml /app/quicsand
COPY quicsand/include /app/quicsand/include

# Copy the Makefile into the container
COPY quicsand/src/client/Makefile /app/Makefile

WORKDIR /app/quicsand

# Set the entrypoint
ENTRYPOINT ["/app/quicsand/src/client/entrypoint.sh"]