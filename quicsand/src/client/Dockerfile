# Use an official lightweight Alpine image with glibc compatibility as a parent image
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

COPY implementations /app/implementations
COPY quicsand /app/quicsand
COPY CMakeLists.txt /app/CMakeLists.txt

RUN apt update && apt install bind9 bind9utils bind9-doc dnsutils -y

WORKDIR /app/build

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/app/quicsand/src/client/entrypoint.sh"]