#!/bin/bash

echo "Entrypoint script started" >> /tmp/log
echo "Number of arguments: $#" >> /tmp/log

# check if there are any arguments
if [ "$#" -eq 0 ]; then
    echo 'Starting server container...' >> /tmp/log

    ./bin/quicsand_server -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i "0.0.0.0" -p 4567

else
    echo 'Starting client container...' >> /tmp/log

    trap 'exit 0' INT

    sleep 2
   
    echo "${*: -2}" >> /tmp/log

    echo "Launched!" >> /tmp/log
    host_id="${*: -1}"

    #obtain the service identifier
    service="${*: -2:1}-$KOLLAPS_UUID"

    echo ID $host_id >> /tmp/log
    echo Service $service >> /tmp/log

    #find out the IP of the servers through the experiment UUID 
    server_ip_k=$(host $service | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | sed -n "${host_id}p")
    echo SERVER_IP $server_ip_k >> /tmp/log
    sleep 2

    ./bin/quicsand_client -i "$server_ip_k" -p 4567 -f "/app/resources/testing_files/file.txt"
fi