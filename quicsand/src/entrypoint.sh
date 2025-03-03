#!/bin/bash

echo "Entrypoint script started" >> /tmp/log
echo "Number of arguments: $#" >> /tmp/log
echo "Test: $TEST" >> /tmp/log

# Load the tests file
TESTS=$(yq '.tests' /app/tests.yaml)

TEST_TYPE=$(echo "$TESTS" | yq ".${TEST}.type" - | tr -d '"')
DURATION=$(echo "$TESTS" | yq ".${TEST}.duration" - | tr -d '"')
DATA_SIZE=$(echo "$TESTS" | yq ".${TEST}.data_size" - | tr -d '"')
FILE_PATH=$(echo "$TESTS" | yq ".${TEST}.file_path" - | tr -d '"')
FACTOR=$(echo "$TESTS" | yq ".${TEST}.factor" - | tr -d '"')
BITRATE=$(echo "$TESTS" | yq ".${TEST}.bitrate" - | tr -d '"')

# check if there are any arguments
if [ "$#" -eq 0 ]; then
    echo 'Starting server container...' >> /tmp/log

    SERVER_LOG="server.log"

    # Start the server in a new tmux window
    case $TEST_TYPE in
        request-response)
            echo "starting request-response server..." >> /tmp/log
            ./bin/quicsand_server_rr -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i 0.0.0.0 -p 4567 -l $SERVER_LOG -m $FACTOR
            ;;
        streaming)
            echo "starting streaming server..." >> /tmp/log
            ./bin/quicsand_server_streaming -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i 0.0.0.0 -p 4567 -d $DURATION -l $SERVER_LOG
            ;;
        upload)
            echo "starting upload server..." >> /tmp/log
            ./bin/quicsand_server_upload -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i 0.0.0.0 -p 4567 -l $SERVER_LOG -t $TEST
            ;;
        download)
            echo "starting download server..." >> /tmp/log
            ./bin/quicsand_server_download -c /app/quicsand/certs/quicsand-server.pem -k /app/quicsand/certs/key.pem -i 0.0.0.0 -p 4567 -l $SERVER_LOG
            ;;
        *)
            echo "Error: Unknown test type $TEST_TYPE" >> /tmp/log
            ;;
    esac
else
    echo 'Starting client container...' >> /tmp/log

    trap 'exit 0' INT
   
    echo "${*: -2}" >> /tmp/log

    echo "Launched!" >> /tmp/log
    host_id="${*: -1}"

    echo "Test: $1" >> /tmp/log

    #obtain the service identifier
    service="${*: -2:1}-$KOLLAPS_UUID"

    echo ID $host_id >> /tmp/log
    echo Service $service >> /tmp/log

    #find out the IP of the servers through the experiment UUID 
    server_ip_k=$(host $service | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | sed -n "${host_id}p")
    echo SERVER_IP $server_ip_k >> /tmp/log

    CLIENT_LOG="client.log"
    
    case $TEST_TYPE in
        request-response)
            echo "starting request-response client..." >> /tmp/log
            ./bin/quicsand_client_rr -i "$server_ip_k" -p 4567 -d $DURATION -s $DATA_SIZE -l $CLIENT_LOG
            ;;
        streaming)
            echo "starting streaming client..." >> /tmp/log
            ./bin/quicsand_client_streaming -i "$server_ip_k" -p 4567 -d $DURATION -b $BITRATE -l $CLIENT_LOG
            ;;
        upload)
            echo "starting upload client..." >> /tmp/log
            ./bin/quicsand_client_upload -i "$server_ip_k" -p 4567 -f $FILE_PATH -l $CLIENT_LOG
            ;;
        download)
            echo "starting download client..." >> /tmp/log
            ./bin/quicsand_client_download -i "$server_ip_k" -p 4567 -f $FILE_PATH -l $CLIENT_LOG
            ;;
        *)
            echo "Error: Unknown test type $TEST_TYPE" >> /tmp/log
            return
            ;;
    esac

    echo "Client finished" >> /tmp/log
fi