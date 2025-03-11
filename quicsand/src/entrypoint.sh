#!/bin/bash

echo "Entrypoint script started"
echo "Number of arguments: $#"
echo "Test: $TEST"

# Load the tests file
TESTS=$(yq '.tests' /app/tests.yaml)

TEST_TYPE=$(echo "$TESTS" | yq ".${TEST}.type" - | tr -d '"')
DURATION=$(echo "$TESTS" | yq ".${TEST}.duration" - | tr -d '"')
DATA_SIZE=$(echo "$TESTS" | yq ".${TEST}.data_size" - | tr -d '"')
FILE_PATH=$(echo "$TESTS" | yq ".${TEST}.file_path" - | tr -d '"')
FACTOR=$(echo "$TESTS" | yq ".${TEST}.factor" - | tr -d '"')
BITRATE=$(echo "$TESTS" | yq ".${TEST}.bitrate" - | tr -d '"')

echo "Test type: $TEST_TYPE"
echo "Duration: $DURATION"
echo "Data size: $DATA_SIZE"
echo "File path: $FILE_PATH"
echo "Factor: $FACTOR"
echo "Bitrate: $BITRATE"

# check if there are any arguments
if [ "$#" -eq 0 ]; then
    echo 'Starting server container...' >> /tmp/log

    SERVER_LOG="server.log"

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
    echo 'Starting client container...'

    trap 'exit 0' INT

    echo "Container to connect to: $1"

    # Read the test name and container name
    SERVER_IP="$1"
    CONTAINER_NAME="$2"

    echo "Server IP: $SERVER_IP"
    echo "Test type: $TEST_TYPE"
    echo "Duration: $DURATION"
    echo "Data size: $DATA_SIZE"
    echo "File path: $FILE_PATH"
    echo "Factor: $FACTOR"
    echo "Bitrate: $BITRATE"

    CLIENT_LOG="client.log"
    
    case $TEST_TYPE in
        request-response)
            echo "starting request-response client..." >> /tmp/log
            ./bin/quicsand_client_rr -i "$SERVER_IP" -p 4567 -d $DURATION -s $DATA_SIZE -l $CLIENT_LOG
            ;;
        streaming)
            echo "starting streaming client..." >> /tmp/log
            ./bin/quicsand_client_streaming -i "$SERVER_IP" -p 4567 -d $DURATION -b $BITRATE -l $CLIENT_LOG
            ;;
        upload)
            echo "starting upload client..." >> /tmp/log
            ./bin/quicsand_client_upload -i "$SERVER_IP" -p 4567 -f $FILE_PATH -l $CLIENT_LOG
            ;;
        download)
            echo "starting download client..." >> /tmp/log
            ./bin/quicsand_client_download -i "$SERVER_IP" -p 4567 -f $FILE_PATH -l $CLIENT_LOG
            ;;
        *)
            echo "Error: Unknown test type $TEST_TYPE"
            return
            ;;
    esac

    echo "Client finished"

    mkdir -p /result

    # Check if client.csv exists before copying
    if [ -f client.csv ]; then
        cp client.csv /result/$CONTAINER_NAME.csv
    else
        echo "Error: client.csv not found."
        exit 1
    fi
fi