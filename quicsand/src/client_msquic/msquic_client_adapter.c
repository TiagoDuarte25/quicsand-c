#ifdef _WIN32
//
// The conformant preprocessor along with the newest SDK throws this warning for
// a macro in C mode. As users might run into this exact bug, exclude this
// warning here. This is not an MsQuic bug but a Windows SDK bug.
//
#pragma warning(disable : 5105)
#endif

#include "quicsand_client_adapter.h"
#include "msquic.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

int connected = 0;
int streamStarted = 0;

struct context
{
    QUIC_API_TABLE *MsQuic;

    QUIC_REGISTRATION_CONFIG RegConfig;
    QUIC_BUFFER Alpn;
    uint64_t IdleTimeoutMs;
    HQUIC Registration;
    HQUIC Configuration;
    HQUIC Connection;
    HQUIC Stream;

    char *Host;
    char *Port;
    size_t reqsize;

    struct Buffer
    {
        QUIC_BUFFER *QUICBuffer;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
    } *recvBuffer;
};

// Function to generate random hexadecimal string
char *generate_hex_string(size_t size)
{
    // Allocate memory for the output string
    // Each byte will be represented by 2 hexadecimal characters + 1 for null terminator
    char *hex_string = malloc(size * 2 + 1);
    if (hex_string == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    // Generate random bytes and convert them to hexadecimal format
    for (size_t i = 0; i < size; ++i)
    {
        unsigned char byte = rand() % 256;         // Generate a random byte
        sprintf(hex_string + i * 2, "%02x", byte); // Convert byte to hex and store in the string
    }

    // Null-terminate the string
    hex_string[size * 2] = '\0';

    return hex_string;
}

void receive_data(Client_CTX ctx)
{
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    pthread_mutex_lock(&client_ctx->recvBuffer->mutex);
    while (client_ctx->recvBuffer->QUICBuffer->Length == 0)
    {
        printf("Waiting for data...\n");
        pthread_cond_wait(&client_ctx->recvBuffer->cond, &client_ctx->recvBuffer->mutex);
    }
    printf("Leave while loop with Length = %d\n", client_ctx->recvBuffer->QUICBuffer->Length);
    pthread_mutex_unlock(&client_ctx->recvBuffer->mutex);
}

void close_stream(Client_CTX ctx)
{
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    client_ctx->MsQuic->StreamClose((HQUIC)client_ctx->Stream);
}

void close_connection(Client_CTX ctx)
{
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    client_ctx->MsQuic->ConnectionClose((HQUIC)client_ctx->Connection);
}

void send_data(Client_CTX ctx, int *reqsize)
{
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    QUIC_STATUS status;
    HQUIC Stream = (HQUIC)client_ctx->Stream;
    uint8_t *SendBufferRaw;
    QUIC_BUFFER *SendBuffer;

    //
    // Allocates and builds the buffer to send over the stream.
    //
    char *data = generate_hex_string(client_ctx->reqsize);
    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + sizeof(data));
    if (SendBufferRaw == NULL)
    {
        printf("SendBuffer allocation failed!\n");
        status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    size_t data_len = strlen(data);
    SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = data;
    SendBuffer->Length = (uint32_t)data_len;

    printf("[strm][%p] Sending data...\n", (void *)Stream);
    printf("Data to send: %s\n", SendBuffer->Buffer);
    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(status = client_ctx->MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer)))
    {
        printf("StreamSend failed, 0x%x!\n", status);
        free(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(status))
    {
        client_ctx->MsQuic->StreamClose(Stream);
        client_ctx->MsQuic->ConnectionShutdown(client_ctx->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
        QUIC_STATUS
    QUIC_API
    client_stream_callback(
        _In_ HQUIC Stream,
        _In_opt_ void *Context,
        _Inout_ QUIC_STREAM_EVENT *Event)
{
    struct client_ctx *client_ctx = (struct client_ctx *)Context;
    switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        //
        // The start process for the stream has completed.
        //
        printf("[strm][%p] Started\n", (void *)Stream);
        streamStarted = 1;
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", (void *)Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
    {
        printf("[strm][%p] Receiving data...\n", (void *)Stream);
        //
        // Data was received from the peer on the stream.
        //
        // Process data from ReceiveData->Buffers and store it in destinationBuffer
        size_t totalSize = 0;
        pthread_mutex_lock(&client_ctx->recvBuffer->mutex);
        client_ctx->recvBuffer->QUICBuffer->Length = Event->RECEIVE.TotalBufferLength;
        printf("Total buffer length: %d\n", Event->RECEIVE.TotalBufferLength);
        printf("Receive Buffer Count: %d\n", Event->RECEIVE.BufferCount);
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i)
        {
            printf("Received data: %s\n", Event->RECEIVE.Buffers[i].Buffer);
            // Copy data from ReceiveData->Buffers[i].Buffer to destinationBuffer
            client_ctx->recvBuffer->QUICBuffer->Buffer = Event->RECEIVE.Buffers[i].Buffer;
            client_ctx->recvBuffer->QUICBuffer->Length = Event->RECEIVE.Buffers[i].Length;
            totalSize += Event->RECEIVE.Buffers[i].Length;
        }
        printf("Data received: %s\n", client_ctx->recvBuffer->QUICBuffer->Buffer);
        pthread_cond_signal(&client_ctx->recvBuffer->cond);
        printf("Signaled\n");
        pthread_mutex_unlock(&client_ctx->recvBuffer->mutex);
        printf("[strm][%p] Data received\n", (void *)Stream);
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", (void *)Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", (void *)Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", (void *)Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            client_ctx->MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void open_stream(Client_CTX ctx)
{
    QUIC_STATUS status;
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    HQUIC conn = client_ctx->Connection;
    HQUIC stream = NULL;
    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (QUIC_FAILED(status = client_ctx->MsQuic->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_callback, ctx, &stream)))
    {
        printf("StreamOpen failed, 0x%x!\n", status);
        goto Error;
    }
    printf("[strm][%p] Starting...\n", (void *)stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(status = client_ctx->MsQuic->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE)))
    {
        printf("StreamStart failed, 0x%x!\n", status);
        client_ctx->MsQuic->StreamClose(stream);
        goto Error;
    }

    while (!streamStarted)
    {
        // Wait for stream to be started
    }
    streamStarted = 0;

    client_ctx->Stream = stream;

Error:

    if (QUIC_FAILED(status))
    {
        client_ctx->MsQuic->ConnectionShutdown(conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        exit(EXIT_FAILURE);
    }
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
        QUIC_STATUS
    QUIC_API
    client_connection_callback(
        _In_ HQUIC Connection,
        _In_opt_ void *Context,
        _Inout_ QUIC_CONNECTION_EVENT *Event)
{
    struct client_ctx *client_ctx = (struct client_ctx *)Context;
    switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", (void *)Connection);
        connected = 1;
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
        {
            printf("[conn][%p] Successfully shut down on idle.\n", (void *)Connection);
        }
        else
        {
            printf("[conn][%p] Shut down by transport, 0x%x\n", (void *)Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", (void *)Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", (void *)Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
        {
            client_ctx->MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", (void *)Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
        {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void open_connection(Client_CTX ctx)
{
    printf("open_connection called\n");

    QUIC_STATUS status;

    if (ctx == NULL)
    {
        printf("Context is not initialized!\n");
        return;
    }

    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    if (QUIC_FAILED(status = client_ctx->MsQuic->ConnectionOpen(client_ctx->Registration, client_connection_callback, client_ctx, &client_ctx->Connection)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", status);
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", (void *)client_ctx->Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(status = client_ctx->MsQuic->ConnectionStart(client_ctx->Connection, client_ctx->Configuration, QUIC_ADDRESS_FAMILY_INET, client_ctx->Host, (uint16_t)atoi(client_ctx->Port))))
    {
        printf("ConnectionStart failed, 0x%x!\n", status);
        goto Error;
    }

    printf("[conn][%p] Started\n", (void *)client_ctx->Connection);

    while (!connected)
    {
        // Wait for connection to be established
    }
    connected = 0;

Error:

    if (QUIC_FAILED(status) && client_ctx->Connection != NULL)
    {
        client_ctx->MsQuic->ConnectionClose(client_ctx->Connection);
    }
}

//
// Helper function to load a client configuration.
//
BOOLEAN
client_load_configuration(struct client_ctx *ctx, int unsecure)
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = ctx->IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (unsecure)
    {
        printf("Unsecure mode\n");
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = ctx->MsQuic->ConfigurationOpen(ctx->Registration, &ctx->Alpn, 1, &Settings, sizeof(Settings), NULL, &ctx->Configuration)))
    {
        printf("ConfigurationOpen failed, 0x%x!\n", status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(status = ctx->MsQuic->ConfigurationLoadCredential(ctx->Configuration, &CredConfig)))
    {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
        return FALSE;
    }
    return TRUE;
}

void client_shutdown(Client_CTX ctx)
{
    struct client_ctx *client_ctx = (struct client_ctx *)ctx;
    if (client_ctx->MsQuic != NULL)
    {
        if (client_ctx->Configuration != NULL)
        {
            client_ctx->MsQuic->ConfigurationClose(client_ctx->Configuration);
        }
        if (client_ctx->Registration != NULL)
        {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            client_ctx->MsQuic->RegistrationClose(client_ctx->Registration);
        }
        MsQuicClose(client_ctx->MsQuic);
    }
}

//
// Runs the client side of the protocol.
//
void client_init(Config *conf, Client_CTX *client_ctx, char *target_ip)
{
    printf("Starting client...\n");
    *client_ctx = malloc(sizeof(struct client_ctx));
    if (*client_ctx == NULL)
    {
        printf("Client context allocation failed!\n");
        // Handle memory allocation failure
        return;
    }
    struct client_ctx *ctx = (struct client_ctx *)*client_ctx;
    ctx->MsQuic = NULL;
    ctx->Registration = NULL;
    ctx->Configuration = NULL;
    ctx->Connection = NULL;
    ctx->Stream = NULL;
    ctx->Host = target_ip;
    ctx->Port = conf->port;
    ctx->reqsize = (size_t)conf->reqsize;
    ctx->recvBuffer = NULL;
    ctx->RegConfig = (QUIC_REGISTRATION_CONFIG){"quicsand", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    ctx->Alpn = (QUIC_BUFFER){sizeof("quicsand") - 1, (uint8_t *)"quicsand"};
    ctx->IdleTimeoutMs = 1000;

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(status = MsQuicOpen2(&ctx->MsQuic)))
    {
        printf("MsQuicOpen2 failed, 0x%x!\n", status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(status = ctx->MsQuic->RegistrationOpen(&ctx->RegConfig, &ctx->Registration)))
    {
        printf("RegistrationOpen failed, 0x%x!\n", status);
        goto Error;
    }
    printf("Registration value: %p\n", ctx->Registration);
    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    if (!client_load_configuration(ctx, conf->unsecure))
    {
        goto Error;
    }
    printf("Client initialized\n");

    // Ensure recvBuffer is initialized
    ctx->recvBuffer = malloc(sizeof(*ctx->recvBuffer));
    if (ctx->recvBuffer == NULL)
    {
        printf("recvBuffer allocation failed!\n");
        // Handle memory allocation failure
        goto Error;
    }

    // Allocate memory for the destination buffer
    ctx->recvBuffer->QUICBuffer = NULL;

    if ((ctx->recvBuffer->QUICBuffer = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER))) == NULL)
    {
        printf("recvBuffer->QUICBuffer allocation failed!\n");
        // Handle memory allocation failure
        goto Error;
    }
    ctx->recvBuffer->QUICBuffer->Length = 0;
    pthread_mutex_init(&ctx->recvBuffer->mutex, NULL);
    pthread_cond_init(&ctx->recvBuffer->cond, NULL);

    printf("recvBuffer allocated\n");

    return;
Error:

    if (ctx->MsQuic != NULL)
    {
        if (ctx->Configuration != NULL)
        {
            ctx->MsQuic->ConfigurationClose(ctx->Configuration);
        }
        if (ctx->Registration != NULL)
        {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            ctx->MsQuic->RegistrationClose(ctx->Registration);
        }
        MsQuicClose(ctx->MsQuic);
    }
}