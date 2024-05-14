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

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = {"quicsand", QUIC_EXECUTION_PROFILE_LOW_LATENCY};

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER Alpn = {sizeof("quicsand") - 1, (uint8_t *)"quicsand"};

//
// The default idle timeout period (1 second) used for the protocol.
//
const uint64_t IdleTimeoutMs = 1000;

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE *MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC configuration;

typedef struct Buffer
{
    QUIC_BUFFER *QUICBuffer;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} Buffer;

Buffer *recvBuffer;

int connected = 0;
int streamStarted = 0;

uint8_t
decode_hex_char(
    _In_ char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    return 0;
}

//
// Helper function to convert a string of hex characters to a byte buffer.
//
uint32_t
decode_hex_buffer(
    _In_z_ const char *HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t *OutBuffer)
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen)
    {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++)
    {
        OutBuffer[i] =
            (decode_hex_char(HexBuffer[i * 2]) << 4) |
            decode_hex_char(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

void receive_data()
{
    pthread_mutex_lock(&recvBuffer->mutex);
    while (recvBuffer->QUICBuffer->Length == 0)
    {
        printf("Waiting for data...\n");
        pthread_cond_wait(&recvBuffer->cond, &recvBuffer->mutex);
    }
    printf("Leave while loop with Length = %d\n", recvBuffer->QUICBuffer->Length);
    pthread_mutex_unlock(&recvBuffer->mutex);
}

void close_stream(Stream stream)
{
    MsQuic->StreamClose((HQUIC)stream);
}

void close_connection(Connection conn)
{
    MsQuic->ConnectionClose((HQUIC)conn);
}

void send_data(
    _In_ Connection connection, _In_ Stream stream, int *reqsize)
{
    QUIC_STATUS status;
    HQUIC Stream = (HQUIC)stream;
    uint8_t *SendBufferRaw;
    QUIC_BUFFER *SendBuffer;

    //
    // Allocates and builds the buffer to send over the stream.
    //
    char *data = "Client Request!";
    SendBufferRaw = (uint8_t *)malloc(sizeof(QUIC_BUFFER) + sizeof(data));
    if (SendBufferRaw == NULL)
    {
        printf("SendBuffer allocation failed!\n");
        status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    // uint16_t data_len = (uint16_t)decode_hex_char(data, sizeof(data), SendBufferRaw);
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
    if (QUIC_FAILED(status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer)))
    {
        printf("StreamSend failed, 0x%x!\n", status);
        free(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(status))
    {
        MsQuic->StreamClose(Stream);
        MsQuic->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
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
    UNREFERENCED_PARAMETER(Context);
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
        pthread_mutex_lock(&recvBuffer->mutex);
        recvBuffer->QUICBuffer->Length = Event->RECEIVE.TotalBufferLength;
        printf("Total buffer length: %d\n", Event->RECEIVE.TotalBufferLength);
        printf("Receive Buffer Count: %d\n", Event->RECEIVE.BufferCount);
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i)
        {
            printf("Received data: %s\n", Event->RECEIVE.Buffers[i].Buffer);
            // Copy data from ReceiveData->Buffers[i].Buffer to destinationBuffer
            recvBuffer->QUICBuffer->Buffer = Event->RECEIVE.Buffers[i].Buffer;
            recvBuffer->QUICBuffer->Length = Event->RECEIVE.Buffers[i].Length;
            totalSize += Event->RECEIVE.Buffers[i].Length;
        }
        printf("Data received: %s\n", recvBuffer->QUICBuffer->Buffer);
        pthread_cond_signal(&recvBuffer->cond);
        printf("Signaled\n");
        pthread_mutex_unlock(&recvBuffer->mutex);
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
            MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

Stream open_stream(Connection connection)
{
    QUIC_STATUS status;
    HQUIC conn = (HQUIC)connection;
    HQUIC stream = NULL;
    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (QUIC_FAILED(status = MsQuic->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_callback, NULL, &stream)))
    {
        printf("StreamOpen failed, 0x%x!\n", status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", (void *)stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(status = MsQuic->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE)))
    {
        printf("StreamStart failed, 0x%x!\n", status);
        MsQuic->StreamClose(stream);
        goto Error;
    }

    while (!streamStarted)
    {
        // Wait for stream to be started
    }
    streamStarted = 0;

    return (Stream)stream;

Error:

    if (QUIC_FAILED(status))
    {
        MsQuic->ConnectionShutdown(conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
    return NULL;
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
    UNREFERENCED_PARAMETER(Context);
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
            MsQuic->ConnectionClose(Connection);
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

Connection open_connection(Config *conf)
{
    QUIC_STATUS status;
    HQUIC conn = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(status = MsQuic->ConnectionOpen(registration, client_connection_callback, NULL, &conn)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", status);
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", (void *)conn);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(status = MsQuic->ConnectionStart(conn, configuration, QUIC_ADDRESS_FAMILY_INET, conf->target, (uint16_t)atoi(conf->port))))
    {
        printf("ConnectionStart failed, 0x%x!\n", status);
        goto Error;
    }

    while (!connected)
    {
        // Wait for connection to be established
    }
    connected = 0;

Error:

    if (QUIC_FAILED(status) && conn != NULL)
    {
        MsQuic->ConnectionClose(conn);
    }

    return (Connection)conn;
}

//
// Helper function to load a client configuration.
//
BOOLEAN
client_load_configuration(Config *conf)
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (conf->unsecure)
    {
        printf("Unsecure mode\n");
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = MsQuic->ConfigurationOpen(registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &configuration)))
    {
        printf("ConfigurationOpen failed, 0x%x!\n", status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(status = MsQuic->ConfigurationLoadCredential(configuration, &CredConfig)))
    {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
        return FALSE;
    }

    return TRUE;
}

void client_shutdown()
{
    if (MsQuic != NULL)
    {
        if (configuration != NULL)
        {
            MsQuic->ConfigurationClose(configuration);
        }
        if (registration != NULL)
        {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(registration);
        }
        MsQuicClose(MsQuic);
    }
}

//
// Runs the client side of the protocol.
//
Config *client_init()
{
    printf("Starting client...\n");
    Config *conf = read_config("config.yaml");
    printf("Configuration loaded\n");

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(status = MsQuicOpen2(&MsQuic)))
    {
        printf("MsQuicOpen2 failed, 0x%x!\n", status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(&RegConfig, &registration)))
    {
        printf("RegistrationOpen failed, 0x%x!\n", status);
        goto Error;
    }

    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    if (!client_load_configuration(conf))
    {
        return NULL;
    }
    printf("Client initialized\n");

    // Ensure recvBuffer is initialized
    recvBuffer = NULL;
    recvBuffer = (Buffer *)malloc(sizeof(Buffer));
    if (recvBuffer == NULL)
    {
        printf("recvBuffer allocation failed!\n");
        // Handle memory allocation failure
        return NULL;
    }

    // Allocate memory for the destination buffer
    recvBuffer->QUICBuffer = NULL;

    if ((recvBuffer->QUICBuffer = (QUIC_BUFFER *)malloc(sizeof(QUIC_BUFFER))) == NULL)
    {
        printf("recvBuffer->QUICBuffer allocation failed!\n");
        // Handle memory allocation failure
        return NULL;
    }
    recvBuffer->QUICBuffer->Length = 0;
    pthread_mutex_init(&recvBuffer->mutex, NULL);
    pthread_cond_init(&recvBuffer->cond, NULL);

    printf("recvBuffer allocated\n");

    return conf;

Error:

    if (MsQuic != NULL)
    {
        if (configuration != NULL)
        {
            MsQuic->ConfigurationClose(configuration);
        }
        if (registration != NULL)
        {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(registration);
        }
        MsQuicClose(MsQuic);
    }
    return NULL;
}