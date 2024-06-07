/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple MsQuic API sample server and client application.

    The quicsample app implements a simple protocol (ALPN "sample") where the
    client connects to the server, opens a single bidirectional stream, sends
    some data and shuts down the stream in the send direction. On the server
    side all connections, streams and data are accepted. After the stream is
    shut down, the server then sends its own data and shuts down its send
    direction. The connection only shuts down when the 1 second idle timeout
    triggers.

    A certificate needs to be available for the server to function.

    On Windows, the following PowerShell command can be used to generate a self
    signed certificate with the correct settings. This works for both Schannel
    and OpenSSL TLS providers, assuming the KeyExportPolicy parameter is set to
    Exportable. The Thumbprint received from the command is then passed to this
    sample with -cert_hash:PASTE_THE_THUMBPRINT_HERE

    New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable

    On Linux, the following command can be used to generate a self signed
    certificate that works with the OpenSSL TLS Provider. This can also be used
    for Windows OpenSSL, however we recommend the certificate store method above
    for ease of use. Currently key files with password protections are not
    supported. With these files, they can be passed to the sample with
    -cert_file:path/to/server.cert -key_file path/to/server.key

    openssl req  -nodes -new -x509  -keyout server.key -out server.cert

--*/

#include "quicsand_server_adapter.h"
#include "msquic.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

struct server_ctx
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

    struct Buffer
    {
        QUIC_BUFFER *QUICBuffer;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
    } *recvBuffer;
} ctx;

const uint32_t SendBufferLength = 100;

void set_family(
    _In_ QUIC_ADDR *Addr,
    _In_ QUIC_ADDRESS_FAMILY Family)
{
    Addr->Ip.sa_family = Family;
}

void set_port(
    _Out_ QUIC_ADDR *Addr,
    _In_ uint16_t Port)
{
    if (QUIC_ADDRESS_FAMILY_INET == Addr->Ip.sa_family)
    {
        Addr->Ipv4.sin_port = htons(Port);
    }
    else
    {
        Addr->Ipv6.sin6_port = htons(Port);
    }
}

void print_usage()
{
    printf(
        "\n"
        "quicsample runs a simple client or server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  quicsample.exe -client -unsecure -target:{IPAddress|Hostname} [-ticket:<ticket>]\n"
        "  quicsample.exe -server -cert_hash:<...>\n"
        "  quicsample.exe -server -cert_file:<...> -key_file:<...> [-password:<...>]\n");
}

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

//
// Allocates and sends some data over a QUIC stream.
//
void server_send(struct server_ctx *ctx)
{
    HQUIC Stream = ctx->Stream;
    //
    // Allocates and builds the buffer to send over the stream.
    //
    void *SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL)
    {
        printf("SendBuffer allocation failed!\n");
        ctx->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }
    char *data = "Server Response!";
    size_t data_len = strlen(data);
    QUIC_BUFFER *SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    SendBuffer->Buffer = data;
    SendBuffer->Length = (uint32_t)data_len;
    // QUIC_BUFFER *SendBuffer = (QUIC_BUFFER *)SendBufferRaw;
    // SendBuffer->Buffer = (uint8_t *)SendBufferRaw + sizeof(QUIC_BUFFER);
    // SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", (void *)Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = ctx->MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer)))
    {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        ctx->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
        QUIC_STATUS
    QUIC_API
    server_stream_callback(
        _In_ HQUIC Stream,
        _In_opt_ void *Context,
        _Inout_ QUIC_STREAM_EVENT *Event)
{
    struct server_ctx *ctx = (struct server_ctx *)Context;
    ctx->Stream = Stream;
    switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", (void *)Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", (void *)Stream);
        printf("Data: %s\n", Event->RECEIVE.Buffers->Buffer);
        server_send(ctx);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", (void *)Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", (void *)Stream);
        ctx->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", (void *)Stream);
        ctx->MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
        QUIC_STATUS
    QUIC_API
    server_connection_callback(
        _In_ HQUIC Connection,
        _In_opt_ void *Context,
        _Inout_ QUIC_CONNECTION_EVENT *Event)
{
    struct server_ctx *ctx = (struct server_ctx *)Context;
    switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", (void *)Connection);
        ctx->MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
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
        ctx->MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", (void *)Event->PEER_STREAM_STARTED.Stream);
        ctx->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)server_stream_callback, ctx);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", (void *)Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
        QUIC_STATUS
    QUIC_API
    server_listener_callback(
        _In_ HQUIC Listener,
        _In_opt_ void *Context,
        _Inout_ QUIC_LISTENER_EVENT *Event)
{
    UNREFERENCED_PARAMETER(Listener);
    struct server_ctx *ctx = (struct server_ctx *)Context;
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type)
    {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        ctx->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void *)server_connection_callback, ctx);
        Status = ctx->MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, ctx->Configuration);
        printf("[list][%p] New Connection\n", (void *)Listener);
        break;
    default:
        break;
    }
    return Status;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER
{
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union
    {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN
server_load_configuration(struct server_ctx *ctx)
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = ctx->IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    char cwd[PATH_MAX];
    char cert_path[PATH_MAX];
    char key_path[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        perror("getcwd() error");
        exit(EXIT_FAILURE);
    }
    strcpy(cert_path, cwd);
    strcpy(key_path, cwd);
    strcat(cert_path, "/certs/quicsand-server.pem");
    strcat(key_path, "/certs/key.pem");
    printf("cert_path: %s\n", cert_path);
    printf("key_path: %s\n", key_path);
    printf("Certifying...\n");
    //
    // Loads the server's certificate from the file.
    //
    Config.CertFile.CertificateFile = cert_path;
    Config.CertFile.PrivateKeyFile = key_path;
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;
    printf("Certified.\n");

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    printf("Opening registration...\n");
    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = ctx->MsQuic->RegistrationOpen(&ctx->RegConfig, &ctx->Registration)))
    {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }
    printf("Registration opened.\n");
    printf("Opening configuration...\n");

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    if (QUIC_FAILED(Status = ctx->MsQuic->ConfigurationOpen(ctx->Registration, &ctx->Alpn, 1, &Settings, sizeof(Settings), NULL, &ctx->Configuration)))
    {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }
    printf("Configuration opened.\n");

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = ctx->MsQuic->ConfigurationLoadCredential(ctx->Configuration, &Config.CredConfig)))
    {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    printf("Credential loaded.\n");
    return TRUE;

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
    return FALSE;
}

//
// Runs the server side of the protocol.
//
Server_CTX server_init(Config *conf)
{
    printf("Starting server...\n");
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    ctx = (struct server_ctx){0};
    ctx.RegConfig = (QUIC_REGISTRATION_CONFIG){"quicsand", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    ctx.Alpn = (QUIC_BUFFER){sizeof("quicsand") - 1, (uint8_t *)"quicsand"};
    ctx.IdleTimeoutMs = 1000;
    ctx.Host = conf->target;
    ctx.Port = conf->port;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen2(&ctx.MsQuic)))
    {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    //
    QUIC_ADDR Address = {0};
    set_family(&Address, QUIC_ADDRESS_FAMILY_INET);
    set_port(&Address, (uint16_t)atoi(conf->port));
    printf("Listening on [::]:%s\n", conf->port);
    //
    // Load the server configuration based on the command line.
    //
    if (!server_load_configuration(&ctx))
    {
        return NULL;
    }
    printf("Configuration loaded.\n");
    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = ctx.MsQuic->ListenerOpen(ctx.Registration, server_listener_callback, &ctx, &Listener)))
    {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }
    printf("Listener created.\n");
    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = ctx.MsQuic->ListenerStart(Listener, &ctx.Alpn, 1, &Address)))
    {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    return (Server_CTX)&ctx;
Error:

    if (Listener != NULL)
    {
        ctx.MsQuic->ListenerClose(Listener);
    }
    exit(0);
}

void server_shutdown(Server_CTX ctx)
{
    struct server_ctx *server_ctx = (struct server_ctx *)ctx;

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    printf("Press Enter to exit.\n\n");
    getchar();

    server_ctx->MsQuic->ConfigurationClose(server_ctx->Configuration);
    server_ctx->MsQuic->RegistrationClose(server_ctx->Registration);
}