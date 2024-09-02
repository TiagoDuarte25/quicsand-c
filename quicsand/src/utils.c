#define _POSIX_C_SOURCE 200809L

#include <utils.h>

config_t *read_config(char *filename)
{
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        perror("getcwd() error");
        exit(EXIT_FAILURE);
    }

    strcat(cwd, "/");
    strcat(cwd, filename);

    FILE *fh = fopen(cwd, "r");
    yaml_parser_t parser;
    yaml_token_t token;
    config_t *config = malloc(sizeof(config_t));

    /* Initialize parser */
    if (!yaml_parser_initialize(&parser))
        fputs("Failed to initialize parser!\n", stderr);
    if (fh == NULL)
        fputs("Failed to open file!\n", stderr);

    /* Set input file */
    yaml_parser_set_input_file(&parser, fh);

    /* START new code */
    char *key = NULL;
    do
    {
        yaml_parser_scan(&parser, &token);
        switch (token.type)
        {
        case YAML_SCALAR_TOKEN:
            if (key == NULL)
            {
                key = strdup((char *)token.data.scalar.value);
            }
            else
            {
                if (strcmp(key, "repetitions") == 0)
                {
                    config->reps = atoi((char *)token.data.scalar.value);
                }
                else if (strcmp(key, "buffer_size") == 0)
                {
                    config->bufsize = atoi((char *)token.data.scalar.value);
                }
                else if (strcmp(key, "request_size") == 0)
                {
                    config->reqsize = atoi((char *)token.data.scalar.value);
                }
                else if (strcmp(key, "unsecure") == 0)
                {
                    config->unsecure = atoi((char *)token.data.scalar.value);
                }
                else if (strcmp(key, "host") == 0)
                {
                    config->host = strdup((char *)token.data.scalar.value);
                }
                else if (strcmp(key, "port") == 0)
                {
                    config->port = strdup((char *)token.data.scalar.value);
                }
                free(key);
                key = NULL;
            }
            break;
        default:
            break;
        }
        if (token.type != YAML_STREAM_END_TOKEN)
            yaml_token_delete(&token);
    } while (token.type != YAML_STREAM_END_TOKEN);
    yaml_token_delete(&token);

    yaml_parser_delete(&parser);
    fclose(fh);

    if (key != NULL)
    {
        free(key);
    }

    return config;
}

/*

//
// Helper function to convert a string of hex characters to a byte buffer.
//
uint32_t
DecodeHexBuffer(
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
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

void PrintUsage()
{
    printf(
        "\n"
        "Usage:\n"
        "\n"
        "   ./client <Options> \n");
}


*/