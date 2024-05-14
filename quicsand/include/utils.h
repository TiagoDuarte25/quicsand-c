#ifndef UTILS_H
#define UTILS_H

#include <yaml.h>

typedef struct config
{
    int reps;
    int bufsize;
    int reqsize;
    int unsecure;
    char *target;
    char *port;
} Config;

Config *read_config(char *filename);

#endif // UTILS_H