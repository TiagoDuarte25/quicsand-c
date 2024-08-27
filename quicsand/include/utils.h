#ifndef UTILS_H
#define UTILS_H

#include <yaml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>
#include <unistd.h>
#include <linux/limits.h>

typedef struct config
{
    int reps;
    int bufsize;
    int reqsize;
    int unsecure;
    char *target;
    char *port;
} config_t;

config_t* read_config(char *filename);

#endif // UTILS_H