/*
  SafeFS
  (c) 2016 2016 INESC TEC. Written by J. Paulo and R. Pontes

*/


#ifndef __SFSConfig_H__
#define __SFSConfig_H__

#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <stdio.h>
#include "../inih/ini.h"
#include "../logging/logdef.h"
#include "../utils/map/map.h"

#define MULTI_LOOPBACK 0
#define SFUSE 1
#define BLOCK_ALIGN 2
#define NOPFUSE 3
#define LOCALFUSE 6

// Default configuration files location
#define DEFAULT_SDSCONFIG_PATH "conf_examples/default.ini"

typedef struct multi_loop_configuration {
    GSList* loop_paths;
    char* root_path;
    int mode;
    int ndevs;
} m_loop_conf;

typedef struct encode_configuration {
    char* key;
    char* iv;
    int key_size;
    int iv_size;
    int mode;
    int operation_mode;
    int cache;
} enc_config;

typedef struct block_align_configuration {
    int block_size;
    int mode;
} block_align_config;

typedef struct local_configuration {
    char* path;
} local_config;

typedef struct log_configuration { int mode; } log_config;

typedef struct sds_configuration {
    enc_config enc_config;
    m_loop_conf m_loop_config;
    block_align_config block_config;
    log_config logging_configuration;
    local_config local_config;
    GSList* layers;
} configuration;

int init_config(char* configuration_file_path, configuration** config);

void clean_config(configuration* config);

#endif /* __SFSConfig_H__ */
