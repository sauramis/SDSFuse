/*
  SafeFS
  (c) 2016 2016 INESC TEC. Written by J. Paulo and R. Pontes

*/


#ifndef __LOCAL_H__
#define __LOCAL_H__

#define FUSE_USE_VERSION 26

#define _GNU_SOURCE

#include <fuse.h>
#include "../../logging/logdef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "../../utils/utils.h"
#include "../../layers_conf/SFSConfig.h"
#include "../../layers_conf/layers_def.h"


int init_local_layer(struct fuse_operations **fuse_operations, configuration data);
int clean_local_layer(configuration data);

#endif
