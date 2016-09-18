#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "dv_types.h"
#include "dv_proto.h"

int
dv_v4_client(struct sockaddr_in *addr, char *cf, char *key, char *ca,
        char *dev, dv_u8 proto)
{
    return 0;
}


