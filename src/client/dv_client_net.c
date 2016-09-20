#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dv_types.h"
#include "dv_proto.h"
#include "dv_tun.h"
#include "dv_log.h"
#include "dv_errno.h"

#define DV_CLIENT_LOG_NAME  "DoveVPN-Client"

static dv_tun_t dv_client_tun;

int
dv_v4_client(struct sockaddr_in *addr, char *cf, char *key, char *ca,
        dv_u8 proto)
{
    int         ret = DV_OK;

    dv_log_init(DV_CLIENT_LOG_NAME);

    ret = dv_tun_init(&dv_client_tun, 1);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    sleep(10);
    dv_tun_exit(&dv_client_tun, 1);
    dv_log_exit();
    return 0;
}


