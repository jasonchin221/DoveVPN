#ifndef __DV_CHANNEL_H__
#define __DV_CHANNEL_H__

#include "dv_types.h"

enum {
    DV_CH_CMD_OPEN = 1,
    DV_CH_CMD_CLOSE,
    DV_CH_CMD_MAX,
};

typedef struct _dv_channel_t {
    dv_u32      ch_command;
    pid_t       ch_pid;
    int         ch_fd;
} dv_channel_t;

extern void dv_close_channel(int *fd);

#endif
