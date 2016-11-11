#ifndef __DV_CHANNEL_H__
#define __DV_CHANNEL_H__

#include "dv_types.h"
#include "dv_event.h"

enum {
    DV_CH_CMD_OPEN = 1,
    DV_CH_CMD_QUIT,
    DV_CH_CMD_TERMINATE,
    DV_CH_CMD_CLOSE,
    DV_CH_CMD_MAX,
};

typedef struct _dv_channel_t {
    dv_u32      ch_command;
    pid_t       ch_pid;
    int         ch_fd;
} dv_channel_t;

extern void dv_close_channel(int *fd);
extern void dv_add_channel_read_event(int fd, dv_event_handler handler);
extern int dv_write_channel(int fd, const void *msg, size_t len);
extern void dv_destroy_channel_events(void);

#endif
