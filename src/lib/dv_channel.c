#include <unistd.h>

#include "dv_channel.h"
#include "dv_log.h"
#include "dv_event.h"
#include "dv_socket.h"
#include "dv_errno.h"

static dv_event_t dv_channel_rev;

void
dv_close_channel(int *fd)
{
    if (close(fd[0]) == -1) {
        DV_LOG(DV_LOG_ALERT, "close() channel failed\n");
    }

    if (close(fd[1]) == -1) {
        DV_LOG(DV_LOG_ALERT, "close() channel failed\n");
    }
}

void
dv_add_channel_read_event(int fd, dv_event_handler handler)
{
    dv_event_conn_set(&dv_channel_rev, NULL, fd, handler,
        dv_event_set_persist_read);
    if (dv_event_add(&dv_channel_rev) != DV_OK) {
        DV_LOG(DV_LOG_ALERT, "Add channel read event failed\n");
    }
}

void
dv_destroy_channel_events(void)
{
    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    dv_event_destroy(&dv_channel_rev);
}

int
dv_write_channel(int fd, const void *msg, size_t len)
{
    return dv_sk_send(fd, msg, len);
}
