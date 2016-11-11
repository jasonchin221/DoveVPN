#include <unistd.h>

#include "dv_channel.h"
#include "dv_log.h"
#include "dv_event.h"
#include "dv_socket.h"

static dv_event_t dv_channel_rev;

void
dv_close_channel(int *fd)
{
    if (close(fd[0]) == -1) {
        DV_LOG(DV_LOG_ALERT, "close() channel failed");
    }

    if (close(fd[1]) == -1) {
        DV_LOG(DV_LOG_ALERT, "close() channel failed");
    }
}

void
dv_add_channel_read_event(int fd, dv_event_handler handler)
{
    dv_event_conn_set(&dv_channel_rev, NULL, fd, handler,
        dv_event_set_persist_read);
}

void
dv_destroy_channel_events(void)
{
    dv_event_destroy(&dv_channel_rev);
}

int
dv_write_channel(int fd, const void *msg, size_t len)
{
    return dv_sk_send(fd, msg, len);
}
