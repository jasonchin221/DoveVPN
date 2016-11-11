#include <unistd.h>

#include "dv_channel.h"
#include "dv_log.h"

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

