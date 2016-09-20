#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include "dv_types.h"
#include "dv_log.h"
#include "dv_errno.h"

int 
dv_process_daemonize(void)
{
    pid_t   pid;
    int     fd = 0;

    if ((pid = fork()) < 0) {
        return DV_ERROR;
    } else if (pid != 0) {
        exit(0);
    }

    setsid();

    if (chdir("/")) {
        return DV_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        DV_LOG(DV_LOG_EMERG, "Open /dev/null failed!\n");
        return DV_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        DV_LOG(DV_LOG_EMERG, "Dup2 STDIN_FILENO failed!\n");
        return DV_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        DV_LOG(DV_LOG_EMERG, "Dup2 STDOUT_FILENO failed!\n");
        return DV_ERROR;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            DV_LOG(DV_LOG_EMERG, "Close %d failed!\n", fd);
            return DV_ERROR;
        }
    }
    return DV_OK;
}


