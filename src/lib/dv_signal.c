#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "dv_types.h"
#include "dv_log.h"
#include "dv_errno.h"
#include "dv_process.h"
#include "dv_signal.h"

int
dv_signal_init(dv_signal_t *signals)
{
    dv_signal_t         *sig = NULL;
    struct sigaction    sa = {};

    for (sig = signals; sig->sig_no != 0; sig++) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig->sig_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->sig_no, &sa, NULL) == -1) {
            return DV_ERROR;
        }
    }

    return DV_OK;
}

int
dv_signal_process(dv_signal_t *signals, char *name, pid_t pid)
{
    dv_signal_t     *sig = NULL;

    for (sig = signals; sig->sig_no != 0; sig++) {
        if (strcmp(name, sig->sig_action) == 0) {
            if (kill(pid, sig->sig_no) != -1) {
                return DV_OK;
            }

            DV_LOG(DV_LOG_ALERT, "kill(%d, %d) failed", (int)pid, sig->sig_no);
            break;
        }
    }

    return DV_ERROR;
}
