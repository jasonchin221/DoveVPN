#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "dv_signal.h"
#include "dv_log.h"
#include "dv_server_signal.h"
#include "dv_server_cycle.h"
#include "dv_server_conn.h"

static void dv_srv_signal_handler(int signo);

static dv_signal_t dv_srv_signals[] = {
    { SIGHUP, "SIGHUP", "reload", dv_srv_signal_handler },

    { SIGTERM, "SIGTERM", "stop", dv_srv_signal_handler },

    { SIGQUIT, "SIGQUIT", "quit", dv_srv_signal_handler },

    { SIGUSR1, "SIGUSR1", "conn", dv_srv_signal_handler },

    { SIGALRM, "SIGALRM", "", dv_srv_signal_handler },

    { SIGINT, "SIGINT", "", dv_srv_signal_handler },

    { SIGIO, "SIGIO", "", dv_srv_signal_handler },

    { SIGCHLD, "SIGCHLD", "", dv_srv_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};

static void
dv_srv_signal_handler(int signo)
{
    switch (signo) {
        case SIGQUIT:
        case SIGINT:
            DV_LOG(DV_LOG_INFO, "Quiting!\n");
            dv_quit = 1;
            break;
        case SIGTERM:
            dv_terminate = 1;
            break;
        case SIGHUP:
            dv_reconfigure = 1;
            break;
        case SIGUSR1:
            DV_LOG(DV_LOG_INFO, "Conn num = (%u)!\n", dv_srv_conn_num_get());
            break;
        default:
            DV_LOG(DV_LOG_INFO, "Other signal(%d)!\n", signo);
            break;
    }
}

int
dv_srv_signal_init(void)
{
    return dv_signal_init(dv_srv_signals);
}

int
dv_srv_signal_process(char *name, pid_t pid)
{
    return dv_signal_process(dv_srv_signals, name, pid);
}

