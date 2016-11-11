#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "dv_signal.h"
#include "dv_log.h"
#include "dv_server_signal.h"

static void dv_srv_signal_handler(int signo);

static dv_signal_t dv_srv_signals[] = {
    { SIGHUP, "SIGHUP", "reload", dv_srv_signal_handler },

    { SIGTERM, "SIGTERM", "stop", dv_srv_signal_handler },

    { SIGQUIT, "SIGQUIT", "quit", dv_srv_signal_handler },

    { SIGUSR1, "SIGUSR1", "", dv_srv_signal_handler },

    { SIGALRM, "SIGALRM", "", dv_srv_signal_handler },

    { SIGINT, "SIGINT", "", dv_srv_signal_handler },

    { SIGIO, "SIGIO", "", dv_srv_signal_handler },

    { SIGCHLD, "SIGCHLD", "", dv_srv_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};

static void dv_srv_signal_handler(int signo)
{
    switch (signo) {
        case SIGINT:
            DV_LOG(DV_LOG_INFO, "Quiting!\n");
            exit(0);
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

