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

#if 0
void
dv_signal_handler(int signo)
{
    char            *action;
    dv_int_t        ignore;
    dv_err_t        err;
    dv_signal_t    *sig;

    ignore = 0;

    err = dv_errno;

    for (sig = dv_signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    dv_time_sigsafe_update();

    action = "";

    switch (dv_process) {

    case DV_PROCESS_MASTER:
    case DV_PROCESS_SINGLE:
        switch (signo) {

        case dv_signal_value(DV_SHUTDOWN_SIGNAL):
            dv_quit = 1;
            action = ", shutting down";
            break;

        case dv_signal_value(DV_TERMINATE_SIGNAL):
        case SIGINT:
            dv_terminate = 1;
            action = ", exiting";
            break;

        case dv_signal_value(DV_NOACCEPT_SIGNAL):
            if (dv_daemonized) {
                dv_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case dv_signal_value(DV_RECONFIGURE_SIGNAL):
            dv_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case dv_signal_value(DV_REOPEN_SIGNAL):
            dv_reopen = 1;
            action = ", reopening logs";
            break;

        case dv_signal_value(DV_CHANGEBIN_SIGNAL):
            if (getppid() > 1 || dv_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            dv_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            dv_sigalrm = 1;
            break;

        case SIGIO:
            dv_sigio = 1;
            break;

        case SIGCHLD:
            dv_reap = 1;
            break;
        }

        break;

    case DV_PROCESS_WORKER:
    case DV_PROCESS_HELPER:
        switch (signo) {

        case dv_signal_value(DV_NOACCEPT_SIGNAL):
            if (!dv_daemonized) {
                break;
            }
            dv_debug_quit = 1;
        case dv_signal_value(DV_SHUTDOWN_SIGNAL):
            dv_quit = 1;
            action = ", shutting down";
            break;

        case dv_signal_value(DV_TERMINATE_SIGNAL):
        case SIGINT:
            dv_terminate = 1;
            action = ", exiting";
            break;

        case dv_signal_value(DV_REOPEN_SIGNAL):
            dv_reopen = 1;
            action = ", reopening logs";
            break;

        case dv_signal_value(DV_RECONFIGURE_SIGNAL):
        case dv_signal_value(DV_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    dv_log_error(DV_LOG_NOTICE, dv_cycle->log, 0,
                  "signal %d (%s) received%s", signo, sig->signame, action);

    if (ignore) {
        dv_log_error(DV_LOG_CRIT, dv_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        dv_process_get_status();
    }

    dv_set_errno(err);
}
#endif

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
        }
    }

    return DV_ERROR;
}
