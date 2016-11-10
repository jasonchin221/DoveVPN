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
#include "dv_process.h"

static void dv_execute_proc(dv_cycle_t *cycle, void *data);
static void dv_signal_handler(int signo);

int             dv_process_slot;
int             dv_channel;
int             dv_last_process;
dv_process_t    dv_processes[DV_MAX_PROCESSES];

dv_signal_t  dv_signals[] = {
    { dv_signal_value(DV_RECONFIGURE_SIGNAL),
      "SIG" dv_value(DV_RECONFIGURE_SIGNAL),
      "reload",
      dv_signal_handler },

    { dv_signal_value(DV_REOPEN_SIGNAL),
      "SIG" dv_value(DV_REOPEN_SIGNAL),
      "reopen",
      dv_signal_handler },

    { dv_signal_value(DV_NOACCEPT_SIGNAL),
      "SIG" dv_value(DV_NOACCEPT_SIGNAL),
      "",
      dv_signal_handler },

    { dv_signal_value(DV_TERMINATE_SIGNAL),
      "SIG" dv_value(DV_TERMINATE_SIGNAL),
      "stop",
      dv_signal_handler },

    { dv_signal_value(DV_SHUTDOWN_SIGNAL),
      "SIG" dv_value(DV_SHUTDOWN_SIGNAL),
      "quit",
      dv_signal_handler },

    { dv_signal_value(DV_CHANGEBIN_SIGNAL),
      "SIG" dv_value(DV_CHANGEBIN_SIGNAL),
      "",
      dv_signal_handler },

    { SIGALRM, "SIGALRM", "", dv_signal_handler },

    { SIGINT, "SIGINT", "", dv_signal_handler },

    { SIGIO, "SIGIO", "", dv_signal_handler },

    { SIGCHLD, "SIGCHLD", "", dv_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};

int
dv_init_signals(void)
{
    dv_signal_t         *sig = NULL;
    struct sigaction    sa = {};

    for (sig = dv_signals; sig->sig_no != 0; sig++) {
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
dv_os_signal_process(char *name, pid_t pid)
{
    dv_signal_t     *sig = NULL;

    for (sig = dv_signals; sig->sig_no != 0; sig++) {
        if (dv_strcmp(name, sig->sig_action) == 0) {
            if (kill(pid, sig->sig_no) != -1) {
                return DV_OK;
            }

            DV_LOG(DV_LOG_ALERT, "kill(%P, %d) failed", pid, sig->sig_no);
        }
    }

    return DV_ERROR;
}
