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

int             dv_process_slot;
int             dv_channel;
int             dv_last_process;
dv_process_t    dv_processes[DV_MAX_PROCESSES];

//static void dv_execute_proc(dv_cycle_t *cycle, void *data);

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



#if 0
dv_pid_t
dv_spawn_process(dv_cycle_t *cycle, dv_spawn_proc_pt proc, void *data,
    char *name, dv_int_t respawn)
{
    u_long     on;
    dv_pid_t  pid;
    dv_int_t  s;

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < dv_last_process; s++) {
            if (dv_processes[s].pid == -1) {
                break;
            }
        }

        if (s == DV_MAX_PROCESSES) {
            dv_log_error(DV_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          DV_MAX_PROCESSES);
            return DV_INVALID_PID;
        }
    }


    if (respawn != DV_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, dv_processes[s].channel) == -1)
        {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return DV_INVALID_PID;
        }

        dv_log_debug2(DV_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       dv_processes[s].channel[0],
                       dv_processes[s].channel[1]);

        if (dv_nonblocking(dv_processes[s].channel[0]) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          dv_nonblocking_n " failed while spawning \"%s\"",
                          name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        if (dv_nonblocking(dv_processes[s].channel[1]) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          dv_nonblocking_n " failed while spawning \"%s\"",
                          name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        on = 1;
        if (ioctl(dv_processes[s].channel[0], FIOASYNC, &on) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        if (fcntl(dv_processes[s].channel[0], F_SETOWN, dv_pid) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        if (fcntl(dv_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        if (fcntl(dv_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            dv_close_channel(dv_processes[s].channel, cycle->log);
            return DV_INVALID_PID;
        }

        dv_channel = dv_processes[s].channel[1];

    } else {
        dv_processes[s].channel[0] = -1;
        dv_processes[s].channel[1] = -1;
    }

    dv_process_slot = s;


    pid = fork();

    switch (pid) {

    case -1:
        dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                      "fork() failed while spawning \"%s\"", name);
        dv_close_channel(dv_processes[s].channel, cycle->log);
        return DV_INVALID_PID;

    case 0:
        dv_pid = dv_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    dv_log_error(DV_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    dv_processes[s].pid = pid;
    dv_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    dv_processes[s].proc = proc;
    dv_processes[s].data = data;
    dv_processes[s].name = name;
    dv_processes[s].exiting = 0;

    switch (respawn) {

    case DV_PROCESS_NORESPAWN:
        dv_processes[s].respawn = 0;
        dv_processes[s].just_spawn = 0;
        dv_processes[s].detached = 0;
        break;

    case DV_PROCESS_JUST_SPAWN:
        dv_processes[s].respawn = 0;
        dv_processes[s].just_spawn = 1;
        dv_processes[s].detached = 0;
        break;

    case DV_PROCESS_RESPAWN:
        dv_processes[s].respawn = 1;
        dv_processes[s].just_spawn = 0;
        dv_processes[s].detached = 0;
        break;

    case DV_PROCESS_JUST_RESPAWN:
        dv_processes[s].respawn = 1;
        dv_processes[s].just_spawn = 1;
        dv_processes[s].detached = 0;
        break;

    case DV_PROCESS_DETACHED:
        dv_processes[s].respawn = 0;
        dv_processes[s].just_spawn = 0;
        dv_processes[s].detached = 1;
        break;
    }

    if (s == dv_last_process) {
        dv_last_process++;
    }

    return pid;
}

dv_pid_t
dv_execute(dv_cycle_t *cycle, dv_exec_ctx_t *ctx)
{
    return dv_spawn_process(cycle, dv_execute_proc, ctx, ctx->name,
                             DV_PROCESS_DETACHED);
}

static void
dv_execute_proc(dv_cycle_t *cycle, void *data)
{
    dv_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        dv_log_error(DV_LOG_ALERT, cycle->log, dv_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}
#endif

