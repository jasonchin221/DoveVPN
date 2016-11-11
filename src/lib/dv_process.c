#include <sys/types.h>
#include <sys/ioctl.h>
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
#include "dv_channel.h"

pid_t           dv_pid;
int             dv_process_slot;
int             dv_pc_channel;
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

pid_t
dv_spawn_process(dv_spawn_proc_pt proc, void *data, char *name)
{
    dv_u32      s = 0;
    dv_ulong    on = 0;
    pid_t       pid;

    for (s = 0; s < dv_last_process; s++) {
        if (dv_processes[s].pc_pid == -1) {
            break;
        }
    }

    if (s == DV_MAX_PROCESSES) {
        DV_LOG(DV_LOG_ALERT, "no more than %d processes can be spawned",
                DV_MAX_PROCESSES);
        return DV_INVALID_PID;
    }

    /* Solaris 9 still has no AF_LOCAL */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, dv_processes[s].pc_channel) == -1) {
        DV_LOG(DV_LOG_ALERT, "socketpair() failed while spawning \"%s\"", name);
        return DV_INVALID_PID;
    }

    DV_LOG(DV_LOG_DEBUG, "pc_channel %d:%d", dv_processes[s].pc_channel[0],
            dv_processes[s].pc_channel[1]);

    if (fcntl(dv_processes[s].pc_channel[0], F_SETFL, O_NONBLOCK) == -1) {
        DV_LOG(DV_LOG_INFO, "Set noblock failed!\n");
        return DV_INVALID_PID;
    }

    if (fcntl(dv_processes[s].pc_channel[1], F_SETFL, O_NONBLOCK) == -1) {
        DV_LOG(DV_LOG_INFO, "Set noblock failed!\n");
        return DV_INVALID_PID;
    }

    on = 1;
    if (ioctl(dv_processes[s].pc_channel[0], FIOASYNC, &on) == -1) {
        DV_LOG(DV_LOG_ALERT, "ioctl(FIOASYNC) failed while spawning \"%s\"",
                name);
        dv_close_channel(dv_processes[s].pc_channel);
        return DV_INVALID_PID;
    }

    if (fcntl(dv_processes[s].pc_channel[0], F_SETOWN, dv_pid) == -1) {
        DV_LOG(DV_LOG_ALERT, "fcntl(F_SETOWN) failed while spawning \"%s\"",
                name);
        dv_close_channel(dv_processes[s].pc_channel);
        return DV_INVALID_PID;
    }

    if (fcntl(dv_processes[s].pc_channel[0], F_SETFD, FD_CLOEXEC) == -1) {
        DV_LOG(DV_LOG_ALERT, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                name);
        dv_close_channel(dv_processes[s].pc_channel);
        return DV_INVALID_PID;
    }

    if (fcntl(dv_processes[s].pc_channel[1], F_SETFD, FD_CLOEXEC) == -1) {
        DV_LOG(DV_LOG_ALERT, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                name);
        dv_close_channel(dv_processes[s].pc_channel);
        return DV_INVALID_PID;
    }

    dv_pc_channel = dv_processes[s].pc_channel[1];

    dv_process_slot = s;

    pid = fork();

    switch (pid) {

    case -1:
        DV_LOG(DV_LOG_ALERT, "fork() failed while spawning \"%s\"", name);
        dv_close_channel(dv_processes[s].pc_channel);
        return DV_INVALID_PID;

    case 0:
        dv_pid = getpid();
        proc(data);
        break;

    default:
        break;
    }

    DV_LOG(DV_LOG_NOTICE, "Start %s %d", name, (int)pid);

    dv_processes[s].pc_pid = pid;
    //dv_processes[s].proc = proc;
    dv_processes[s].pc_data = data;
    dv_processes[s].pc_name = name;
    //dv_processes[s].exiting = 0;

    if (s == dv_last_process) {
        dv_last_process++;
    }

    return pid;
}

#if 0
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
        DV_LOG(DV_LOG_ALERT,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}
#endif

void
dv_process_init(void)
{
    dv_u32  i = 0;

    for (i = 0; i < DV_MAX_PROCESSES; i++) {
        dv_processes[i].pc_pid = DV_INVALID_PID;
    }
}
