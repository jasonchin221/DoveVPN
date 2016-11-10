#ifndef __DV_PROCESS_H__
#define __DV_PROCESS_H__

#include <sys/types.h>
#include <unistd.h>

#define DV_MAX_PROCESSES        1024
#define dv_signal_value(n)      SIG##n
#define dv_value(n)             #n
#define DV_SHUTDOWN_SIGNAL      QUIT
#define DV_TERMINATE_SIGNAL     TERM
#define DV_NOACCEPT_SIGNAL      WINCH
#define DV_RECONFIGURE_SIGNAL   HUP
#define DV_REOPEN_SIGNAL        USR1
#define DV_CHANGEBIN_SIGNAL     USR2

typedef struct _dv_signal_t {
    int         sig_no;
    char        *sig_name;
    char        *sig_action;
    void        (*sig_handler)(int signo);
} dv_signal_t;

typedef struct _dv_process_t {
    pid_t               pc_pid;
    int                 pc_status;
    int                 pc_channel[2];

    //ngx_spawn_proc_pt   proc;
    void               *pc_data;
    char               *pc_name;

    dv_u32              pc_flags;
#if 0
    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
#endif
} dv_process_t;

extern int dv_init_signals(void);

#endif
