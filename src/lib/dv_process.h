#ifndef __DV_PROCESS_H__
#define __DV_PROCESS_H__

#include <sys/types.h>
#include <unistd.h>

#define DV_MAX_PROCESSES        1024
#define DV_INVALID_PID          -1

typedef void (*dv_spawn_proc_pt)(void *cycle, void *data);

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


extern int dv_process_slot;
extern int dv_channel;
extern int dv_last_process;
extern dv_process_t dv_processes[];

extern int dv_process_daemonize(void);
extern void dv_process_init(void);
extern void dv_process_exit(void);
extern pid_t dv_spawn_process(void *cycle, dv_spawn_proc_pt proc,
        void *data, char *name);

#endif
