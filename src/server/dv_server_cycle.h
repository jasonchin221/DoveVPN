#ifndef __DV_SERVER_CYCLE_H__
#define __DV_SERVER_CYCLE_H__

#include <signal.h>

#include "dv_tun.h"
#include "dv_server_conf.h"

enum {
    DV_PROCESS_SINGLE,
    DV_PROCESS_MASTER,
    DV_PROCESS_WORKER,
};

extern dv_tun_t dv_srv_tun;
extern sig_atomic_t dv_quit;
extern sig_atomic_t dv_reconfigure;
extern sig_atomic_t dv_terminate;

extern int dv_argc;
extern char **dv_argv;

extern int dv_server_cycle(dv_srv_conf_t *conf);
extern int dv_server_send_signal(char *pid_file, char *cmd);

#endif
