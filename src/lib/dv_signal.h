#ifndef __DV_SIGNAL_H__
#define __DV_SIGNAL_H__

#include <sys/types.h>
#include <unistd.h>

#define dv_signal_value(n)      SIG##n
#define dv_value(n)             #n

typedef struct _dv_signal_t {
    int         sig_no;
    char        *sig_name;
    char        *sig_action;
    void        (*sig_handler)(int signo);
} dv_signal_t;

extern int dv_signal_init(dv_signal_t *signals);
extern int dv_signal_process(dv_signal_t *signals, char *name, pid_t pid);

#endif
