#ifndef __DV_SIGNAL_H__
#define __DV_SIGNAL_H__

#include <sys/types.h>
#include <unistd.h>

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

extern int dv_init_signals(void);

#endif
