#ifndef __DV_SERVER_SIGNAL_H__
#define __DV_SERVER_SIGNAL_H__

#define DV_SHUTDOWN_SIGNAL      QUIT
#define DV_TERMINATE_SIGNAL     TERM
#define DV_NOACCEPT_SIGNAL      WINCH
#define DV_RECONFIGURE_SIGNAL   HUP
#define DV_REOPEN_SIGNAL        USR1
#define DV_CHANGEBIN_SIGNAL     USR2

extern int dv_srv_signal_process(char *name, pid_t pid);
extern int dv_srv_signal_init(void);

#endif
