
#include "dv_types.h"
#include "dv_log.h"

int dv_log_print;

void
dv_log_init(const char *logname)
{
#ifndef DV_CLIENT 
    openlog(logname, LOG_CONS | LOG_PID, LOG_USER);
#endif
}

void
dv_log_exit(void)
{
#ifndef DV_CLIENT 
    closelog();
#endif
}

