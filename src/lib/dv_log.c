
#include "dv_types.h"
#include "dv_log.h"

void
dv_log_init(const char *logname)
{
    openlog(logname, LOG_CONS | LOG_PID, LOG_USER);
}

void
dv_log_exit(void)
{
    closelog();
}


