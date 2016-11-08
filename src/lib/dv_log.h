#ifndef __DV_LOG_H__
#define __DV_LOG_H__

#ifdef DV_CLIENT
#define DV_LOG(priority, format, ...) \
    do { \
        printf("[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#else
#include <syslog.h>
extern int dv_log_print;
#define DV_LOG(priority, format, ...) \
    do { \
        if (dv_log_print) { \
            printf("[%s, %d]: "format, __FUNCTION__, \
                    __LINE__, ##__VA_ARGS__); \
        } else { \
            syslog(priority, "[%s, %d]: "format, __FUNCTION__, \
                    __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#endif

#ifdef DV_CLIENT
#define DV_LOG_EMERG   1   //system is unusable
#define DV_LOG_ALERT   2   //action must be taken immediately
#define DV_LOG_CRIT    3    //critical conditions
#define DV_LOG_ERROR   4     //error conditions
#define DV_LOG_WARNING 5     //warning conditions
#define DV_LOG_NOTICE  6  //normal, but significant, condition
#define DV_LOG_INFO    7    //informational message
#define DV_LOG_DEBUG   8   //debug-level message
#else
#define DV_LOG_EMERG   LOG_EMERG   //system is unusable
#define DV_LOG_ALERT   LOG_ALERT   //action must be taken immediately
#define DV_LOG_CRIT    LOG_CRIT    //critical conditions
#define DV_LOG_ERROR   LOG_ERR     //error conditions
#define DV_LOG_WARNING LOG_WARNING     //warning conditions
#define DV_LOG_NOTICE  LOG_NOTICE  //normal, but significant, condition
#define DV_LOG_INFO    LOG_INFO    //informational message
#define DV_LOG_DEBUG   LOG_DEBUG   //debug-level message
#endif

extern void dv_log_init(const char *logname);
extern void dv_log_exit(void);

#endif
