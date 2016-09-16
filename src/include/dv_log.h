#ifndef __DV_LOG_H__
#define __DV_LOG_H__

#ifdef DV_CLIENT
#define DV_LOG(priority, fmt, ...) \
    do { \
        printf("[%s, %d]: "fmt, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#else
#include <syslog.h>
#define DV_LOG(priority, format, ...) \
    do { \
        syslog(priority, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif

#define DV_LOG_EMERG   LOG_EMERG   //system is unusable
#define DV_LOG_ALERT   LOG_ALERT   //action must be taken immediately
#define DV_LOG_CRIT    LOG_CRIT    //critical conditions
#define DV_LOG_ERROR   LOG_ERR     //error conditions
#define DV_LOG_WARNING LOG_WARNING     //warning conditions
#define DV_LOG_NOTICE  LOG_NOTICE  //normal, but significant, condition
#define DV_LOG_INFO    LOG_INFO    //informational message
#define DV_LOG_DEBUG   LOG_DEBUG   //debug-level message

#endif
