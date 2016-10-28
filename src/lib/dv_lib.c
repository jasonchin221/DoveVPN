#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>


#include "dv_lib.h"
#include "dv_types.h"
#include "dv_log.h"
#include "dv_errno.h"
#include "dv_mem.h"

#define DV_PROC_CPU         "/proc/cpuinfo" 
#define DV_PROC_PROCESSOR   "processor"
#define DV_PROC_BUF_LEN     1024

dv_u32
dv_get_cpu_num(void)
{
    char    *data = NULL;
    char    *cpu = NULL;
    char    info[DV_PROC_BUF_LEN] = {};
    dv_u32  num = 0;
    int     rlen = 0;
    int     len = 0;
    int     fd = 0;

    fd = open(DV_PROC_CPU, O_RDONLY);
    if (fd < 0) {
        DV_LOG(DV_LOG_ERROR, "Open %s failed!\n", DV_PROC_CPU);
        return 0;
    }

    while (1) {
        rlen = read(fd, info, sizeof(info));
        if (rlen <= 0) {
            break;
        }
        len += rlen;
    }

    close(fd);
    data = dv_calloc(len + 1);
    if (data == NULL) {
        return 0;
    }
    fd = open(DV_PROC_CPU, O_RDONLY);
    if (fd < 0) {
        DV_LOG(DV_LOG_ERROR, "Open %s failed!\n", DV_PROC_CPU);
        dv_free(data);
        return 0;
    }

    rlen = read(fd, data, len);
    close(fd);
    if (rlen <= 0) {
        DV_LOG(DV_LOG_ERROR, "read from %s failed!\n", DV_PROC_CPU);
        dv_free(data);
        return 0;
    }

    cpu = data;
    while (1) {
        cpu = strstr(cpu, DV_PROC_PROCESSOR);
        if (cpu == NULL) {
            break;
        }
        num++;
        cpu += sizeof(DV_PROC_PROCESSOR);
    }

    dv_free(data);

    return num;
}
