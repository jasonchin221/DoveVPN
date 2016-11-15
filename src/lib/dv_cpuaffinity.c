#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>

#include "dv_errno.h"

int
dv_cpuaffinity_set(int cpu)
{
    cpu_set_t   mask = {};
    int         ret = 0;

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    ret = sched_setaffinity(0, sizeof(mask), &mask);
    if (ret == 0) {
        return DV_OK;
    }

    return DV_ERROR;
}

