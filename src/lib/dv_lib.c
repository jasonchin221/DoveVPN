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

long
dv_get_cpu_num(void)
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}
