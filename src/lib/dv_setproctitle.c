#include <string.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_mem.h"
#include "dv_assert.h"
#include "dv_log.h"

extern char **environ;

static char **dv_os_argv; 
static char *dv_os_argv_last;

int
dv_init_setproctitle(char **argv)
{
    char        *p = NULL;
    size_t      size = 0;
    int         i = 0;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = dv_calloc(size);
    if (p == NULL) {
        return DV_ERROR;
    }

    dv_os_argv = argv;
    dv_os_argv_last = dv_os_argv[0];

    for (i = 0; dv_os_argv[i]; i++) {
        if (dv_os_argv_last == dv_os_argv[i]) {
            dv_os_argv_last = dv_os_argv[i] + strlen(dv_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (dv_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            dv_os_argv_last = environ[i] + size;

            strncpy(p, environ[i], size);
            environ[i] = (char *)p;
            p += size;
        }
    }

    dv_os_argv_last--;

    return DV_OK;
}

void
dv_setproctitle(char *title)
{
    char        *p = NULL;

    dv_assert(dv_os_argv != NULL);

    dv_os_argv[1] = NULL;

    p = dv_os_argv[0];
    p += snprintf(p, dv_os_argv_last - p, "DoveVPN: ");
    p += snprintf(p, dv_os_argv_last - p, "%s ", title);

    if (dv_os_argv_last - p) {
        memset(p, 0, dv_os_argv_last - p);
    }

    DV_LOG(DV_LOG_DEBUG, "setproctitle: \"%s\"", dv_os_argv[0]);
}


