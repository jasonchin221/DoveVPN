

#include "dv_errno.h"
#include "dv_test_conf.h"

int
dv_test_conf_parse(dv_test_conf_t *conf, char *file)
{
    int     ret = DV_OK;

    ret = dv_srv_conf_parse(&conf->cf_core, file);
    if (ret != DV_OK) {
        return ret;
    }

    return DV_OK;
}
