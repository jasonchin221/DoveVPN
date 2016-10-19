
#include "dv_proto.h"
#include "dv_lib.h"
#include "dv_errno.h"
#include "dv_types.h"


static const dv_proto_suite_t *dv_proto_suite[] = {
    &dv_suite_openssl,
};

#define DV_PROTO_SUITE_NUM  DV_ARRAY_SIZE(dv_proto_suite)

static const dv_proto_name_type_t dv_proto_name_type_maps[] = {
    {
        .nt_type = DV_PROTO_TYPE_OPENSSL,
        .nt_name = DV_PROTO_OPENSSL,
    },
    {
        .nt_type = DV_PROTO_TYPE_NONE,
        .nt_name = DV_PROTO_PLAINTEXT,
    },
};

#define DV_PROTO_TYPE_NUM  DV_ARRAY_SIZE(dv_proto_name_type_maps)

const dv_proto_suite_t *
dv_proto_suite_find(const char *name)
{
    int     type = -1;
    int     i = 0;

    for (i = 0; i < DV_PROTO_TYPE_NUM; i++) {
        if (strcmp(dv_proto_name_type_maps[i].nt_name, name) == 0) {
            type = dv_proto_name_type_maps[i].nt_type;
            break;
        }
    }

    for (i = 0; i < DV_PROTO_SUITE_NUM; i++) {
        if (dv_proto_suite[i]->ps_proto_type == type) {
            return dv_proto_suite[i];
        }
    }

    return NULL;
}
