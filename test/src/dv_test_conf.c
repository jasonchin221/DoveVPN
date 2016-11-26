

#include "dv_errno.h"
#include "dv_test_conf.h"

#define DV_TEST_CONF_BACKEND    "backend"

dv_test_conf_t dv_test_conf;

static dv_test_conf_parse_t dv_test_conf_paser = {
    {
        .cp_name = "ip",
        .cp_type = ,
        .cp_proc = ,
    },
};

int
dv_test_conf_parse(dv_ser_conf_t *conf, char *file)
{
    json_object             *obj = NULL;
    json_object             *sub_obj = NULL;
    json_object             *a_obj = NULL;
    json_object             *param = NULL;
    const char              *val_str = NULL;
    int                     len = 0;
    int                     type = 0;
    int                     i = 0;
    int                     ret = DV_ERROR;

    ret = dv_srv_conf_parse(conf, file);
    if (ret != DV_OK) {
        return ret;
    }

    obj = dv_conf_parse(file, DV_TEST_CONF_BACKEND, &sub_obj);
    if (obj == NULL) {
        DV_LOG(DV_LOG_EMERG, "Parse %s failed!\n", DV_TEST_CONF_BACKEND);
        ret = DV_ERROR;
        goto out;
    }

    len = json_object_array_length(sub_obj);
    for (i = 0; i < len && i < DV_CONF_BACKEND_ADDR_MAX_NUM; i++) {
        a_obj = json_object_array_get_idx(sub_obj, i);
        type = json_object_get_type(a_obj);
        if (type != json_type_object) {
            goto out;
        }
        if (!json_object_object_get_ex(a_obj, DV_CIPHER_CONF_CIPHER, &param)) {
            DV_LOG(DV_LOG_EMERG, "Missing %s!\n", DV_CIPHER_CONF_CIPHER);
            goto out;
        }

        type = json_object_get_type(param);
        if (type != json_type_string) {
            goto out;
        }
        val_str = json_object_get_string(param);
        if (val_str == NULL) {
            goto out;
        }
        strncpy(dv_proto_ciphers[i], val_str, sizeof(dv_proto_ciphers[i]) - 1);
    }

out:
    if (obj != NULL) {
        json_object_put(obj);
    }

    return ret;
}

