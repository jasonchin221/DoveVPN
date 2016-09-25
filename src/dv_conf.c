#include <stdio.h>
#include <string.h>

#include <json/json.h>
#include <json/json_util.h>

#include "dv_log.h"
#include "dv_conf.h"
#include "dv_errno.h"
#include "dv_debug.h"

static int
json_object_object_get_ex(json_object* obj, const char *key,
        json_object **sub_obj)
{
    *sub_obj = json_object_object_get(obj, key);

    if (*sub_obj == NULL) {
        return 0;
    }

    return 1;
}

json_object *
dv_conf_parse(char *file, const char *key_name, json_object **sub_obj)
{
    json_object          *obj = NULL;
    json_object          *param = NULL;

    obj = json_object_from_file(file);
    if (obj == NULL) {
        return NULL;
    }

    if (!json_object_object_get_ex(obj, key_name, &param)) {
        param = NULL;
    }

    *sub_obj = param;

    return obj;
}

void
dv_conf_parse_int(void *conf, json_object *param,
            const dv_conf_parse_t *p)
{
    int     val_num = 0;

    val_num = json_object_get_int(param);
    DV_ASSERT(sizeof(val_num) == p->cp_len);
    memcpy((void *)conf + p->cp_offset, &val_num, p->cp_len);
}

void
dv_conf_parse_str(void *conf, json_object *param,
            const dv_conf_parse_t *p)
{
    const char      *val_str = NULL;

    val_str = json_object_get_string(param);
    strncpy((void *)conf + p->cp_offset, val_str, p->cp_len);
}

int
dv_config_parse(char *file, void *conf, const char *root_name, 
        const dv_conf_parse_t *array,
        dv_u32 array_num)
{
    json_object             *obj = NULL;
    json_object             *sub_obj = NULL;
    json_object             *param = NULL;
    const dv_conf_parse_t   *p = NULL;
    int                     type = 0;
    int                     i = 0;
    int                     ret = DV_OK;

    obj = dv_conf_parse(file, root_name, &sub_obj);
    if (obj == NULL) {
        ret = DV_ERROR;
        goto out;
    }

    for (i = 0; i < array_num; i++) {
        p = array + i;
        if (!json_object_object_get_ex(sub_obj, p->cp_name, &param)) {
            param = NULL;
        }
        if (param == NULL) {
            if (p->cp_necessary == DV_FALSE) {
                continue;
            }
            ret = DV_ERROR;
            goto out;
        }

        type = json_object_get_type(param);
        if (p->cp_type != type) {
            ret = DV_ERROR;
            goto out;
        }

        p->cp_parse(conf, param, p);
    }

out:
    if (obj != NULL) {
        json_object_put(obj);
    }

    return ret;
}


