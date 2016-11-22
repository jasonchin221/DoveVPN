#include <stdio.h>
#include <string.h>

#include <json-c/json.h>
#include <json-c/json_util.h>

#include "dv_log.h"
#include "dv_lib.h"
#include "dv_conf.h"
#include "dv_errno.h"
#include "dv_debug.h"
#include "dv_proto.h"

#define DV_CIPHER_CONF_PROTO_TYPE      "type"
#define DV_CIPHER_CONF_CERT            "cert"
#define DV_CIPHER_CONF_KEY             "key"
#define DV_CIPHER_CONF_CA              "ca"
#define DV_CIPHER_CONF_CIPHERS         "ciphers"
#define DV_CIPHER_CONF_CIPHER          "cipher"

static dv_cipher_conf_t dv_cipher_config;

static dv_conf_parse_t dv_cipher_conf[] = {
    {
        .cp_name = DV_CIPHER_CONF_PROTO_TYPE,
        .cp_len = sizeof(dv_cipher_config.cc_proto_type),
        .cp_offset = dv_offsetof(dv_cipher_conf_t, cc_proto_type),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_CIPHER_CONF_CERT,
        .cp_len = sizeof(dv_cipher_config.cc_cert),
        .cp_offset = dv_offsetof(dv_cipher_conf_t, cc_cert),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_CIPHER_CONF_KEY,
        .cp_len = sizeof(dv_cipher_config.cc_key),
        .cp_offset = dv_offsetof(dv_cipher_conf_t, cc_key),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_CIPHER_CONF_CA,
        .cp_len = sizeof(dv_cipher_config.cc_ca),
        .cp_offset = dv_offsetof(dv_cipher_conf_t, cc_ca),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
};

#define DV_CIPHER_CONF_ARRAY_SIZE DV_ARRAY_SIZE(dv_cipher_conf)


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
    strncpy((void *)conf + p->cp_offset, val_str, p->cp_len - 1);
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
        DV_LOG(DV_LOG_EMERG, "Parse %s failed!\n", root_name);
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
            DV_LOG(DV_LOG_EMERG, "%s not exist!\n", p->cp_name);
            goto out;
        }

        type = json_object_get_type(param);
        if (p->cp_type != type) {
            ret = DV_ERROR;
            DV_LOG(DV_LOG_EMERG, "Type(%d) not match(%d)!\n", p->cp_type, type);
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

static int
dv_cipher_conf_parse_ciphers(dv_cipher_conf_t *conf, char *key_word, char *file)
{
    json_object             *obj = NULL;
    json_object             *sub_obj = NULL;
    json_object             *a_obj = NULL;
    json_object             *param = NULL;
    json_object             *p = NULL;
    const char              *val_str = NULL;
    int                     len = 0;
    int                     type = 0;
    int                     i = 0;
    int                     ret = DV_OK;

    obj = dv_conf_parse(file, key_word, &sub_obj);
    if (obj == NULL) {
        DV_LOG(DV_LOG_EMERG, "Parse %s failed!\n", key_word);
        ret = DV_ERROR;
        goto out;
    }

    if (!json_object_object_get_ex(sub_obj, DV_CIPHER_CONF_CIPHERS, &p)) {
        DV_LOG(DV_LOG_INFO, "Parse %s failed!\n", DV_CIPHER_CONF_CIPHERS);
        goto out;
    }

    len = json_object_array_length(p);
    for (i = 0; i < len && i < DV_PROTO_CIPHER_MAX_NUM; i++) {
        a_obj = json_object_array_get_idx(p, i);
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

int
dv_cipher_conf_parse(dv_cipher_conf_t *conf, char *key_word, char *file)
{
    int                 ret = DV_OK;

    ret = dv_config_parse(file, conf, key_word, dv_cipher_conf,
            DV_CIPHER_CONF_ARRAY_SIZE);
    if (ret != DV_OK) {
        return ret;
    }

    return dv_cipher_conf_parse_ciphers(conf, key_word, file);
}

