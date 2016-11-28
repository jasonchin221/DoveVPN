

#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_log.h"
#include "dv_test_conf.h"

#define DV_TEST_CONF_BACKEND    "backend"

dv_test_conf_t dv_test_conf;
static int dv_test_ip_parse(dv_backend_addr_t *addr, json_object *param);
static int dv_test_port_parse(dv_backend_addr_t *addr, json_object *param);

static dv_test_conf_parse_t dv_test_conf_paser[] = {
    {
        .cp_name = "ip",
        .cp_type = json_type_string,
        .cp_parser = dv_test_ip_parse,
    },
    {
        .cp_name = "port",
        .cp_type = json_type_int,
        .cp_parser = dv_test_port_parse,
    },
};

#define DV_TEST_CONF_ARRAY_SIZE DV_ARRAY_SIZE(dv_test_conf_paser)

static int
dv_test_ip_parse(dv_backend_addr_t *addr, json_object *param)
{
    const char      *ip = NULL;

    ip = json_object_get_string(param);
    if (ip == NULL) {
        return DV_ERROR;
    }

    if (dv_ip_version4(ip)) {
        addr->ba_addr.ba_addr4.sin_family = AF_INET,
        addr->ba_addr.ba_addr4.sin_addr.s_addr = inet_addr(ip);
    } else {
        addr->ba_addr.ba_addr6.sin6_family = AF_INET6,
        inet_pton(AF_INET6, ip, &addr->ba_addr.ba_addr6);
    }

    return DV_OK;
}

static int 
dv_test_port_parse(dv_backend_addr_t *addr, json_object *param)
{
    struct sockaddr     *sk = NULL;
    int                 port = 0;

    sk = (struct sockaddr *)&addr->ba_addr;
    port = json_object_get_int(param);
    if (sk->sa_family == AF_INET) {
        addr->ba_addr.ba_addr4.sin_port = DV_HTONS(port);
    } else {
        addr->ba_addr.ba_addr6.sin6_port = DV_HTONS(port);
    }

    return DV_OK;
}

int
dv_test_conf_parse(dv_srv_conf_t *conf, char *file)
{
    json_object             *obj = NULL;
    json_object             *sub_obj = NULL;
    json_object             *a_obj = NULL;
    json_object             *param = NULL;
    dv_test_conf_parse_t    *parser = NULL;
    dv_backend_addr_t       *addr = NULL; 
    int                     len = 0;
    int                     type = 0;
    int                     i = 0;
    int                     j = 0;
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
        addr = &dv_test_conf.cf_backend_addrs[dv_test_conf.cf_backend_addr_num];
        for (j = 0; j < DV_TEST_CONF_ARRAY_SIZE; j++) {
            parser = &dv_test_conf_paser[i];
            if (!json_object_object_get_ex(a_obj, parser->cp_name, &param)) {
                continue;
            }
            type = json_object_get_type(param);
            if (type != parser->cp_type) {
                goto out;
            }
            if (parser->cp_parser(addr, param) != DV_OK) {
                goto out;
            }
            break;
        }

        if (j != DV_TEST_CONF_ARRAY_SIZE) {
            dv_test_conf.cf_backend_addr_num++;
        }
    }

out:
    if (obj != NULL) {
        json_object_put(obj);
    }

    return ret;
}

