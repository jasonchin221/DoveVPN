#ifndef __DV_CONF_H__
#define __DV_CONF_H__

#include <json-c/json.h>
#include <json-c/json_util.h>

#include "dv_types.h"

#define DV_IP_ADDRESS_LEN       32
#define DV_CONF_STR_LEN         256

typedef struct _dv_cipher_conf_t {
    char        cc_proto_type[DV_CONF_STR_LEN];
    char        cc_cert[DV_CONF_STR_LEN];
    char        cc_key[DV_CONF_STR_LEN];
    char        cc_ca[DV_CONF_STR_LEN];
} dv_cipher_conf_t;

typedef struct _dv_conf_parse_t {
    const char  *cp_name;
    dv_u32      cp_len;
    dv_u32      cp_offset;
    int         cp_type;
    dv_bool     cp_necessary;
    void        (*cp_parse)(void *conf, json_object *param,
                    const struct _dv_conf_parse_t *p);
} dv_conf_parse_t;

extern json_object *dv_conf_parse(char *file, const char *key_name,
        json_object **sub_obj);
extern void dv_conf_parse_int(void *conf, json_object *param,
            const dv_conf_parse_t *p);
extern void dv_conf_parse_str(void *conf, json_object *param,
            const dv_conf_parse_t *p);
extern int dv_config_parse(char *file, void *conf, const char *root_name, 
        const dv_conf_parse_t *array, dv_u32 array_num);
extern int dv_cipher_conf_parse(dv_cipher_conf_t *conf, 
        char *key_word, char *file);

#endif
