
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_msg.h"
#include "dv_if.h"

int
dv_client_set_tun_ip(char *dev, const dv_proto_suite_t *suite, void *ssl)
{
    dv_msg_ipaddr_t     msg = {};
    int                 rlen = 0;
    int                 ret = DV_OK;

    rlen = suite->ps_read(ssl, &msg, sizeof(&msg));
    if (rlen < 0) {
        return DV_ERROR;
    }

    if (msg.mi_header.mh_type != DV_MSG_TYPE_IPADDR) {
        return DV_ERROR;
    }

    ret = dv_if_set_ip(dev, msg.mi_ip, msg.mi_mask);
    if (ret != DV_OK){
        return DV_ERROR;
    }

    return DV_OK;
}
