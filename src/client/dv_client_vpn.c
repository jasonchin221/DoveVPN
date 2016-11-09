
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_msg.h"
#include "dv_if.h"
#include "dv_log.h"

int
dv_client_set_tun_ip(char *dev, const dv_proto_suite_t *suite, void *ssl)
{
    dv_msg_ipaddr_t     msg = {};
    int                 rlen = 0;
    int                 ret = DV_OK;

    rlen = suite->ps_read(ssl, &msg, sizeof(msg));
    if (rlen < sizeof(msg)) {
        DV_LOG(DV_LOG_INFO, "Read tun msg failed, rlen = %d\n", rlen);
        return DV_ERROR;
    }

    if (msg.mi_header.mh_type != DV_MSG_TYPE_IPADDR) {
        DV_LOG(DV_LOG_INFO, "Tun msg header invalid, type = %d\n",
                msg.mi_header.mh_type);
        return DV_ERROR;
    }

    DV_LOG(DV_LOG_DEBUG, "ip = %s, mask = %zu, rlen = %d, msg = %d\n",
            msg.mi_ip, msg.mi_mask, rlen, (int)sizeof(msg));
    ret = dv_if_set(dev, msg.mi_ip, msg.mi_mask, msg.mi_mtu);
    if (ret != DV_OK){
        DV_LOG(DV_LOG_INFO, "Set if failed\n");
        return DV_ERROR;
    }

    ret = dv_route_set(dev, msg.mi_route_net, msg.mi_route_mask);
    if (ret != DV_OK){
        DV_LOG(DV_LOG_INFO, "Set route failed\n");
        return DV_ERROR;
    }

    return DV_OK;
}
