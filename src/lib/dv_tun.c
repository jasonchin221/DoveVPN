#include <sys/types.h>          /* See NOTES */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "dv_tun.h"
#include "dv_log.h"
#include "dv_types.h"
#include "dv_errno.h"

int
dv_tun_dev_create(dv_tun_t *tun, int i)
{
    struct ifreq    ifr = {};

    if ((tun->tn_fd = open(DV_DEV_TUN, O_RDWR)) < 0) {
        DV_LOG(DV_LOG_EMERG, "Cannot open %s\n", DV_DEV_TUN);
        return DV_ERROR;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name) - 1, "tun%d", i);
    strncpy(tun->tn_name, ifr.ifr_name, sizeof(tun->tn_name) - 1);
    if (ioctl(tun->tn_fd, TUNSETIFF, (void *)&ifr) < 0) {
        DV_LOG(DV_LOG_EMERG, "Cannot set tun for %s\n", ifr.ifr_name);
        close(tun->tn_fd);
        return DV_ERROR;
    }

    if (ioctl(tun->tn_fd, TUNSETPERSIST, 1) < 0){
        DV_LOG(DV_LOG_EMERG, "Enabling TUNSETPERSIST\n");
        close(tun->tn_fd);
        return DV_ERROR;
    }

    fcntl(tun->tn_fd, F_SETFL,O_NONBLOCK);

    return DV_OK;
}

int
dv_tun_dev_destroy(dv_tun_t *tun)
{
    if (tun->tn_fd < 0) {
        return DV_ERROR;
    }

    if (ioctl(tun->tn_fd, TUNSETPERSIST, 0) < 0) {
        DV_LOG(DV_LOG_EMERG, "Disabling TUNSETPERSIST\n");
        return DV_ERROR;
    }

    close(tun->tn_fd);
    return DV_OK;
}

int
dv_tun_init(dv_tun_t *tun)
{
    int         ret = DV_OK;

    ret = dv_tun_dev_create(tun, 0);
    if (ret != DV_OK) {
        tun->tn_fd = -1;
        return DV_ERROR;
    }

    return DV_OK;
}
    
void
dv_tun_exit(dv_tun_t *tun)
{
    if (tun->tn_fd < 0) {
        return;
    }
    dv_tun_dev_destroy(tun);
}
 
