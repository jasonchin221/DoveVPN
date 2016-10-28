#ifndef __DV_CLIENT_PROCESS_H__
#define __DV_CLIENT_PROCESS_H__

enum {
    DV_CLI_EVENT_SSL,
    DV_CLI_EVENT_TUN,
    DV_CLI_EVENT_MAX,
};

extern int dv_client_process(dv_client_conf_t *conf);

#endif
