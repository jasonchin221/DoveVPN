#ifndef __DV_EVENT_H__
#define __DV_EVENT_H__

#include <event2/event.h>

#include "dv_types.h"

#define DV_READ_EVENT               EV_READ 
#define DV_WRITE_EVENT              EV_WRITE
#define DV_EVENT_FLAGS_NEED_FREE    0x01

typedef event_callback_fn dv_event_handler;

typedef struct _dv_event_t {
    struct event        *et_ev;
    struct timeval      *et_timeout;
    dv_event_handler    et_handler;
    dv_u32              et_flags;
    void                *et_peer_ev;
    void                *et_conn;
    void                (*et_conn_free)(void *conn);
} dv_event_t;

typedef struct _dv_event_register_t {
    dv_event_t      *er_ev;
    int             er_sockfd;
} dv_event_register_t;

static inline void
dv_event_conn_set(dv_event_t *ev, void *conn, int fd, dv_event_handler handler,
        void (*event_set)(int, dv_event_t *))
{
    ev->et_conn = conn;
    ev->et_handler = handler;
    event_set(fd, ev);
}
   
extern dv_event_t *dv_event_create(void);
extern int dv_event_destroy(dv_event_t *event);
extern int dv_event_init(void);
extern void dv_event_exit(void);
extern void dv_event_set(int s, dv_event_t *event, short type);
extern void dv_event_set_read(int s, dv_event_t *event);
extern void dv_event_set_persist_read(int s, dv_event_t *event);
extern void dv_event_set_write(int s, dv_event_t *event);
extern int dv_event_add(dv_event_t *event);
extern int dv_event_del(dv_event_t *event);
extern int dv_process_events(void);

#endif
