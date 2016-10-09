#ifndef __DV_EVENT_H__
#define __DV_EVENT_H__

#include <event2/event.h>

#include "dv_types.h"

#define DV_READ_EVENT               EV_READ 
#define DV_WRITE_EVENT              EV_WRITE

typedef event_callback_fn dv_event_handler;

typedef struct _dv_event_t {
    struct event        *et_ev;
    struct timeval      *et_timeout;
    dv_event_handler    et_handler;
    dv_u32              et_flags;
//    void *conn;
 //   struct krk_buffer *buf;
  //  void *data;
}dv_event_t;

typedef struct _dv_event_register_t {
    dv_event_t      *er_ev;
    int             er_sockfd;
}dv_event_register_t;

extern dv_event_t* dv_event_create(dv_pool_t *pool);
extern void dv_event_set(int s, dv_event_t *event, short type);
extern void dv_event_set_read(int s, dv_event_t *event);
extern void dv_event_set_write(int s, dv_event_t *event);
extern dv_int dv_event_add(dv_event_t *event);

#endif
