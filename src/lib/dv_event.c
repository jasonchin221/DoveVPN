#include <stdlib.h>
#include <string.h>

#include "dv_event.h"
#include "dv_errno.h"
#include "dv_types.h"
#include "dv_log.h"
#include "dv_mem.h"

#define DV_SOCKET_MAX_NUM       110000

/* the global event_base */
static struct event_base *
dv_event_base = NULL;

static dv_event_register_t
dv_event_register_array[DV_SOCKET_MAX_NUM] = {};

int
dv_process_events(void)
{
    return event_base_loop(dv_event_base, 0);
}

int
dv_event_init(void)
{
    if (dv_event_base == NULL) {
        dv_event_base = event_base_new();
        if (dv_event_base == NULL) {
            return DV_ERROR;
        }
    }

    return DV_OK;
}

/**
 * dv_event_exit - exit events
 * @
 *
 * return DV_OKg on success
 */
void
dv_event_exit(void)
{
    //dv_event_remove_registered();
    if (dv_event_base != NULL) {
        event_base_free(dv_event_base);
    }
}

void 
dv_event_set(int s, dv_event_t *event, short type)
{
    /* set here means delete the old one and assign a new one */
    if (event->et_ev) {
        event_free(event->et_ev);
    }

    event->et_ev = event_new(dv_event_base, s, type, 
                    event->et_handler, (void *)event);
    if (event->et_ev == NULL) {
        DV_LOG(DV_LOG_NOTICE, "Event_new failed!\n");
    }
}

void 
dv_event_set_read(int s, dv_event_t *event)
{
    dv_event_set(s, event, EV_READ|EV_ET);
}

void 
dv_event_set_persist_read(int s, dv_event_t *event)
{
    dv_event_set(s, event, EV_READ|EV_PERSIST);
}

void 
dv_event_set_write(int s, dv_event_t *event)
{
    dv_event_set(s, event, EV_WRITE|EV_ET);
}

int 
dv_event_add(dv_event_t *event)
{
    int  err;

    err = event_add(event->et_ev, event->et_timeout);
    if (err < 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

int 
dv_event_del(dv_event_t *event)
{
    int  err;

    err = event_del(event->et_ev);
    if (err < 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

/**
 * dv_event_create - create a new event
 * @
 *
 * return address of new event on success;
 * NULL for failed.
 */
dv_event_t * 
dv_event_create(void)
{
    dv_event_t* event;

    event = dv_calloc(sizeof(*event));
    if (!event) {
        DV_LOG(DV_LOG_NOTICE, "Malloc event failed!\n");
        return NULL;
    }

    event->et_flags |= DV_EVENT_FLAGS_NEED_FREE;

    return event;
}

/**
 * dv_event_destroy - destroy an event
 * @event: event to destroy
 *
 *
 * return DV_OKg on success;
 * -1 for failed.
 */
int 
dv_event_destroy(dv_event_t *event)
{
    if (!event) {
        /*TODO: add error log */
        return DV_ERROR;
    }

    if (event->et_ev) {
        event_free(event->et_ev);
    }

    if (event->et_timeout) {
        dv_free(event->et_timeout);
    }

    if (event->et_conn_free) {
        event->et_conn_free(event->et_conn);
    }

    if (event->et_flags & DV_EVENT_FLAGS_NEED_FREE) {
        dv_free(event);
    }

    return DV_OK;
}

int
dv_event_register(dv_event_register_t *event) 
{
    int i = 0;

    if (event == NULL) {
        return DV_ERROR;
    }

    for (i = 0; i < DV_SOCKET_MAX_NUM; i++) {
        if (dv_event_register_array[i].er_ev == NULL) {
            dv_event_register_array[i] = *event;
            return DV_OK;
        }
    }

    return DV_ERROR;
}

int
dv_event_unregister(int sockfd) 
{
    dv_event_register_t *er = NULL;
    int                 i = 0;

    for (i = 0; i < DV_SOCKET_MAX_NUM; i++) {
        er = &dv_event_register_array[i];
        if (er->er_ev != NULL && er->er_sockfd == sockfd) {
            dv_event_del(er->er_ev);
            dv_event_destroy(er->er_ev);
            memset(er, 0, sizeof(*er));
            return DV_OK;
        }
    }

    return DV_ERROR;
}

#if 0
static void
dv_event_remove_registered(void)
{
    int i = 0;

    for (i = 0; i < DV_SOCKET_MAX_NUM; i++) {
        if (dv_event_register_array[i].er_ev == NULL) {
            continue;
        }
        dv_event_del(dv_event_register_array[i].er_ev);
    }
}
#endif

void 
dv_event_set_timer(dv_event_t *tmout)
{
    if (tmout->et_ev) {
        event_free(tmout->et_ev);
    }

    tmout->et_ev = evtimer_new(dv_event_base, tmout->et_handler, 
                    (void*)tmout);
    if (tmout->et_ev == NULL) {
        DV_LOG(DV_LOG_INFO, "Evtime_new failed!\n");
    }
}

#if 0
int
dv_event_prepare(void)
{
    dv_event_t *event = NULL;
    int sockfd = 0;
    int i = 0;
    int err = DV_OK;

    dv_event_base = event_base_new();
    if (dv_event_base == NULL) {
        return DV_ERROR;
    }

    for (i = 0; i < DV_SOCKET_MAX_NUM; i++) {
        event = dv_event_register_array[i].er_ev;
        if (event == NULL) {
            continue;
        }

        sockfd = dv_event_register_array[i].er_sockfd;
        dv_log("TCP socket is %d!\n", sockfd);
        dv_event_set_read(sockfd, event);

        err = dv_event_add(event);
        if (err != DV_OK) {
            dv_log("Add registered event failed!sockfd = %d\n",sockfd);
            goto event_exit;
        }
    }

out:
    return err;
event_exit:
    event_base_free(dv_event_base);
    goto out;
}

#endif
