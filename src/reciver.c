
#include <ngtawstd/common.h>
#include "reciver.h"
#include "logger.h"
TS_LIST_HEAD(reciver_head);

taw_reciver_t* taw_reciver_new()
{
    taw_reciver_t* t = taw_zalloc_type(taw_reciver_t);
    t->loggers = ts_btree_new(TS_BTREE_DEFAULT_M, TS_BTREE_BASE_DIFF, (ts_btree_data_free_func)&taw_logger_free);
    TS_INIT_LIST_HEAD(&t->next);
    return t;
}

void taw_reciver_free(taw_reciver_t* r)
{
    if(r == NULL)
        return;

    ts_btree_free(r->loggers);
    r->loggers=NULL;
    FREEPTR(r);
}


int taw_reciver_start_udp(taw_reciver_t* r, uv_loop_t* loop)
{
    r->udp.server.data = r;
    return udp_reciver_init( loop,&r->udp, r->addr,r->port);
}

int taw_reciver_start(taw_reciver_t* r, uv_loop_t* loop)
{
    switch(r->type)
    {
        case TAW_RECIVER_UDP:
            {
                taw_reciver_start_udp(r, loop);
            }
            break;
    }
    return 0;
}
