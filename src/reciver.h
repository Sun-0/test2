#ifndef TAW_RECIVER_H
#define TAW_RECIVER_H
#include <ngtawstd/list.h>
#include <ngtawstd/btree.h>
#include <uv.h>
#include "tawflexer.h"
#include "udp.h"
enum taw_reciver_type
{
    TAW_RECIVER_UDP=0,
};

#define TAW_RECIVER_NAME_MAXLEN 128
typedef struct taw_reciver
{
    char name[TAW_RECIVER_NAME_MAXLEN];
    enum taw_reciver_type type;
    char addr[TAW_RECIVER_NAME_MAXLEN];
    int port;
    struct ts_btree* loggers; //next for type list
    ts_list_t next;
    union {
        udp_server_t udp;
    };
    int event;
}taw_reciver_t;


taw_reciver_t* taw_reciver_new();

void taw_reciver_free(taw_reciver_t* r);

extern ts_list_t reciver_head;

int taw_reciver_start(taw_reciver_t* r, uv_loop_t* loop);
static inline int taw_reciver_start_all(uv_loop_t* loop)
{

    taw_reciver_t* r;
    ts_list_for_each_entry(r, &reciver_head, next)
    {
        taw_reciver_start(r, loop);
    }
    return 0;
}

#endif
