#ifndef TAW_RECIVER_READER_H
#define TAW_RECIVER_READER_H

#include <ngtawstd/libconfig.h>
#include "reciver.h"




int tawreciver_read_config(taw_reciver_t * reciver,config_setting_t* setting);
static inline int tawreciver_read_config_tolist(ts_list_t* reciver_head,config_setting_t* setting)
{
    taw_reciver_t* t = taw_reciver_new();
    if(tawreciver_read_config(t,setting)==0)
    {
        //ts_list_add_tail(reciver_head,&t->next);
        ts_list_add_tail(&t->next, reciver_head);
    }
    else
    {
        taw_reciver_free(t);

    }
    return 0;
}

static inline int taw_reciver_readlist(config_setting_t* setting)
{
    int l = config_setting_length(setting);
    int i=0;
    for(i=0;i<l;i++)
    {
        tawreciver_read_config_tolist(&reciver_head,config_setting_get_elem(setting,i));
    }
    return 0;
}



#endif//TAW_RECIVER_READER_H
