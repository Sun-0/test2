
#ifndef TAW_LOGGER_READER_H
#define TAW_LOGGER_READER_H

#include <ngtawstd/libconfig.h>

#include "logger.h"

extern int loggers_num;

int tawlogger_read_config(taw_logger_t* logger,config_setting_t* setting);

static inline int tawlogger_read_config_toreciver(config_setting_t* setting)
{
    int i __tawstd_unused;
    taw_logger_t* t = taw_logger_new();
    taw_reciver_t* r =NULL;
    if(tawlogger_read_config(t,setting)==0)
    {
        ts_list_for_each_entry(r,&reciver_head,next)
        {
            if(strcasecmp(r->name,t->reciver_name) == 0)
            {
                i = ts_btree_insert(r->loggers,&t->ipv4,sizeof(t->ipv4),t);
                return 0;
            }
        }
    }
    else
    {
        taw_logger_free(t);
    }
    return -1;
}

static inline int taw_logger_readlist(config_setting_t* setting)
{
    int l = config_setting_length(setting);
    loggers_num = l;
    int i=0;
    for(i=0;i<l;i++)
    {
        tawlogger_read_config_toreciver(config_setting_get_elem(setting,i));
    }
    return 0;
}

#endif//TAW_LOGGER_READER_H

