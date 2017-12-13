#include <ngtawstd/libconfig.h>
#include <sys/types.h>
#include <dirent.h>

#include "reciver_reader.h"

int tawreciver_read_config(taw_reciver_t * reciver,config_setting_t* setting)
{
    int ret = 0 ;

    if(setting == NULL)
        return -1;

    const char* strv=NULL;
    config_setting_lookup_string(setting,"name",&strv);
    if(strv == NULL)
    {
        return -2;
    }
    strncpy(reciver->name, strv, TAW_RECIVER_NAME_MAXLEN);

    strv=NULL;    
    config_setting_lookup_string(setting,"type",&strv);
    if(strv == NULL)
    {
        return -3;
    }
    if(strcasecmp(strv,"udp") == 0 )
    {
        reciver->type = TAW_RECIVER_UDP;
        //strv="0.0.0.0";    
        config_setting_lookup_string(setting,"addr",&strv);
        strncpy(reciver->addr, strv, TAW_RECIVER_NAME_MAXLEN);
        //int port=514;
        int port;
        config_setting_lookup_int(setting,"port",&port);
        reciver->port  = port;
    }

    int event;
    char *env;

    env = getenv("flexer_event");
    if(env != NULL) {
        event =  atoi(env);
        reciver->event = event==0?0:1;
        printf("flexer_event = %d\n",event);
    }
    else {
        config_setting_lookup_int(setting,"event",&event);
        reciver->event = event==0?0:1;
    }

    return ret;
}

