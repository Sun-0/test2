
#include "logger.h"
#include "logger_reader.h"
#include "tawflexer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int tawlogger_read_config(taw_logger_t* logger,config_setting_t* setting)
{
/* config:
        name="topsec";
        reciver="syslog";
        type="Firewall/TOPSEC/TOS/V005";
        flexer="天融信TOS005防火墙";
      */

    if(setting == NULL)
        return -1;

    const char* strv=NULL;
    config_setting_lookup_string(setting,"name",&strv);
    if(strv == NULL)
    {
        return -2;
    }
    strncpy(logger->name, strv, TAW_LOGGER_NAME_MAXLEN);
    strv=NULL;    
      
    config_setting_lookup_string(setting,"type",&strv);
    strncpy(logger->type, strv, TAW_LOGGER_NAME_MAXLEN);
    strv=NULL;   
      
    config_setting_lookup_string(setting,"reciver",&strv);
    if(strv == NULL)
    {
        return -4;
    }
    strncpy(logger->reciver_name, strv, TAW_LOGGER_NAME_MAXLEN);
    strv=NULL;   

    config_setting_lookup_string(setting,"flexer",&strv);
    if(strv == NULL)
    {
        return -5;
    }
    logger->flexer = tawflexer_find(strv);
    if(logger->flexer== NULL)
        return -6;
    strv=NULL;   


    config_setting_lookup_string(setting,"addr",&strv);
    
    if(strv)
    {
        inet_aton(strv, &logger->ipv4);
    }
    strv=NULL;   

    return 0;
}




