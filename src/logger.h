#ifndef TAW_LOGGER_H__
#define TAW_LOGGER_H__

#include "reciver.h"
#include "tawflexer.h"

#define TAW_LOGGER_NAME_MAXLEN 128

typedef struct taw_logger
{
    char name[TAW_LOGGER_NAME_MAXLEN];
    char type[TAW_LOGGER_NAME_MAXLEN];
    char reciver_name[TAW_LOGGER_NAME_MAXLEN];
    struct in_addr ipv4;
    taw_reciver_t* reciver;
    tawflexer_t* flexer;//parser
}taw_logger_t;

taw_logger_t* taw_logger_new() ;
void taw_logger_free(taw_logger_t* t);

#endif
