#include "logger.h"


taw_logger_t* taw_logger_new() 
{
    taw_logger_t* t =taw_zalloc_type(taw_logger_t);
   
    return t;
}

void taw_logger_free(taw_logger_t* t)
{
    FREEPTR(t);
}


