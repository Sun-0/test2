
#ifndef FLEXER_READER_H
#define FLEXER_READER_H 1

#include "tawflexer.h"
#include  <ngtawstd/libconfig.h>
int tawflexer_readfile(tawflexer_t* flexer,const char* filename);

int tawflexer_readdir_tolist(ts_list_t* flexer_head,const char* dirname);

static inline int tawflexer_readdir(const char* dirname)
{
    return  tawflexer_readdir_tolist(&all_flexer,dirname);
}


#endif
