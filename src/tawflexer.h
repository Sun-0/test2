/*!
 *  @file   tawflexer.h
 *  @brief  
 *  
 *  <+DETAILED+>
 *  
 *  @author  ZHANG Fengyu (张凤羽), zhang_fengyu@topsec.com.cn
 *  
 *  @internal
 *    Created:       11/04/16
 *    Revision:      none
 *    Compiler:      gcc
 *    Organization:  TAW
 *    Copyright:     Copyright (c) 2016, ZHANG Fengyu
 *  
 *  This source code is released for free distribution under the terms of the
 *  GNU General Public License as published by the Free Software Foundation.
 */


#ifndef  tawflexer_INC
#define  tawflexer_INC


#include <ngtawstd/zytypes.h>
#include <ngtawstd/array.h>
#include <pcre.h>
#include "functions.h"

#define TAW_FLEXER_NAME_MAX_LEN 128
#define TAW_FLEXER_TYPE_MAX_LEN 128
#define TAW_FLEXER_INPUTNAME_MAX_LEN 128


enum tawflexer_expression_type
{
    TAW_FLEXER_EXPRESSION_WELF=0,
    TAW_FLEXER_EXPRESSION_ENC,
    TAW_FLEXER_EXPRESSION_REG,
};

typedef struct tawflexer_config
{
    char addr[128];
    char type[128];
    char name[128];
    int num;
}tawflexer_config_loggers;

typedef struct tawflexer_tokenmaper
{
    char name[TAW_FLEXER_NAME_MAX_LEN];
    char value[TAW_FLEXER_NAME_MAX_LEN];
    tawf_function_t* func;
    int remove;
    ts_list_t next;
}tawflexer_tokenmapper_t;

typedef struct tawflexer_tokenmaps
{
    uint16_t maps_flag;           //maps链表元素, 0:没有, 1:有
    uint16_t tokenmaps_flag;      //tokenmaps链表元素, 0:没有, 1:有
    struct zypattern* pt;
    ts_list_t maps;
    ts_list_t tokenmaps;
    ts_list_t next;  
    char token_type[128];
}tawflexer_tokenmaps_t;

typedef struct tawflexer_tokens
{
    char name[TAW_FLEXER_NAME_MAX_LEN];
    char value[TAW_FLEXER_NAME_MAX_LEN];
    ts_list_t next;
}tawflexer_tokens_t;


struct tawflexer_enc_name
{
    short id_start;
    short id_end;
    char name[TAW_FLEXER_NAME_MAX_LEN];
};
TS_ARRAY_DEF(tawflexer_enc_name_array, struct tawflexer_enc_name);


struct tawflexer_pcre_name
{
    char name[TAW_FLEXER_NAME_MAX_LEN];
};
TS_ARRAY_DEF(tawflexer_pcre_name_array, struct tawflexer_pcre_name);

typedef struct tawflexer_expression
{
    char input[TAW_FLEXER_INPUTNAME_MAX_LEN];
    enum tawflexer_expression_type type;
    union{
        struct{
            pcre * reg;
            int id_to_name;
            tawflexer_pcre_name_array_t * reg_names;
        };
        struct{
            char sep;
            char quote_start;
            char quote_end;
            int max_field;
            tawflexer_enc_name_array_t * enc_names;
        };
    };
    char token_type[32];
    uint16_t maps_flag;         //0:公有maps不存在,1:存在
    uint16_t tokenmaps_flag;
    ts_list_t maps;
    ts_list_t tokens;
    ts_list_t tokenmaps;
    ts_list_t next; 

} tawflexer_expression_t;

typedef struct tawflexer
{
    ts_list_t next;
    char name[TAW_FLEXER_NAME_MAX_LEN]; 
    char type[TAW_FLEXER_NAME_MAX_LEN]; 
    char exp_type[TAW_FLEXER_NAME_MAX_LEN]; 
    ts_list_t expressions;
}tawflexer_t;

extern ts_list_t all_flexer;

tawflexer_tokenmapper_t * tawflexer_tokenmapper_new();
tawflexer_tokenmaps_t* tawflexer_tokenmaps_new();
tawflexer_expression_t*  tawflexer_expression_new();
tawflexer_t* tawflexer_new();
tawflexer_tokens_t * tawflexer_token_new();
void tawflexer_free(tawflexer_t* f);

static inline tawflexer_t* tawflexer_find(const char* name)
{
    tawflexer_t * f =NULL;
    ts_list_for_each_entry(f, &all_flexer, next)
    {
        if(strcasecmp(f->name, name)==0) {
            return f;
        }
    }
    return NULL;
}

int tawflexer_run(tawflexer_t* flexer, ZYMap* m);
int tawflexer_exp_do_tokenmaps(tawflexer_expression_t* e, ZYMap* m, int flag);
int tawflexer_exp_do_maps(tawflexer_expression_t* e, tawflexer_tokenmaps_t* t, ZYMap* m, int *match_num, int flag);

#endif   /* ----- #ifndef tawflexer_INC  ----- */
