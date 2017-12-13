/*!
 *  @file   tawflexer.c
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

#include "tawflexer.h"
#include "functions.h"
#include "udp.h"
#include <time.h>

TS_LIST_HEAD(all_flexer);

tawflexer_tokenmapper_t * tawflexer_tokenmapper_new()
{
    tawflexer_tokenmapper_t *m = taw_zalloc_type(tawflexer_tokenmapper_t);
    TS_INIT_LIST_HEAD(&m->next);
    return m;
}

tawflexer_tokens_t * tawflexer_token_new()
{
    tawflexer_tokens_t *t = taw_zalloc_type(tawflexer_tokens_t);
    TS_INIT_LIST_HEAD(&t->next);
    return t;
}

tawflexer_tokenmaps_t* tawflexer_tokenmaps_new()
{ 
    tawflexer_tokenmaps_t *m = taw_zalloc_type(tawflexer_tokenmaps_t);
    TS_INIT_LIST_HEAD(&m->maps);
    TS_INIT_LIST_HEAD(&m->next);
    TS_INIT_LIST_HEAD(&m->tokenmaps);
    return m;
}

void tawflexer_tokenmapper_free(tawflexer_tokenmapper_t* e)
{
    FREEPTR(e);
}

void tawflexer_tokenmaps_free(tawflexer_tokenmaps_t* f)
{

    tawflexer_tokenmapper_t* e;
    tawflexer_tokenmapper_t * save;
    ts_list_for_each_entry_safe(e,save,&(f->maps),next)
    {
        ts_list_del(&e->next);
        tawflexer_tokenmapper_free(e);
    }
    FREEPTR(e);
}

tawflexer_expression_t* tawflexer_expression_new()
{
    tawflexer_expression_t *e = taw_zalloc_type(tawflexer_expression_t);
    TS_INIT_LIST_HEAD(&e->maps);
    TS_INIT_LIST_HEAD(&e->tokens);
    TS_INIT_LIST_HEAD(&e->tokenmaps);
    TS_INIT_LIST_HEAD(&e->next);
    return e;
}

void tawflexer_expression_free(tawflexer_expression_t* e)
{
    if(e->type == TAW_FLEXER_EXPRESSION_REG && e->reg)
    {
        pcre_free(e->reg);
        e->reg=NULL;
    }
    tawflexer_tokenmaps_t* t;
    tawflexer_tokenmaps_t * save;
    ts_list_for_each_entry_safe(t,save,&(e->tokenmaps),next)
    {
        ts_list_del(&t->next);
        tawflexer_tokenmaps_free(t);
    }

    FREEPTR(e);
}

tawflexer_t* tawflexer_new()
{
    tawflexer_t* f = taw_zalloc_type(tawflexer_t);
    TS_INIT_LIST_HEAD(&f->expressions);
    TS_INIT_LIST_HEAD(&f->next);
    return f;
}

void tawflexer_free(tawflexer_t* f)
{
    tawflexer_expression_t* e;
    tawflexer_expression_t* save;
    ts_list_for_each_entry_safe(e,save,&(f->expressions),next)
    {
        ts_list_del(&e->next);
        tawflexer_expression_free(e);
    }
    FREEPTR(f);
}

int tawflexer_exp_do_maps(tawflexer_expression_t* e, tawflexer_tokenmaps_t* t, ZYMap* m, int *match_num, int flag)
{
    ZYElem* item = NULL;
    tawflexer_tokenmapper_t* mapper; 
    int i = 0, ret = 0;
    void* val=NULL;
    ts_list_t *tokens;
    if(e != NULL && e->maps_flag == 1)
        tokens = &e->maps;
    else if (t != NULL && t->maps_flag == 1){   //maps存在
        tokens = &t->maps;
    }

    ts_list_for_each_entry(mapper, tokens, next){
        if(mapper->func){
            ZYElem e ;
            memset(&e, 0, sizeof(e));
            item = &e;
            tawf_do_func(mapper->func, m, item);

            if(item->type != ZYT_UNDEFINE && flag == 0) {//flag=0,统计数量
                (*match_num)++;

            }
            else if (item->type != ZYT_UNDEFINE && flag == 1) {
                val= (void*)zyelem_get_value(item);
                zymap_put_value(m,_K(mapper->name) , val, item->type, 0);
                zyelem_free_value(item);

                tawf_param_t* p;
                if(mapper->remove) {
                    TS_ARRAY_FOR_EACHP(&mapper->func->params, i, p) {
                        if(p->type == TAWF_PARAM_FIELD) {
                            zymap_remove(m, _K(p->str));
                        }
                    }
                }
            }
            else{
            }
        }
        else{
            ZYElem* item = zymap_get_elem(m, _K(mapper->value));
            //printf("mapper->value = %s\n", mapper->value);
            if(item){
                if(flag == 0)
                    (*match_num)++;
                if(flag == 1){
                    val= (void*)zyelem_get_value(item);
                    zymap_put_value(m,_K(mapper->name) , val, item->type, 0);

                    if(mapper->remove)
                        zymap_remove(m, _K(mapper->value));
                }
            }
        }
    }

    if( (t != NULL) && (t->tokenmaps_flag == 1)){
        tawflexer_tokenmaps_t* tokenmaps = NULL;
        ts_list_for_each_entry(tokenmaps, &t->tokenmaps, next){
            if(tokenmaps->pt){
                if( (ret = zy_pt_search(m , ZYT_MAP,tokenmaps->pt)) != 13)
                    continue;
            }        
            tawflexer_exp_do_maps(NULL, tokenmaps, m, match_num, flag);           
            break;
        }
        if (ret != 13)
            TLOG_DEBUG("zy_pt_search 条件匹配失败!!!");
    }
    else 
        return 0;

    return 0;
}

//flag 0:只记录成功匹配的数量不解析，1:解析
int tawflexer_exp_do_tokenmaps(tawflexer_expression_t* e, ZYMap* m, int flag)
{
    tawflexer_tokenmaps_t* tokens=NULL;
    int match_num = 0, ret = 0;

    if(e->maps_flag == 1){   //公有map存在
        tawflexer_exp_do_maps(e, NULL, m, &match_num, flag);
    }

    //zyprintf("${1@MPJ}", m);
    if(e->tokenmaps_flag == 1){
        ts_list_for_each_entry(tokens, &e->tokenmaps, next){
            if(tokens->pt){
                //printf("zy_pt_search == %d\n", zy_pt_search(m , ZYT_MAP,tokens->pt));
                if( (ret = zy_pt_search(m , ZYT_MAP,tokens->pt)) != 13)
                    continue;
            }
            tawflexer_exp_do_maps(NULL, tokens, m, &match_num, flag);
            break;
        }
        if (ret != 13)
            TLOG_DEBUG("zy_pt_search 条件匹配失败!!!");
    }

    return match_num;
}

int tawflexer_exp_run_welf(tawflexer_t* flexer, tawflexer_expression_t* e, ZYMap* m)
{
    char *start, *end;
    char buf[4096] = "";
    const char* str = zymap_get_str(m, _K(e->input));

    if(str == NULL)
        return 0;
    char* s = taw_strdup(str);
    //printf("s = %s\n", s);
    if (taw_is_linklog(s, buf) == 0) {
        start = buf;
        zymap_put_str(m, _K("ORIGINAL_DATA"), buf);
        zymap_put_str(m, _K("type"), "linkage_log");
        while ( (end = strchr(start, ';'))) {
            linklog_to_map(m, start, end-start+1);
            start = end + 1;
        }
        //zyprintf("linklog--${1@MPJ}", m);
    }
    else {
        func_WELFParse(s, m, e->max_field);
    }
    //do map
    tawflexer_exp_do_tokenmaps( e, m, 1);
    FREEPTR(s);
    return 0;
}
int list_to_map(const ZYList *list, ZYMap *map)
{
    if (list == NULL || map == NULL)
        return -1;
    const ZYList *l = list;
    ZYElem *elem = NULL;
    char *p = NULL;
    int num = 1;
    char str_num[3] = { 0 };

    ZYLIST_FOR_EACH(l, elem){
        sprintf(str_num, "%d", num++);
        p = zyelem_get_str(elem, 0);    
        //printf("p = %s\n", p);
        zymap_put_str(map, _K(str_num), p);
    }
#if 0
    char *key;
    int key_len;
    ZYMAP_FOR_EACH(map, key, key_len, elem) {
        printf("key = %s, value = %s\n", key, zyelem_get_str(elem, 0));
    }
#endif

    return 0;
}

int tawflexer_exp_run_enc(tawflexer_t* flexer,  tawflexer_expression_t* e, ZYMap* m)
{
    const char* str = zymap_get_str(m, _K(e->input));
    if(str == NULL)
        return 0;
    char* s = taw_strdup(str);
    ZYList* list = zylist(); 
#if 0
    printf("e->sep = %c\n", e->sep);
    printf("e->quote_start = %c\n", e->quote_start);
    printf("e->quote_end = %c\n", e->quote_end);
    printf("e->maxfile = %d\n", e->max_field);
#endif 
    func_EnclosureSeparator(s, list, e->sep, e->quote_start, e->quote_end, e->max_field);
    //printf("str =-- %s\n", str);

    //TODO: do tokens here
    list_to_map(list, m);
    tawflexer_exp_do_tokenmaps( e, m, 1);

    zylist_free(list);
    FREEPTR(s);
    return 0;
}
int tawflexer_exp_run_reg(tawflexer_t* flexer, tawflexer_expression_t* e, ZYMap* m)
{
    const char* str = zymap_get_str(m, _K(e->input));
    if(str == NULL)
        return 0;
    int  ovector[512];
    int  rc = pcre_exec(e->reg,  NULL,  str,  strlen(str),  0,  0,  ovector,  512);  
    if (rc < 0)  
    {                     //如果没有匹配，返回错误信息 
        printf("reg 没有匹配\n");
        return -1; 
    }   
    int i =0;
    char tmp[3] = { 0 };
    for (i = 0; i < rc; i++) 
    { 
        //分别取出捕获分组 $0整个正则公式 $1第一个() 
        const char* __tawstd_unused substring_start = str + ovector[2*i]; 
        int __tawstd_unused substring_length = ovector[2*i+1] - ovector[2*i]; 
        //TODO: do tokens here
        if (i >= 1) {
            sprintf(tmp, "%d", i);
            zymap_put_nstr(m, _K(tmp), substring_start, substring_length);
        }
    }

    tawflexer_exp_do_tokenmaps( e, m, 1);

    return 0;
}
int tawflexer_run(tawflexer_t* flexer, ZYMap* m)
{
    tawflexer_expression_t* e;
    ts_list_for_each_entry(e, &flexer->expressions, next)
    {
        switch(e->type)
        {
            case TAW_FLEXER_EXPRESSION_WELF:
                {
                    if(tawflexer_exp_run_welf(flexer, e, m)==0) {
                        goto finish;
                    }
                }
                break;
            case TAW_FLEXER_EXPRESSION_ENC:
                {
                    if(tawflexer_exp_run_enc(flexer, e, m)==0)
                        goto finish;
                }
                break;
            case TAW_FLEXER_EXPRESSION_REG:
                {
                    if(tawflexer_exp_run_reg(flexer, e, m)==0)
                        goto finish;
                }
                break;
        }
    }
finish:

    return 0;
}
