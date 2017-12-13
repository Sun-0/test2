/*!
 *  @file   syslogd.c
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

#include <uv.h>
#include <ngtawstd/common.h>



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "udp.h"
#include "reciver.h"
#include "logger.h"
#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>
#include <ngtawstd/zytypes.h>
#include <ngtawstd/libconfig.h>
#include "tawflexer.h"
#include "logger_reader.h"
#include <pthread.h>

#define MAX    (128)

int loggers_num = 0;
extern char pub_addr_port[64];
int list_to_map(ZYList* list, ZYMap* map);

int num = 0;
long int send_num = 1;
static void alloc_cb(uv_handle_t* handle,
        size_t suggested_size,
        uv_buf_t* buf) {
    if(suggested_size== 0)
        printf("free buffer \n");
    //printf("alloc buffer \n");
    static char slab[65536];
    buf->base = slab;
    buf->len = sizeof(slab);
}


static void __tawstd_unused close_cb(uv_handle_t* handle) {
    uv_is_closing(handle);
}

//判断是否是hostname
int is_hostname(char *url)
{
    char *start = NULL;
    char *end_h = NULL;
    char tmp_pub_addr[64] = { 0 };

    strcpy(tmp_pub_addr, pub_addr_port);
    if ( strstr(tmp_pub_addr, "tcp") == NULL)
        return 0;

    if ( (start = strchr(tmp_pub_addr, ':')) == NULL) {
        printf("1_nanomsg.conf error\n");
        exit(-1);
    }
    start+=3;

    //判断是否是hostname，解析hostname
    if(atoi(start)==0)
    {
        if ( (end_h= strchr(start, ':')) == NULL) {
            printf("2_nanomsg.conf error\n");
            exit(-1);
        }
        printf("start = %s\n",start);
        struct hostent *he;
        char host[40];
        char *host_p=host;
        while(*start&& *start!=':') *host_p++=*start++;
        *host_p=0;
        he = gethostbyname(host);
        printf("hostname %s \n",host);
        if(!he){

            printf("hostname %s error\n",host);
            exit(-1);
        }
        char destIP[128];
        if(he->h_addr_list)
            inet_ntop(he->h_addrtype,*he->h_addr_list,destIP,sizeof(destIP));
        sprintf(url,"tcp://%s%s",destIP,end_h);
        return 1;
    }

    return 0;
}

int nanomsg_server(void)
{
    char url[64] = { 0 };
    int len_str = 0;

    //建立socket链接
    int sock = nn_socket(AF_SP, NN_PUB);
    if (sock < 0) {
        fprintf (stderr, "nn_socket failed: %s\n", nn_strerror (errno));
        exit(-1);
    }

    //判断是否是hostname:port格式
    if ( is_hostname(url) ) {
        if(nn_bind(sock, url) < 0) {
            fprintf(stderr, "nn_bind failed: %s\n", nn_strerror(errno));
            exit(-1);
        }
    }
    else {
        printf("pub_addr_port = %s\n", pub_addr_port);
        if(nn_bind(sock, pub_addr_port) < 0) {
            fprintf(stderr, "nn_bind failed: %s\n", nn_strerror(errno));
            exit(-1);
        }
    }

    ZYMap* m = zymap();
    zymap_put_str(m, _K("s_eid"), "test");
    zymap_put_int8(m, _K("i_warninglevel"), 1);

    //zyprintf("${1@MPJ}", m); 
    void *str = zymap_dump_ptr(m, &len_str);
    sleep(3);
    nn_send(sock, str, len_str, 0);

    zymap_free(m);
    taw_free(str);

    return sock;
}

int fun_int(const char* data)
{
    int i = 0;
    size_t len = 0;
    const char* str = data;

    len = strlen(str);
    for (i = 0; i < len; ++i) {
        if ( '0' > *(data + i) || *(data+i) > '9') {
            return -1;
        }
    }
    return 0;
}

int fun_double(const char* data)
{
    const char* str = data;
    char* tmp = NULL;
    int len = 0, i = 0;

    if ( (tmp = strchr(str, '.')) == NULL)
        return -1;
    len = tmp - str + 1;
    for (i = 0; i < len; ++i) 
        if (*(tmp + i) < '0' || *(tmp + i) > '9') 
            return -1;

    tmp++;
    len = strlen(tmp);
    for (i = 0; i < len; ++i)
        if (*(tmp + i) < '0' || *(tmp + i) > '9') 
            return -1;

    return 0;

}

int fun_ip(const char* data)
{
    const char* str = data;
    char* tmp = NULL;
    int i = 0, len = 0;

    for (i = 0; i < 3; ++i) {
        if ( (tmp = strchr(str, '.')) == NULL)
            return -1;
        str = ++tmp;
    }
    tmp++;
    len = strlen(tmp);
    for (i = 0; i < len; ++i)
        if (*(tmp + i) < '0' || *(tmp + i) > '9') {
            return -1;
        }


    return 0;
}



int fun_time(const char* data)
{
    const char* str = NULL;
    char *tmp = NULL;
    //long int ret = 0;
    int i = 0;

    str = data;
    while( (tmp = strchr(str, '-')) != NULL) {
        str = ++tmp;
        i++;
    }
    if (i != 2)
        return -1;

    i = 0;
    while (  (tmp = strchr(str, ':')) != NULL) {
        str = ++tmp;
        i++;
    }
    if (i != 2)
        return -1;

    return 0;
}

int fun_mac(const char* data)
{
    const char* str = NULL;
    char* tmp = NULL;
    int num = 0;

    str = data;
    while ( (tmp = strchr(str, ':')) != NULL) {
        str = ++tmp;
        num++;
    }
    if (num != 5)
        return -1;

    return 0;
}

int taw_reciver_do_syslog(const taw_reciver_t* r, taw_logger_t* l,  const char* s, int len, char* addr)
{

    //fwrite(s, len, 1, stdout);
    //printf("\n");
    int len_str;
    void *str;

    ZYMap* m = zymap();
    zymap_put_nstr(m, _K("ORIGINAL_DATA"), s, len);
    zymap_put_str(m, _K("DATA_COLLECTION_TYPE"), l->reciver_name);
    zymap_put_str(m, _K("SECURITY_OBJECT_TYPE"), l->type);
    zymap_put_str(m, _K("client_addr"), addr);

    tawflexer_run(l->flexer, m);

    //zyprintf("${1@MPJ}", m); 
    str = zymap_dump_ptr(m, &len_str);
    nn_send(sockt, str, len_str, 0);
    printf("send_num = %ld\n", send_num++);
    zymap_free(m);
    taw_free(str);

    return 0;
}

//判断是否是enc格式
//mesg要解析的字符串
//是返回0，否返回-1
int taw_is_enc(const char* mesg) {

    const char * start, *end;

    if ( (start = strchr(mesg, '"')) == NULL) {
        for (; *mesg != '\0'; ++mesg)
            if (*mesg != ' ' && *mesg!= '\t')
                return -1;
            else
                return 0;
    }


    if ( mesg < start) {
        for (; mesg < start; mesg++) {
            if (*mesg != ' ' && *mesg != '\t') {
                return -1;
            }
        }
    }
    start++;

    if ( (end = strchr(start, '"')) == NULL)
        return -1;
    end++;

    if (*end == '\0' || *end == '\r' || *end == '\n')
        return 0;
    if ( *end != ' ')
        return -1;
    taw_is_enc(end);
    return 0;
}

int linklog_to_map(ZYMap *map, char *str, const int len)
{
    char *tmp, *pos, *end;
    const char sep_one = '=';
    const char sep_two = ';';

    if(str == NULL || len <2)
        return -1;
    pos = memchr(str, sep_one, len);
    end = memchr(str, sep_two, len);
    end--;
    if(pos == NULL)
        return -1;
    tmp = pos+1;
    pos--;
    while (*str == ' ')
        str++;
    while (*pos == ' ')
        pos--;
    while (*tmp == ' ')
        tmp++;
    while (*end == ' ')
        end--;
    zymap_put_nstr(map, _K(str, pos-str+1), tmp, end-tmp+1);

    return 0;

}

int tawflexer_match_exp(tawflexer_expression_t *e, ZYMap *m)
{
    tawflexer_tokenmaps_t *tokens = NULL;
    tawflexer_tokenmapper_t *mapper = NULL;
    void *key = NULL;
    int key_len  __tawstd_unused;
    int num = 0;
    ZYElem *elem  __tawstd_unused;

    ts_list_for_each_entry(tokens, &e->tokenmaps, next) {
        ZYMAP_FOR_EACH(m, key, key_len, elem) {
            ts_list_for_each_entry(mapper, &tokens->maps, next) {
                //          printf("key = %s, mapper->value = %s\n", key, mapper->value);
                if(strcmp(key, mapper->value) == 0) {
                    num++;
                    break;
                }
            }
        }
    }
    //printf("num = %d\n", num);
    return num;
}

int tawflexer_send_map(tawflexer_expression_t* e, ZYMap* m, char* str, const struct sockaddr_in* client_addr, tawflexer_config_loggers* l)
{
    int len;
    void* dump_map;
    zymap_put_nstr(m, _K("ORIGINAL_DATA"), str, strlen(str));
    zymap_put_str(m, _K("DATA_COLLECTION_TYPE"), "syslog");
    zymap_put_str(m, _K("SECURITY_OBJECT_TYPE"), l->type);
    zymap_put_str(m, _K("client_addr"), inet_ntoa(client_addr->sin_addr));
    tawflexer_exp_do_tokenmaps( e, m, 1);
    //zyprintf("${1@MPJ}", m); 

    dump_map = zymap_dump_ptr(m, &len);
    nn_send(sockt, dump_map, len, 0);
    printf("send_num = %ld\n", send_num++);

    taw_free(dump_map);
    return 0;
}
int analysis_linklog(char *str, const struct sockaddr_in* client_addr, tawflexer_config_loggers* loggers)
{
    char *start, *end;
    ZYMap *m = zymap();
    int num, ret = 0, mark = 0, equal = 0;
    tawflexer_t* flexer;
    tawflexer_expression_t* e;
    tawflexer_expression_t* tmp_e;

    start = str;
    while ( (end = strchr(start, ';'))) {
        linklog_to_map(m, start, end-start+1);
        start = end + 1;
    }

    ts_list_for_each_entry(flexer, &all_flexer, next) {
        //printf("flexer->name = %s\n", flexer->name);
        //printf("flexer->exp_type = %s\n", flexer->exp_type);
        if(strcmp(flexer->exp_type, "TAW_FLEXER_EXPRESSION_WELF") != 0) 
            continue;
        ts_list_for_each_entry(e, &flexer->expressions, next) {
            num = _ZMLen(m);
            ret = tawflexer_match_exp(e, m);
            //完全匹配
            if(num == ret){
                loggers->num = num;
                mark++;
                if (mark >= 2) {
                    tawflexer_send_map( e,  m, str, client_addr, loggers);
                    zymap_free(m);
                    return -2;
                }
                tmp_e = e;
                strncpy(loggers->name, flexer->name, TAW_FLEXER_NAME_MAX_LEN);
                strncpy(loggers->type, flexer->type, TAW_FLEXER_TYPE_MAX_LEN);
                strncpy(loggers->addr, inet_ntoa(client_addr->sin_addr), TAW_FLEXER_TYPE_MAX_LEN);
                break;

            }
            //取最大匹配度
            else if(ret >= loggers->num && !mark){
                if (ret == loggers->num)
                    equal = ret;
                loggers->num = ret;
                tmp_e = e;
                strncpy(loggers->name, flexer->name, TAW_FLEXER_NAME_MAX_LEN);
                strncpy(loggers->type, flexer->type, TAW_FLEXER_TYPE_MAX_LEN);
                strncpy(loggers->addr, inet_ntoa(client_addr->sin_addr), TAW_FLEXER_TYPE_MAX_LEN);
            }
        }

    }
    if (ret == 0) {
        zymap_free(m);
        return -1;
    }
    if (equal == loggers->num) {
        tawflexer_send_map( tmp_e,  m, str, client_addr, loggers);
        zymap_free(m);
        return -2;
    }
    else {
        tawflexer_send_map( tmp_e,  m, str, client_addr, loggers);
        zymap_free(m);
    }

    return 0;
}
int taw_is_linklog(const char* str, char* buf)
{
    int i = 0, len;
    char *start, *end;
    strcpy(buf, str);
    len = strlen(buf);

    //printf("buf = %s\n", buf);
    for (i = 0 ; i < len; ++i) {
        buf[i] = (char)(buf[i]^0xa6);
    }

    if ( (end = strchr(buf, ';')) == NULL) {
        return -1;
    }
    if ( (start = strchr(buf, '=')) == NULL) 
        return -1;
    if (start > end) 
        return -1;

    return 0;
}

int taw_is_welf(const char* mesg)
{
    const char *start, *end, *tmp_end;;
    char tmp[512] = { 0 };
    char *tmp_str = NULL;
    char *space1 = NULL;
    char *space2 = NULL;
    char *quot = NULL;
    printf("mesg = %s\n", mesg);

    start = mesg;
    //判断第一个等号有几个key，一个返回0;
    if ( (end = strchr(mesg, '=')) != NULL) {
        tmp_end = end + 1;
        end--;
        while(*start == ' ')
            start++;
        while(*end == ' ')
            end--;
        strncpy(tmp, start, end-start+1);
        if(strchr(tmp, ' ') != NULL)
            return -1;
    }
    else
        return -1;

    while( (end = strchr(tmp_end, '='))) {
        start = tmp_end;
        tmp_end = end + 1;
        end = end - 1;
        while(*start == ' ')
            start++;
        while(*end == ' ')
            end--;
        bzero(tmp, 512);
        strncpy(tmp, start, end-start+1);
        if( (quot = strchr(tmp, '"')) != NULL) {
            quot = strchr(++quot, '"');
            tmp_str = quot;
        }
        else
            tmp_str = tmp;
        while( (space1 = strchr(tmp_str, ' ')) != NULL) {
            tmp_str = space1+1;
            if(space2 != NULL) {
                if(*space1 != *(space2+1)) {
                    printf("tmp1 = %s\n", space1);
                    printf("tmp2 = %s\n", space2);
                    return -1;
                }
            }
            space2 = space1;
        }
        space1 = NULL;
        space2 = NULL;
    }


    return 0;
}



int taw_study_close(const uv_buf_t* rcvbuf, ssize_t nread, const taw_reciver_t *r, const struct sockaddr* addr)
{
    taw_logger_t* l = NULL;
    char client_ip[32] = { 0 };
    struct sockaddr_in* client_addr;

    client_addr = (struct sockaddr_in*)addr;
    strncpy(client_ip,inet_ntoa(client_addr->sin_addr), sizeof(client_ip));
    printf("client_ip = %s\n", client_ip);

    printf("num = %d\n", ++num);
    switch(addr->sa_family)
    {
        case  AF_INET:
            {
                l=ts_btree_find(r->loggers, &(((struct sockaddr_in*)addr)->sin_addr),sizeof(struct in_addr) );
            }
            break;
        case AF_INET6:
            l=ts_btree_find(r->loggers, &(((struct sockaddr_in6*)addr)->sin6_addr),sizeof(struct in6_addr) );
            break;
    }


    if(l == NULL) {
        printf("l == NULL\n");
        return -1;
    }
    if(l->flexer == NULL)
        return -1;


    const char* s = rcvbuf->base;
    ssize_t len = nread;
    int rest = nread;
    const char* pos = NULL;
    //trim \r\n
    while(rest > 0)
    {
        pos = memchr(s,  '\r', rest);
        if(pos == NULL)
            pos = memchr(s, '\n', rest);
        if(pos == NULL)
        {
            taw_reciver_do_syslog(r, l, s, len, client_ip);
            break;
        }
        else
        {
            len = pos-s;
            taw_reciver_do_syslog(r, l, s, len, client_ip);
            rest -= len;

            s=pos+1;
            rest--;

            while(rest >0 && (*s == '\r' || 
                        *s == '\n' ))
            {
                s++;
                rest--;
            }
        }
    }
    return 0;
}

int tawflexer_set_conf(tawflexer_config_loggers conf, char* client_addr)
{
    printf("client_addr = %s\n", client_addr);
    //const char* filename = "/home/test/tawflexer.conf";
    const char* filename = "/etc/tawflexer.conf";
    int i, l;
    const char* ip = NULL;

    config_t cfg;
    config_init(&cfg);
    config_read_file(&cfg,filename);

    config_setting_t* setting = config_root_setting(&cfg);
    config_setting_t* loggers = config_setting_lookup(setting, "loggers");
    l = config_setting_length(loggers);

    for (i = 0; i < l; ++i) {
        config_setting_t* elem = config_setting_get_elem(loggers, i);
        config_setting_lookup_string(elem, "addr", &ip);
        if (strcmp(ip, client_addr) == 0) {
            config_destroy(&cfg);
            return -1;
        }
    }

    config_setting_t* group = config_setting_add(loggers, NULL, CONFIG_TYPE_GROUP);

    config_setting_t* name = config_setting_add(group, "name", CONFIG_TYPE_STRING);
    config_setting_set_string(name, "topsec");

    config_setting_t* reciver = config_setting_add(group, "reciver", CONFIG_TYPE_STRING);
    config_setting_set_string(reciver, "syslog");

    printf("addr = %s\n ", conf.addr);
    config_setting_t* addr = config_setting_add(group, "addr", CONFIG_TYPE_STRING);
    config_setting_set_string(addr, conf.addr);

    printf("flexer = %s\n ", conf.name);
    config_setting_t* flexer = config_setting_add(group, "flexer", CONFIG_TYPE_STRING);
    config_setting_set_string(flexer, conf.name);

    printf("type = %s\n ", conf.type);
    config_setting_t* type = config_setting_add(group, "type", CONFIG_TYPE_STRING);
    config_setting_set_string(type, conf.type);

    config_write(&cfg, stdout);
    config_write_file(&cfg, filename);

    config_destroy(&cfg);

    return 0;                                           

}
int tawflexer_data_type(char* type, char* data)
{
    int ret = 0;
    char* str = data;
    if (str == NULL)
        return -1;

    if ( (ret = fun_int(str)) == 0) {
        *type = 'i';
        return 0;
    }
    if ( (ret = fun_double(str)) == 0) {
        *type = 'd';
        return 0;
    }
    if ( (ret = fun_ip(str)) == 0) {
        *type = 'p';
        return 0;
    }
    if ( (ret = fun_time(data)) == 0) {
        *type = 't';
        return 0;
    }
    if ( (ret = fun_mac(data)) == 0) {
        *type = 'm';
        return 0;
    }

    *type = 's';
    return 0;
}


int tawflexer_welf_match_flexer(char* str, int len, const struct sockaddr_in* client_addr, tawflexer_config_loggers* loggers, int flag)
{

    //printf("str = %s\n", str);
    char *start, *end;
    int num, ret = 0, equal = 0;
    tawflexer_t* flexer;
    tawflexer_expression_t* e;
    tawflexer_expression_t* tmp_e;

    ZYMap *m = zymap();

    //func_WELFParse(str, m, e->max_field);
    if(flag == 0)       //flag==0 welf
        func_WELFParse(str, m, 0);
    else if(flag == 1){  //flag==1 联动日志
        start = str;
        while ( (end = strchr(start, ';'))) {
            linklog_to_map(m, start, end-start+1);
            start = end + 1;
        }
        zymap_put_str(m, _K("type"), "linkage_log");
        //zyprintf("====${1@MPJ}", m);
    }
    else{
    }
    num = _ZMLen(m);
    //zyprintf("${1@MPJ}", m); 

    ts_list_for_each_entry(flexer, &all_flexer, next) {
        printf("flexer->name = %s\n", flexer->name);
        if(strcmp(flexer->exp_type, "TAW_FLEXER_EXPRESSION_WELF") != 0) 
            continue;
        ts_list_for_each_entry(e, &flexer->expressions, next) {
            ret = tawflexer_exp_do_tokenmaps( e, m, 0); 
            printf("字段 = %d, 解析 = %d\n", num, ret);
            //        zyprintf("${1@MPJ}", m); 
            //必须取完全解析
            if(ret >= num){
                printf("flexer->name = %s, type = %s\n", flexer->name, flexer->type);
                equal++;
                if(equal == 2){
                    zymap_free(m);
                    return -1;      //能完全解析的文件太多,无法指定配置文件
                }
                tmp_e = e;
                bzero(loggers, 0);
                strncpy(loggers->name, flexer->name, TAW_FLEXER_NAME_MAX_LEN);
                strncpy(loggers->type, flexer->type, TAW_FLEXER_TYPE_MAX_LEN);
                strncpy(loggers->addr, inet_ntoa(client_addr->sin_addr), TAW_FLEXER_TYPE_MAX_LEN);
                break;
            }
        }
    }

    //只有单个完全解析文件
    if (equal == 1) {
        tawflexer_send_map( tmp_e,  m, str, client_addr, loggers);
        zymap_free(m);
    }
    else
        return -2;  //无法完全解析    

    return 0;
}

int tawflexer_enc_match_flexer(char* str, int len, const struct sockaddr_in* client_addr, tawflexer_config_loggers* loggers)
{

    tawflexer_t *flexer;
    tawflexer_expression_t *e;
    char type[128] = { 0 };
    char* p = NULL;
    int i = 0;
    ZYElem* elem;
    ZYList* list = zylist();
    ZYMap* m = zymap();

    char tmp_str[len];
    memset(tmp_str, 0, len);
    strcpy(tmp_str, str);

    ts_list_for_each_entry(flexer, &all_flexer, next) {
        if(strcmp(flexer->exp_type, "TAW_FLEXER_EXPRESSION_ENC") != 0) 
            continue;
        ts_list_for_each_entry(e, &flexer->expressions, next) {
            //printf("e->token_type = %s\n", e->token_type);
            func_EnclosureSeparator(tmp_str, list, e->sep, e->quote_start, e->quote_end, e->max_field);
            memset(tmp_str, 0, len);
            strcpy(tmp_str, str);
            //printf("tmp_str = %s\n", tmp_str);
            i = 0;
            ZYLIST_FOR_EACH(list, elem){
                p = zyelem_get_str(elem, 0);
                //printf("p = %s\n", p);
                tawflexer_data_type(&type[i], p);
                i++;
            }
            //printf("type          = %s\n", type);
            if (strcasecmp(type, e->token_type) == 0) {
                strncpy(loggers->name, flexer->name, TAW_FLEXER_NAME_MAX_LEN);
                strncpy(loggers->type, flexer->type, TAW_FLEXER_TYPE_MAX_LEN);
                strncpy(loggers->addr, inet_ntoa(client_addr->sin_addr), TAW_FLEXER_TYPE_MAX_LEN);

                list_to_map(list, m);
                tawflexer_send_map( e,  m, str, client_addr, loggers);

                zylist_free(list);
                zymap_free(m);
                return 0;

            }
            memset(type, 0, 128);
            zylist_clean(list);
        }

    }
    zylist_free(list);
    zymap_free(m);

    return -1;
}

int tawflexer_reg(tawflexer_expression_t *e, ZYMap *m, const char* str, char* addr, tawflexer_config_loggers *l)
{
    int len, match_num;
    void* dump_map;
    zymap_put_nstr(m, _K("ORIGINAL_DATA"), str, strlen(str));
    zymap_put_str(m, _K("DATA_COLLECTION_TYPE"), "syslog");
    zymap_put_str(m, _K("SECURITY_OBJECT_TYPE"), l->type);
    zymap_put_str(m, _K("client_addr"), addr);

    tawflexer_exp_do_maps(e, NULL, m, &match_num, 1);
    //zyprintf("${1@MPJ}", m); 

    dump_map = zymap_dump_ptr(m, &len);
    nn_send(sockt, dump_map, len, 0);
    printf("send_num = %ld\n", ++send_num);

    taw_free(dump_map);
    return 0;
}

int tawflexer_reg_match_flexer(char* str, const struct sockaddr_in* client_addr, tawflexer_config_loggers* loggers)
{
    tawflexer_t* flexer;
    tawflexer_expression_t* e;
    int  ovector[512];
    int rc, i;
    char tmp[3] = { 0 };

    ZYMap* m = zymap();


    ts_list_for_each_entry(flexer, &all_flexer, next) {
        if (strcmp(flexer->exp_type, "TAW_FLEXER_EXPRESSION_REG") != 0) 
            continue;
        ts_list_for_each_entry(e, &flexer->expressions, next) {
            rc = pcre_exec(e->reg,  NULL,  str,  strlen(str),  0,  0,  ovector,  512);  
            if (rc < 0)  
                continue; 
            for (i = 1; i < rc; i++) {
                const char* __tawstd_unused substring_start = str + ovector[2*i]; 
                int __tawstd_unused substring_length = ovector[2*i+1] - ovector[2*i]; 

                sprintf(tmp, "%d", i);
                zymap_put_nstr(m, _K(tmp), substring_start, substring_length);
            }

            strncpy(loggers->name, flexer->name, TAW_FLEXER_NAME_MAX_LEN);
            strncpy(loggers->type, flexer->type, TAW_FLEXER_TYPE_MAX_LEN);
            strncpy(loggers->addr, inet_ntoa(client_addr->sin_addr), TAW_FLEXER_TYPE_MAX_LEN);

            tawflexer_reg( e,  m, str, inet_ntoa(client_addr->sin_addr), loggers);
            zymap_free(m);

            return 0;
        }
    }
    return -1;  //遍历结束没有匹配成功，返回-1
}

int taw_study_open(const uv_buf_t* rcvbuf, ssize_t nread, const taw_reciver_t *r, const struct sockaddr_in* client_addr)
{
    ssize_t len = nread+1;
    int ret = 0;
    char s[len];
    char linklog[4096] = "";
    memset(s, 0, len);
    strncpy(s, rcvbuf->base, len-1);
    tawflexer_config_loggers loggers;

    loggers.num = 0;

    if (taw_study_close(rcvbuf, nread, r, (struct sockaddr*)client_addr) != -1){
        return 0;
    }

    if (taw_is_linklog(s, linklog) == 0) {  //特殊联动日志处理
        if ( (ret = tawflexer_welf_match_flexer(linklog, len, client_addr, &loggers, 1)) == 0){
            tawflexer_set_conf(loggers, inet_ntoa(client_addr->sin_addr));
        }
        return 0;   
    }
    //特殊堡垒日志处理
    if( (strstr(s, "uid") && strstr(s, "uip") && strstr(s, "resip")) != 0){
        printf("--reg格式\n");
        if (tawflexer_reg_match_flexer(s, client_addr, &loggers) != 0) {
            printf("reg没有解析文件可匹配");
            return -1;
        }
        tawflexer_set_conf(loggers, inet_ntoa(client_addr->sin_addr));
        return 0;
    }


    //解析str判断welf,enc,reg,根据不同的格式选择匹配方式
    //printf("s = %s\n", s);
    if (taw_is_welf(s) == 0) {
        printf("welf格式\n");
        if ( (ret = tawflexer_welf_match_flexer(s, len, client_addr, &loggers, 0)) == 0){
            tawflexer_set_conf(loggers, inet_ntoa(client_addr->sin_addr));
        }
        if (ret == -1){
            TLOG_DEBUG("能完全解析的文件太多,无法指定解析文件!");
            return -1;
        }
        if(ret == -2)
            TLOG_DEBUG("无法完全解析!");
    }
    else if(taw_is_enc(s) == 0) {
        printf("enc格式\n");
        if (tawflexer_enc_match_flexer(s, len, client_addr, &loggers) != 0) {
            printf("enc没有解析文件可匹配\n");
            return -1;
        }
        tawflexer_set_conf(loggers, inet_ntoa(client_addr->sin_addr));
    }
    else {
        printf("reg格式\n");
        if (tawflexer_reg_match_flexer(s, client_addr, &loggers) != 0) {
            printf("reg没有解析文件可匹配");
            return -1;
        }
        tawflexer_set_conf(loggers, inet_ntoa(client_addr->sin_addr));
    }

    return 0;

}
int tawflexer_fail_to_log(char* str, struct sockaddr_in* client_addr)
{
    FILE* fd = fopen("tawflexer.log", "r");
    if (fd == NULL) {
        printf("fopen tawflexer.log error\n");
        return -1;
    }
    printf("client_addr = %s\n",inet_ntoa(client_addr->sin_addr));
    //printf("str = %s\n", str);
    if (fputs(inet_ntoa(client_addr->sin_addr), fd) == EOF) {
        printf("fputs error\n");
        return -1;
    }
    if (fputc(':', fd) == -1)
        return -1;
    fprintf(fd, "%s\n", str);
    printf("写入完成\n");

    return 0;
}

static void udp_recv_cb(uv_udp_t* handle,
        ssize_t nread,
        const uv_buf_t* rcvbuf,
        const struct sockaddr* addr,
        unsigned flags) {
    struct sockaddr_in *client_addr;
    client_addr = (struct sockaddr_in*)addr;

    if (nread < 0) {
        //ASSERT(0 && "unexpected error");
        return;
    }

    if (nread == 0) {
        /* Returning unused buffer */
        /* Don't count towards sv_recv_cb_called */
        return;
    }

    taw_reciver_t* r = handle->data;
    if (r->event == 0) {
        taw_study_close( rcvbuf, nread, r, addr);
    }
    else {
        taw_study_open( rcvbuf, nread, r, client_addr);
    }
}


int taw_btree_conf_cmp(taw_reciver_t *r, config_setting_t *setting)
{
    void *key = NULL, *data = NULL;
    int __tawstd_unused key_len = 0, i = 0, flag = 0;
    const char *conf_addr = NULL, *flexer_name = NULL;
    int logger_len = config_setting_length(setting);

    TS_BTREE_FOR_EACH(r->loggers, key, key_len, data){
        flag = 0;
        //printf("key = %s, type = %s\n", inet_ntoa(*((struct in_addr*)key)), ((taw_logger_t*)data)->type );
        char *btree_addr = inet_ntoa( *((struct in_addr*)key));
        for(i = 0; i < logger_len; i++) {
            config_setting_t *loggers = config_setting_get_elem(setting, i);
            conf_addr = NULL;
            config_setting_lookup_string(loggers, "addr", &conf_addr);
            config_setting_lookup_string(loggers, "flexer", &flexer_name);
            //  printf("btree_addr = %s, conf_addr = %s\n", btree_addr, conf_addr);
            //  printf("data->name = %s, flexer_name = %s\n", ((taw_logger_t*)data)->type, flexer_name );
            if (strcmp(btree_addr, conf_addr) != 0 ){
                continue;
            }
            else if(strcmp(btree_addr, conf_addr)==0 && ((taw_logger_t*)data)->flexer!=NULL && strcmp( ((taw_logger_t*)data)->flexer->name, flexer_name)==0){    //节点和内容一样
                flag = 1;
                break;
            }
            else if(strcmp(btree_addr, conf_addr) == 0){     //节点一样内容不一样，更新内容
                if ( ((taw_logger_t*)data)->flexer==NULL || strcmp( ((taw_logger_t*)data)->flexer->name, flexer_name)!=0){
                    flag = 1;
                    printf("===\n");
                    taw_logger_t* t = taw_logger_new();
                    tawlogger_read_config(t, loggers);
                    memset((taw_logger_t*)data, 0, sizeof(taw_logger_t));
                    strcpy( ((taw_logger_t*)data)->name, t->name);
                    strcpy( ((taw_logger_t*)data)->type, t->type);
                    strcpy( ((taw_logger_t*)data)->reciver_name, t->reciver_name);
                    inet_aton(inet_ntoa(*((struct in_addr*)key)), &( ((taw_logger_t*)data)->ipv4));
                    ((taw_logger_t*)data)->reciver = t->reciver;
                    ((taw_logger_t*)data)->flexer = t->flexer;

                    break;
                }
            }
            else {
            }

        }
        if (flag == 0) {    //配置文件没有此节点,释放节点内容
            if (data != NULL)
                memset((taw_logger_t*)data, 0, sizeof(taw_logger_t));
        }
    }

    struct in_addr n_addr;
    for (i = 0; i < logger_len; i++) {
        conf_addr = NULL;
        config_setting_t *loggers = config_setting_get_elem(setting, i);
        config_setting_lookup_string(loggers, "addr", &conf_addr);
        inet_aton(conf_addr, &n_addr);
        void* node = ts_btree_find(r->loggers, (void*)&n_addr, sizeof(struct in_addr));
        if (node == NULL) {
            taw_logger_t* t = taw_logger_new();
            tawlogger_read_config(t, loggers);
            ts_btree_insert(r->loggers, &t->ipv4, sizeof(t->ipv4), t);
        }
    }

    TS_BTREE_FOR_EACH(r->loggers, key, key_len, data){
        if (((taw_logger_t*)data)->flexer != NULL) {
            printf("key = %s\n", inet_ntoa( *((struct in_addr*)key)) );
            printf("node->flexer->name = %s\n", ((taw_logger_t*)data)->name);
            printf("node->flexer->name = %s\n", ((taw_logger_t*)data)->type);
            printf("node->flexer->name = %s\n", ((taw_logger_t*)data)->reciver_name);
            printf("node->flexer->name = %s\n", ((taw_logger_t*)data)->flexer->name);
        }
        else 
            printf("flexer == NULL\n");
    }


    return 0;
}


void* thread_fun(void* arg)
{
    char* filename = "/etc/tawflexer.conf";
    //udp_server_t* server = (udp_server_t*)arg;
    config_t cfg;
    config_setting_t *loggers = NULL;
    config_setting_t *setting = NULL;
    taw_reciver_t* r = NULL;

    while(1){
        config_init(&cfg);
        if (config_read_file(&cfg, filename) == CONFIG_TRUE) {
            setting = config_root_setting(&cfg);
            if ( (loggers = config_setting_lookup(setting, "loggers")) == NULL){
                printf("not find loggers\n");
                exit(1);
            }
            else{
                ts_list_for_each_entry(r, &reciver_head, next){
                    taw_btree_conf_cmp(r, loggers);
                }
            }
        }
        else
            TLOG_DEBUG("config_read_file == FALSE");
        config_destroy(&cfg);
        sleep(3);
    }
}

int udp_reciver_init(uv_loop_t* loop, udp_server_t *server, char* listen_addr,int port)
{

    int r __tawstd_unused;
#if 0
    uv_udp_t* p;
    pthread_t tid;

    p = &(server->server);
    taw_reciver_t* s = p->data;
    if (s->event == 1) {
        printf("pthread start\n");
        pthread_create(&tid, NULL, thread_fun, (void*)server);
    }
#endif 
    pthread_t tid;
    pthread_create(&tid, NULL, thread_fun, (void*)server);

    r = uv_ip4_addr(listen_addr, port, &(server->addr));
    r = uv_udp_init(loop, &(server->server));
    r = uv_udp_bind(&(server->server), (const struct sockaddr*)&(server->addr), 0);

    int recv_len = 5*1024*1024;
    socklen_t optlen = sizeof(recv_len);

    setsockopt(server->server.io_watcher.fd , SOL_SOCKET, SO_RCVBUF, &recv_len, optlen); 

    r = uv_udp_recv_start(&(server->server), alloc_cb, udp_recv_cb);

    return 0;
}

