/*!
 *  @file   func_EnclosureSeparator.c
 *  @brief  
 *  
 *  <+DETAILED+>
 *  
 *  @author  ZHANG Fengyu (张凤羽), zhang_fengyu@topsec.com.cn
 *  
 *  @internal
 *    Created:       11/10/16
 *    Revision:      none
 *    Compiler:      gcc
 *    Organization:  TAW
 *    Copyright:     Copyright (c) 2016, ZHANG Fengyu
 *  
 *  This source code is released for free distribution under the terms of the
 *  GNU General Public License as published by the Free Software Foundation.
 */

#include "functions.h"
#include <time.h>


int func_EnclosureSeparator(char* str, ZYList* loglist, char sep, char quote_start, char quote_end, int max_field)
{
    //转义字符
    char escape='\\';
    char *p=str;

    if(str == NULL)
        return 0;

    char* start = *p== sep ? NULL:p;
    char* j = p;

    int in_quote=0;
    int is_escape=0;
    int ret = 0;

    do{
        //for(;*p!='\0' && *p != '\r' && *p !='\n' && ret < max_field;p++, j++)
        if(j!=p)
        {
            *j=*p;//move char
        }

        if(is_escape)
        {
            is_escape=0;
            p++; j++;
            continue;
        }

        if(*j =='\0' || *j == '\r' || *j =='\n') 
        {
            if(start && (j-start) >0)
            {
                zylist_append_nstr(loglist, start, j-start);
                ret++;
            }
            start=NULL;
            break;
        }
        else if(*j == sep && in_quote == 0)
        {
            if(start && (j-start) >0)
            {
                zylist_append_nstr(loglist, start, j-start);
                ret++;
            }
            start=NULL;
        }
        else{
            if(start == NULL)
                start=j;
            if(*j == escape)
            {
                j--;//move back
                is_escape =1; 
            }
            else if(in_quote ==0 && *j == quote_start)
            {
                in_quote =1;
                j--;//move back
            }
            else if(in_quote && *j == quote_end)
            {
                in_quote = 0;
                j--;//move back
            }
        }

        p++; j++;
    } while(ret < max_field || max_field <=0);
    return ret;
}

int __func_WELFParse_parse_KV(ZYMap* logmap,char* str, int len, int flag_attacklog)
{
    const char sep='=';
    if(str == NULL || len <2)
        return 0;
    char* pos=memchr(str,sep,len);
    if(pos == NULL)
        return 0;

    if( (flag_attacklog==1) && (strncmp("attack_type", str, pos-str)==0)){
        if( (strncmp("begin", pos+1, len-(pos-str)-1)==0) || (strncmp("end", pos+1, len-(pos-str)-1)==0) || (strncmp("continue", pos+1, 
                        len-(pos-str)-1)==0)){
            zymap_put_nstr(logmap,_K("attack_status"),pos+1,len - (pos-str) -1);
        }
        else 
            zymap_put_nstr(logmap,_K(str,pos-str),pos+1,len - (pos-str) -1);
    }
    else
        zymap_put_nstr(logmap,_K(str,pos-str),pos+1,len - (pos-str) -1);
    return 1;
}


static int inline __is_welf_sep(char p)
{
    if( p ==  ' ' ||
            p ==  '\t')
        return 1;
    return 0;
}

int func_WELFParse(char* str, ZYMap* logmap,int max_field)
{
    //转义字符
    char escape='\\';
    char *p=str;
    const char quote_start='"'; const char quote_end='"';

    if(str == NULL)
        return 0;

    char* start =  __is_welf_sep(*p) ? NULL:p;
    char* j = p;
    //printf("j = %c\n", *j);

    int in_quote=0;
    int is_escape=0;
    int ret = 0;
    int flag_attacklog = 0;

    if(strstr(str, "attacklog") != NULL) //如果是攻击日志,需要处理重复字段attack_type
        flag_attacklog = 1;

    do{
        //for(;*p!='\0' && *p != '\r' && *p !='\n' && ret < max_field;p++, j++)
        if(j!=p)
        {
            *j=*p;//move char
        }

        if(is_escape)
        {
            is_escape=0;
            p++; j++;
            continue;
        }

        if(*j =='\0' || *j == '\r' || *j =='\n') 
        {
            //if(start && (j-start) >1){
            if(start && (j-start) >0){
                ret+=__func_WELFParse_parse_KV(logmap,start,j-start, flag_attacklog);
            }
            start=NULL;
            break;
        }
        else if(__is_welf_sep(*j)&& in_quote == 0)
        {
            //if(start && (j-start) >1)
           if(start && (j-start) >0)
            {
                ret+=__func_WELFParse_parse_KV(logmap,start,j-start, flag_attacklog);
            }
            start=NULL;
        }
        else{
            if(start == NULL)
                start=j;
            if(*j == escape)
            {
                j--;//move back
                is_escape =1; 
            }
            else if(in_quote ==0 && *j == quote_start)
            {
                in_quote =1;
                j--;//move back
            }
            else if(in_quote && *j == quote_end)
            {
                in_quote = 0;
                j--;//move back
            }
        }

        p++; j++;
    } while(ret < max_field || max_field <=0);

    return ret;
}


int func_FormatMac(const char* format ,const char* macstr,char* result)
{
    const char* p=macstr;
    const char* f = format;
    unsigned char hex=0;    
    int i = 0;

    memset(result,0,6);

    for(;*f != '\0' && *p!='\0';f++,p++)
    {
        if(*f == 'H' ||*f == 'H')//do input
        {
            hex <<= i%2 * 4;
            switch(*p)
            {
                case 'a' ... 'z':
                    hex |= *p - 'a' + 10;
                    break;
                case 'A' ... 'Z':
                    hex |= *p - 'A' + 10;
                    break;
                case '0' ... '9':
                    hex |= *p - '0';
                    break;
                default:
                    //format error,set 0
                    break;
            }
            if(i%2 != 0)
            {
                result[i/2] = hex;
                hex=0;
            }
            i++;
        }
    }
    return 0;
}

int func_FormatTime(char* format ,char* timestr,time_t* result)
{
    struct tm tm;
    strptime(timestr,format,&tm);
    *result = mktime(&tm);
    return 0;
}

tawf_function_t* tawf_func_new()
{
    tawf_function_t* t = taw_zalloc_type(tawf_function_t);
    tawf_params_init(&t->params, 8); //max 5 params now
    return t;
}

void tawf_func_clean_params(tawf_function_t* f)
{
    tawf_params_set_len(&f->params, 0);
}
void tawf_func_free(tawf_function_t* f)
{
    tawf_params_clean(&f->params);
    FREEPTR(f);
}
int __tawf_parse_funcname(const char* str, int len, tawf_function_t* func, char *token_type)
{
    func->type = TAWF_UNDEFINE;
    if(strncasecmp(str,"WELF", len ) == 0)
    {
        func->type = TAWF_WELF; 
    }
    else if(strncasecmp(str,"EnclosureSeparator", len ) == 0)
    {
        func->type = TAWF_ENCLOSURESEP; 
    }
    else if(strncasecmp(str,"_FormatMac", len ) == 0) {
        func->type = TAWF_FORMATMAC; 
        *token_type = 'm';
    }
    else if(strncasecmp(str,"_FormatIP", len ) == 0) {
        func->type = TAWF_FORMATIP; 
        *token_type = 'p';
    }
    else if(strncasecmp(str,"_FormatSubtract", len ) == 0) {
        func->type = TAWF_FORMATSUBTRACT; 
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatTime0", len ) == 0) {
        func->type = TAWF_FORMATTIME_0; 
        *token_type = 't';
    }
    else if(strncasecmp(str,"_FormatTime1", len ) == 0) {
        func->type = TAWF_FORMATTIME_1; 
        *token_type = 't';
    }
    else if(strncasecmp(str,"_GetTime", len ) == 0)
        func->type = TAWF_GETTIME; 
    else if(strncasecmp(str,"_FormatInt8", len ) == 0) {
        func->type = TAWF_INT8;   
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatUint8", len ) == 0) {
        func->type = TAWF_UINT8;
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatInt16", len ) == 0) {
        func->type = TAWF_INT16; 
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatUint16", len ) == 0) {
        func->type = TAWF_UINT16;
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatInt32", len ) == 0) {
        func->type = TAWF_INT32; 
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatUint32", len ) == 0) {
        func->type = TAWF_UINT32;
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatInt64", len ) == 0) {
        func->type = TAWF_INT64;
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatUint64", len ) == 0) {
        func->type = TAWF_UINT64;
        *token_type = 'i';
    }
    else if(strncasecmp(str,"_FormatFloat", len ) == 0) {
        func->type = TAWF_FLOAT;
        *token_type = 'd';
    }
    else if(strncasecmp(str,"_FormatDouble", len ) == 0) {
        func->type = TAWF_DOUBLE;
        *token_type = 'd';
    }
    else if(strncasecmp(str,"_FormatReplace", len ) == 0) {
        func->type = TAWF_REPLACE;
        *token_type = 'd';
    }

    return func->type;
}

int __tawf_add_param(char* str, int isstr, tawf_function_t* func)
{
    tawf_param_t* p = tawf_params_add(&func->params);
    if(isstr)
    {
        p->type = TAWF_PARAM_STRING;
        strncpy(p->str, str, TAWF_PARAM_STR_MAX_LEN);
    }
    else
    {
        switch(*str)
        {
#if 0
            case '0' ... '9': //int or float
                {
                    char* point = strchr(str, '.');
                    if(point)
                    {
                        p->type = TAWF_PARAM_DOUBLE;
                        p->d = strtod(str, &point);
                    }
                    else
                    {
                        p->i = strtol(str, &point, 0);
                    }
                }
                break;
#endif
            default://column name
                {
                    p->type = TAWF_PARAM_FIELD;
                    strncpy(p->str, str, TAWF_PARAM_STR_MAX_LEN);
                }
                break;
        }
    }
    return 0;
}

int __tawf_parse_param(const char* str, tawf_function_t* func, char* value)
{
    char* param = taw_strdup(str);
    const char* p = str;

    int l = 0;
    int in_str=0;
    int param_start=0;

    for(;*p!='\0';p++)
    {
        if(param_start==0)
        {
            if(*p != ' ')
            {
                if(*p == '\'')
                {
                    in_str = 1;
                    p++;
                }
                param_start=1;
            }
            else
                continue;
        }

        if(param_start)
        {
            if(in_str)
            {
                if(*p == '\\')
                {
                    param[l]=*(p+1);
                    p++;
                    l++;
                    continue;
                }

                if( *p == '\'')
                {
                    param[l]='\0';
                    strcpy(value, param);
                    __tawf_add_param(param, 1, func);
                    param_start = 0;
                    l = 0;
                    in_str = 0;
                }
            }
            else if(*p == ',' ||*p == ' ' ||*p == ')')
            {
                param[l]='\0';
                strcpy(value, param);
                __tawf_add_param(param, 0, func);
                param_start = 0;
                l = 0;
            }
            else
            {
                param[l]=*(p);
                l++;
            }

        }

    }
    return 0;
}

int tawf_parse_function(const char* str, tawf_function_t* func, char* value, char *token_type)
{
    tawf_func_clean_params(func);
    const char* p =str;

    while(*p == ' '&&*p!='\0') //skip white space
        p++;

    char* j = strchr(p,'(');//param start
    if(j == NULL)
        return -1;
    while(j>p && (*j == '(' || *j == ' ' )) //skip white space
        j--;

    if(__tawf_parse_funcname(p, j-p+1, func, token_type) == TAWF_UNDEFINE)
        return -2;

    p = strchr(p,'(');//param start
    while((*p == '(' || *p == ' ')&&*p!='\0')//find start
        p++;
    __tawf_parse_param(p, func, value);

    return 0;
}


static int __tawf_do_formatip(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* ipv = zymap_get_str(input, _K(p->str));
    if(ipv)
    {
        ZYIP* ip = zyip();
        int ret = zyip_aton(_K(ipv), ip);
        if(ret == 0) {
            zyelem_set_zyip(output, ip);
            zyip_free(ip);
        }
        else {
            //    zyelem_set_ptr(output, ipv);
        }
    }
    return 0;
}
static int __tawf_do_formatsubtract(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    char str1[32] = {0};
    char *str2 = NULL;

    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    str2 = strstr(p->str, "-");
    strncpy(str1, p->str, str2-p->str);
    str2 = str2+1;

    uint64_t recv = zymap_get_uint64(input, _K(str1));
    uint64_t attack = zymap_get_uint64(input, _K(str2));
    zyelem_set_uint64(output, recv-attack);

    return 0;
}


static int __tawf_do_formatreplace(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* str = zymap_get_str(input, _K(p->str));
    char* tmp = NULL;

    if (str != NULL){
        while((tmp = strchr(str, ','))){
            *tmp = ';'; 
        }
    }
    return 0;
}

static int __tawf_do_formattime0(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* str_time = zymap_get_str(input, _K(p->str));
    if(str_time)
    {
        time_t second;
        struct tm tm_time;  
        memset(&tm_time, 0, sizeof(struct tm));

        strptime(str_time, "%Y-%m-%d %H:%M:%S", &tm_time);  
        second = mktime(&tm_time);  
        zyelem_set_uint64(output, second);
    }
    return 0;
}

/*
   static time_t func_formattime(char* format ,const char* timestr)
   {
   struct tm tm;
   char *start;
   char *end;
   char *tmp_start;
   char tmp_time[5] = {0};
   char search[6] = "YMDhms";
   int i = 0;

   memset(&tm, 0, sizeof(struct tm));  //tm置0,可以大大提高mktime()的效率
   tmp_start = format;

   for (i = 0; i < 6; i++) {
   start = index(format, search[i]);
   end = rindex(format, search[i]);
   strncpy(tmp_time, timestr+(start-tmp_start), end-start+1);
   if (i == 0)  {
   tm.tm_year = (atoi(tmp_time)+2000-1900);
   } else if (i == 1) {
   tm.tm_mon = atoi(tmp_time)-1;   //区间取值0~11, 1表示2月份
   } else if (i == 2) {
   tm.tm_mday = atoi(tmp_time);
   } else if (i == 3) {
   tm.tm_hour= atoi(tmp_time);
   } else if (i == 4) {
   tm.tm_min = atoi(tmp_time);
   }
   else {
   tm.tm_sec = atoi(tmp_time);
   }

   memset(tmp_time, 0, 5);
   }
   time_t t = mktime(&tm);
   return t;
   }
 */
static int __tawf_do_formattime1(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* str_time = zymap_get_str(input, _K(p->str));

    if (str_time == NULL)
        return -1;

    struct tm tm;
    struct tm *new_tm;
    time_t new;
    const char *format = "%b %d %H:%M:%S";
    //char *timestr = "Jun 19 11:48:01";

    new = time(NULL);
    new_tm = localtime(&new);
    tm.tm_year = new_tm->tm_year;

    strptime(str_time, format, &tm);
    time_t sec = mktime(&tm);
    zyelem_set_uint64(output, sec);

    return 0;

}

/*
   static int __tawf_do_formattime2(tawf_function_t* f , ZYMap* input , ZYElem* output)
   {
   tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
   const char* str_time = zymap_get_str(input, _K(p->str));
   char *format = "YY/MM/DD/hhmmss";
   time_t t;

   if (str_time) {
   t = func_formattime(format, str_time);
   }
   zyelem_set_uint64(output, t);

   return 0;
   }
 */

static int __tawf_do_formatmac(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* mac_str = zymap_get_str(input, _K(p->str));

    if (mac_str) {
        unsigned char *mac = taw_malloc("char", 6, 0);
        sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5]);  
        zyelem_set_ptr(output, (void*)mac);
    }
    return 0;
}

static int __tawf_do_formatint(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    int64_t data = 0;

    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* ptr = zymap_get_str(input, _K(p->str));

    if(ptr)
    {
        data = atol(ptr);
        switch(f->type) {
            case TAWF_INT8:
                zyelem_set_int8(output, (int8_t)data);
                break;
            case TAWF_UINT8:
                zyelem_set_uint8(output, (uint8_t)data);
                break;
            case TAWF_INT16:
                zyelem_set_int16(output, (int16_t)data);
                break;
            case TAWF_UINT16:
                zyelem_set_uint16(output, (uint16_t)data);
                break;
            case TAWF_INT32:
                zyelem_set_int32(output, (int32_t)data);
                break;
            case TAWF_UINT32:
                zyelem_set_uint32(output, (uint32_t)data);
                break;
            case TAWF_INT64:
                zyelem_set_int64(output, (int64_t)data);
                break;
            case TAWF_UINT64:
                zyelem_set_uint64(output, (uint64_t)data);
                break;
            default:
                output->type = ZYT_UNDEFINE;
                break;
        }
    }
    return 0;
}

static int __tawf_do_formatdouble(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    double data;

    tawf_param_t* p = tawf_params_get_ptr(&f->params, 0);
    const char* ptr = zymap_get_str(input, _K(p->str));

    if(ptr)
    {
        data = atof(ptr);
        switch(f->type) {
            case TAWF_DOUBLE:
                zyelem_set_double(output, data);
                break;
            case TAWF_FLOAT:
                zyelem_set_double(output, (float)data);
                break;
            default:
                output->type = ZYT_UNDEFINE;
                break;
        }
    }
    return 0;
}
/*
static int __tawf_do_formataddmaps()
{
    
    return 0;
}
*/
int tawf_do_func(tawf_function_t* f , ZYMap* input , ZYElem* output)
{
    switch(f->type)
    {
        case TAWF_FORMATIP:
            return __tawf_do_formatip( f,  input,  output);
            break;
        case TAWF_FORMATMAC:
            return __tawf_do_formatmac( f, input,  output);
            break;
        case TAWF_FORMATTIME_0:
            return __tawf_do_formattime0( f, input,  output);
            break;
        case TAWF_FORMATTIME_1:
            return __tawf_do_formattime1( f, input,  output);
            break;
        case TAWF_FORMATSUBTRACT:
            return __tawf_do_formatsubtract( f, input,  output);
            break;

        case TAWF_INT8:
        case TAWF_UINT8:
        case TAWF_INT16:
        case TAWF_UINT16:
        case TAWF_INT32:
        case TAWF_UINT32:
        case TAWF_INT64:
        case TAWF_UINT64:
            __tawf_do_formatint(f , input , output);
            break;
        case TAWF_FLOAT:
        case TAWF_DOUBLE:
            __tawf_do_formatdouble(f , input , output);
            break;
        case TAWF_REPLACE:
            __tawf_do_formatreplace(f , input , output);
            break;

        default:
            output->type = ZYT_UNDEFINE;
            break;
    }
    return 0;
}


//unit test
#include "functions_test.c"
