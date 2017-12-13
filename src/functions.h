/*!
 *  @file   functions.h
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


#ifndef  functions_INC
#define  functions_INC

#include <ngtawstd/zytypes.h>
#include <ngtawstd/array.h>

enum tawf_function_type 
{
     TAWF_UNDEFINE=0, 
     TAWF_ENCLOSURESEP, 
     TAWF_WELF, 
     TAWF_FORMATMAC, 
     TAWF_FORMATIP, 
     TAWF_FORMATTIME_0, 
     TAWF_FORMATTIME_1, 
     TAWF_FORMATSUBTRACT,
     TAWF_GETTIME, 
     TAWF_INT8,
     TAWF_UINT8,
     TAWF_INT16,
     TAWF_UINT16,
     TAWF_INT32,
     TAWF_UINT32,
     TAWF_INT64,
     TAWF_UINT64,
     TAWF_FLOAT,
     TAWF_DOUBLE,
     TAWF_STRING,
     TAWF_REPLACE,
     TAWF_ADDMAPS,
    
};

enum tawf_function_param_type 
{
    TAWF_PARAM_STRING=0, 
    TAWF_PARAM_FIELD, 
    TAWF_PARAM_INT, 
    TAWF_PARAM_DOUBLE, 
};

#define TAWF_PARAM_STR_MAX_LEN 1024

typedef struct tawf_param
{
    enum tawf_function_param_type type;
    union
    {
            char str[TAWF_PARAM_STR_MAX_LEN];
            int   i;
            double d;
    };
}tawf_param_t;

TS_ARRAY_DEF(tawf_params, tawf_param_t);

typedef struct tawf_functions
{
    enum tawf_function_type type;
    tawf_params_t params;
}tawf_function_t;

int tawf_parse_function(const char* str, tawf_function_t* func, char* value, char *exp_type);

int func_EnclosureSeparator(char* str, ZYList* loglist, char sep, char quote_start, char quote_end, int max_field);

int func_WELFParse(char* str, ZYMap* logmap,int max_field);

int func_FormatMac(const char* format ,const char* macstr,char* result);

int func_FormatIP(const char* macstr,char* result);

int func_FormatTime(char* format ,char* timestr,time_t* result);

tawf_function_t* tawf_func_new();
void tawf_func_free(tawf_function_t* f);

int tawf_do_func(tawf_function_t* f , ZYMap* input , ZYElem* output);

#endif   /* ----- #ifndef functions_INC  ----- */
