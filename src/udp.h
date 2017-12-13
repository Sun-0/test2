/*!
 *  @file   udp.h
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

#ifndef  tf_udp_INC
#define  tf_udp_INC


#include <uv.h>
#include "tawflexer.h"
#include <ngtawstd/tawstd_spinlock.h>

extern int sockt;

typedef struct udp_reciver_struct
{
    struct sockaddr_in addr;
    uv_udp_t server;
}udp_server_t;

int udp_reciver_init(uv_loop_t* loop, udp_server_t *server, char* listen_addr,int port);

int nanomsg_server(void);

int taw_is_linklog(const char* str, char* buf);

int linklog_to_map(ZYMap *map, char *str, const int len);
 
#endif   /* ----- #ifndef udp_INC  ----- */
