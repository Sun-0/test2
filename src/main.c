/*!
 *  @file   main.c
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

#include "flexer_reader.h"
#include "reciver_reader.h"
#include "reciver.h"
#include "udp.h"
#include "logger_reader.h"
#include <ngtawstd/common.h>
#include <ngtawstd/stringfns.h>
#include <libconfig.h>
#include <ngtawutils/command-line.h>
#include <ngtawutils/daemon.h>

DAEMON_SHORT_OPTIONS_N
#define SERVER_NAME "tawlogserver"

int sockt = 0;
char pub_addr_port[64] = { 0 };

static int read_flexer_config_file(const char* filename)
{

    config_t cfg;
    config_init(&cfg);
    const char *pub = NULL;
    int ret =0;    
    if(config_read_file(&cfg,filename)==CONFIG_TRUE)
    {
        config_setting_t* setting = config_root_setting(&cfg);

        config_setting_t* recivers= config_setting_lookup(setting, "recivers");
        if (recivers == NULL) {
            printf("not find revicers\n");
            exit(1);
        }
        taw_reciver_readlist(recivers); // read reciver first
        //config_write_file(&cfg, filename);

        config_setting_t* loggers= config_setting_lookup(setting, "loggers");
        if (loggers == NULL) {
            printf("not find loggers\n");
            exit(1);
        }
        taw_logger_readlist(loggers);  

        config_setting_lookup_string(setting, "addr", &pub);
        strcpy(pub_addr_port, pub);
        //printf("pub_addr_port = %s\n", pub_addr_port);

    }
    else
    {
        TLOG_ERROR("read %s:%d error:%s",config_error_file(&cfg),config_error_line(&cfg), config_error_text(&cfg));
        ret = -1;
    }

    config_destroy(&cfg); 
    return ret;
}

int main(int argc, char** argv)
{
    tawstd_init(argc, argv);
    daemonize(SERVER_NAME);

    char* flexer_cfgpath=taw_strdup("/etc/tawflexer.conf");
    char* flexer_dir=taw_strdup("/etc/tawflexer/flexer");
    //read flexer first 
    tawflexer_readdir(flexer_dir);

    //read config file
    read_flexer_config_file(flexer_cfgpath);

    //建立socket连接，用于msg
    sockt = nanomsg_server();

    uv_loop_t* loop = uv_default_loop();

    taw_reciver_start_all(loop);    

    uv_run(loop,  UV_RUN_DEFAULT);


    return 0;
}
