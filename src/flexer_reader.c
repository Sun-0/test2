#include "flexer_reader.h"
#include <ngtawstd/libconfig.h>
#include <sys/types.h>
#include <dirent.h>


int __tawflexer_parse_separator_expression (tawflexer_t *flexer, tawflexer_expression_t* e,const char * val)
{
    const char* p =val;
    while(*p == ' '&&*p!='\0')
        p++;

    char* j = strchr(p,'(');//param start
    if(j == NULL)
        return -1;
    while(j>p && (*j == '(' || *j == ' ' ))
        j--;

    if(strncasecmp(p,"WELF",j-p +1 ) == 0)
    {
        strncpy(flexer->exp_type, "TAW_FLEXER_EXPRESSION_WELF",  TAW_FLEXER_TYPE_MAX_LEN);
        e->type = TAW_FLEXER_EXPRESSION_WELF;
        e->max_field = 0;
        p = strchr(p,'(');//param start
        while((*p == '(' || *p == ' ')&&*p!='\0')
            p++;
        e->max_field = strtoul(p,&j,10);
    }
    else if(strncasecmp(p,"EnclosureSeparator",j-p +1 ) == 0)
    {
        strncpy(flexer->exp_type, "TAW_FLEXER_EXPRESSION_ENC",  TAW_FLEXER_TYPE_MAX_LEN);
        e->type = TAW_FLEXER_EXPRESSION_ENC;
        e->max_field = 0;
        p = strchr(p,'\'');//param start
        if(p==NULL)
            return 0;
        p++;
        e->sep = *p;

        p = strchr(p,',');//next param
        if(p==NULL)
            return 0;
        p = strchr(p,'\'');//param start
        if(p==NULL)
            return 0;
        p++;
        e->quote_start = *p;


        p = strchr(p,',');//next param
        if(p==NULL)
            return 0;
        p = strchr(p,'\'');//param start
        if(p==NULL)
            return 0;
        p++;
        e->quote_end= *p;

        p = strchr(p,',');//next param
        if(p==NULL)
            return 0;

        while((*p == ',' || *p == ' ')&&*p!='\0')
            p++;
        e->max_field = strtoul(p,&j,10);

    }
    else
        return -2; //error type

    return 0;
}




int tawflexer_parse_add_tokenmapper(tawflexer_expression_t* e, tawflexer_tokenmaps_t* t,config_setting_t* setting, char *token_type, int* index)
{

    const char* strn = NULL;
    config_setting_lookup_string(setting,"name",&strn);
    if(strn == NULL)
    {
        return -1;
    }
    const char* strv = NULL;
    config_setting_lookup_string(setting,"value",&strv);
    if(strv == NULL)
    {
        return -1;
    }
    
    int remove= 1;
    config_setting_lookup_int(setting,"remove",&remove);
    tawflexer_tokenmapper_t* m = tawflexer_tokenmapper_new();
    strncpy(m->name,strn,TAW_FLEXER_NAME_MAX_LEN);
    m->remove = remove;

    if(strchr(strv, '('))//function
    {
        m->func = tawf_func_new();

        if(tawf_parse_function(strv, m->func, m->value, token_type) != 0)
        {
            strncpy(m->value,strv,TAW_FLEXER_NAME_MAX_LEN);
            tawf_func_free(m->func);
            m->func = NULL;
        }
        if( strcmp(strv, "_FormatIP(client_addr)") != 0) {
            (*index)++;
        }
    }
    else
    {
        strncpy(m->value,strv,TAW_FLEXER_NAME_MAX_LEN);
        if ( (strcmp(strv, "ORIGINAL_DATA") != 0) && (strcmp(strv, "DATA_COLLECTION_TYPE") != 0) && (strcmp(strv, "SECURITY_OBJECT_TYPE") != 0) )  {
            *token_type = 's';
            (*index)++;
        }
    }

    if(e == NULL)
        ts_list_add_tail(&(m->next), &t->maps); 
    else 
        ts_list_add_tail(&(m->next), &e->maps);
    return 0;
}

int tawflexer_parse_add_tokenmap1(tawflexer_tokenmaps_t *token, config_setting_t* setting)
{
    const char *strv = NULL;
    int i = 0, index = 0;
    config_setting_t *tokenmaps;

    tawflexer_tokenmaps_t* m = tawflexer_tokenmaps_new();
    config_setting_lookup_string(setting, "condition", &strv);
    if(strv){
        struct zy_pattern_error ecode;
        struct zypattern* pt = zy_pt_compile(strv,NULL,&ecode);
        if(pt == NULL)
            return -2;
        m->pt = pt;
    }
    else{
        m->pt = NULL;
    }
    m->tokenmaps_flag = 0;
    if( (tokenmaps = config_setting_lookup(setting, "tokenmaps")) != NULL){
        m->tokenmaps_flag = 1;
        for (i=0; i<config_setting_length(tokenmaps); i++){
            config_setting_t* tokenmap = config_setting_get_elem(tokenmaps, i);
            tawflexer_parse_add_tokenmap1(m, tokenmap);
        }        
    }
    //最内部的map
    m->maps_flag = 0;
    config_setting_t* maps= config_setting_lookup(setting,"maps");
    if(maps){
        m->maps_flag = 1;    //嵌套结束
        index = 0;
        for(i=0; i<config_setting_length(maps); i++){
            config_setting_t* map= config_setting_get_elem(maps,i);
            tawflexer_parse_add_tokenmapper (NULL, m,map, &m->token_type[index], &index);

        }
    }
    ts_list_add_tail(&m->next, &token->tokenmaps);

    return 0;
}



int tawflexer_parse_add_tokenmap0(tawflexer_expression_t* e, config_setting_t* setting)
{
    const char* strv = NULL;
    int i = 0, index = 0;
    config_setting_lookup_string(setting,"condition",&strv);
    tawflexer_tokenmaps_t* m = tawflexer_tokenmaps_new();
    if(strv)
    {
        struct zy_pattern_error ecode;
        struct zypattern* pt = zy_pt_compile(strv,NULL,&ecode);
        //printf("ecode = %d\n", ecode.ecode);
        if(pt == NULL)
            return -2;
        m->pt = pt;
    }
    else
    {
        m->pt = NULL;
    }

    m->tokenmaps_flag = 0;
    config_setting_t* tokenmaps= config_setting_lookup(setting,"tokenmaps");
    if (tokenmaps != NULL) {
        m->tokenmaps_flag = 1;
        for (i = 0; i < config_setting_length(tokenmaps); i++) {
            config_setting_t* tokenmap = config_setting_get_elem(tokenmaps, i);
            tawflexer_parse_add_tokenmap1(m, tokenmap);
        }

    }
    m->maps_flag = 0;
    config_setting_t* maps= config_setting_lookup(setting,"maps");  //公有maps
    if(maps){
        m->maps_flag = 1;
        for(i=0; i<config_setting_length(maps); i++){
            config_setting_t* map= config_setting_get_elem(maps,i);
            tawflexer_parse_add_tokenmapper (NULL, m, map, &m->token_type[index], &index);
        }    
    }

    //ts_list_add_tail(&e->tokenmaps,&m->next);
    ts_list_add_tail(&m->next, &e->tokenmaps);
    return 0;
}

int tawflexer_parse_add_token(tawflexer_expression_t *e, config_setting_t *setting, int index_two)
{
    const char* strn = NULL;
    config_setting_lookup_string(setting,"name",&strn);
    if(strn == NULL)
    {
        return -1;
    }
    const char* strv = NULL;
    config_setting_lookup_string(setting,"value",&strv);
    if(strv == NULL)
    {
        return -1;
    }

    tawflexer_tokens_t *t = tawflexer_token_new();
    strncpy(t->name, strn, TAW_FLEXER_NAME_MAX_LEN);
    strncpy(t->value, strv, TAW_FLEXER_NAME_MAX_LEN);

    ts_list_add_tail(&(t->next), &e->tokens); 

    return 0;
}

int tawflexer_test_log(tawflexer_tokenmaps_t *tokenmaps)
{
    if(tokenmaps->tokenmaps_flag == 1){
        tawflexer_tokenmaps_t *t;
        ts_list_for_each_entry(t, &tokenmaps->tokenmaps, next){
            tawflexer_test_log(t);
        }  
    }
    else {
        tawflexer_tokenmapper_t* mapper; 
        ts_list_for_each_entry(mapper, &tokenmaps->maps, next){
            printf("mapper->kay = %s, value = %s\n", mapper->name, mapper->value);
        }
        return 0;
    }
    if(tokenmaps->maps_flag == 1){
        tawflexer_tokenmapper_t* mapper; 
        ts_list_for_each_entry(mapper, &tokenmaps->maps, next){
            printf("mapper->kay = %s, value = %s\n", mapper->name, mapper->value);
        }
        return 0;
    }
    return 0;
}

int tawflexer_parse_add_expression(tawflexer_t* flexer,config_setting_t* setting)
{
    int ret = 0;
    const char* strv = NULL;
    config_setting_lookup_string(setting,"field",&strv);
    if(strv == NULL)
    {
        return -1;
    }

    tawflexer_expression_t* e = tawflexer_expression_new();

    if(e == NULL)
        return -2;

    strncpy(e->input,strv,TAW_FLEXER_INPUTNAME_MAX_LEN);
    strv=NULL;
    config_setting_lookup_string(setting,"reg",&strv);
    if(strv == NULL)
    {
        config_setting_lookup_string(setting,"separator",&strv);
        if(strv == NULL)
            return -3;//no separator
        //parse function
        __tawflexer_parse_separator_expression ( flexer,e,strv);
        strv=NULL;
    }
    else
    {
        strncpy(flexer->exp_type, "TAW_FLEXER_EXPRESSION_REG",  TAW_FLEXER_TYPE_MAX_LEN);
        e->type = TAW_FLEXER_EXPRESSION_REG;
        const char *error;
        int  erroffset;
        e->reg = pcre_compile(strv, 0, &error, &erroffset, NULL);
        if(e->reg == NULL)
            return -3; 
        config_setting_t* tokens = config_setting_lookup(setting, "tokens");
        if (tokens) {
            int i = 0;
            for (i = 0; i < config_setting_length(tokens); ++i) {
                config_setting_t* token = config_setting_get_elem(tokens, i);
                tawflexer_parse_add_token(e, token, i);
            }
        }

    }

    e->tokenmaps_flag = 0;
    config_setting_t* tokenmaps = config_setting_lookup(setting,"tokenmaps"); 
    if(tokenmaps)
    {
        int i=0;
        e->tokenmaps_flag = 1;
        for(i=0;i<config_setting_length(tokenmaps);i++)
        {
            config_setting_t* tokenmap = config_setting_get_elem(tokenmaps, i);
            tawflexer_parse_add_tokenmap0(e, tokenmap);
        }
    }
#if 1
    int i = 0, index = 0;
    e->maps_flag = 0;
    config_setting_t* maps= config_setting_lookup(setting,"maps");  //公有maps
    if(maps){
        e->maps_flag = 1;
        for(i=0; i<config_setting_length(maps); i++){
            config_setting_t* map= config_setting_get_elem(maps,i);
            tawflexer_parse_add_tokenmapper(e, NULL, map, &e->token_type[index], &index);
        }    
    }
#endif

    ts_list_add_tail(&e->next, &flexer->expressions);

    return ret;
}

int tawflexer_read_config(tawflexer_t* flexer,config_setting_t* setting)
{
    int ret = 0 ;

    if(setting == NULL)
        return -1;

    const char* strv=NULL;
    config_setting_lookup_string(setting,"name",&strv);
    if(strv == NULL)
    {
        return -2;
    }
    strncpy(flexer->name, strv, TAW_FLEXER_NAME_MAX_LEN);

    strv=NULL;    
    config_setting_lookup_string(setting,"type",&strv);
    if(strv == NULL)
    {
        return -3;
    }
    strncpy(flexer->type, strv, TAW_FLEXER_NAME_MAX_LEN);

    config_setting_t* expressions = config_setting_lookup(setting,"expressions"); 

    int i =0;
    for(i=0;i<config_setting_length(expressions);i++)
    {
        config_setting_t* expression = config_setting_get_elem(expressions,i);
        tawflexer_parse_add_expression(flexer,expression);
    }

    //测试
#if 0
    tawflexer_expression_t* e;
    tawflexer_tokenmaps_t *t;
    tawflexer_tokenmapper_t* m;
    ts_list_for_each_entry(e, &flexer->expressions, next){
        if(e->maps_flag == 1){
            ts_list_for_each_entry(m, &e->maps, next){
                printf("e->key = %s, e->value = %s\n", m->name, m->value);
            }
        }
        ts_list_for_each_entry(t, &e->tokenmaps, next){        
            tawflexer_test_log(t);
        }
    }
#endif




    return ret;
}


int tawflexer_readfile(tawflexer_t* flexer,const char* filename)
{

    config_t cfg;
    config_init(&cfg);
    int ret =0;    
    if(config_read_file(&cfg,filename)==CONFIG_TRUE)
    {
        config_setting_t* setting = config_root_setting(&cfg);
        ret =  tawflexer_read_config( flexer,setting);
    }
    else
    {
        TLOG_ERROR("read %s:%d error:%s",config_error_file(&cfg),config_error_line(&cfg), config_error_text(&cfg));
        ret = -1;
    }

    config_destroy(&cfg); 
    return ret;
}


int tawflexer_readdir_tolist(ts_list_t* flexer_head,const char* dirname)
{
    int  ret = 0;
    DIR* d=NULL;
    d=opendir(dirname);
    if(d==NULL)
    {
        TLOG_INFO("open dir %s failed",dirname);
        return -1;
    }
    struct dirent* ent; 
    char pathname[512];
    const char* pos=NULL;
    while((ent=readdir(d))!=NULL)
    {
        if(ent->d_type !=DT_LNK &&
                ent->d_type !=DT_REG &&
                ent->d_type !=DT_UNKNOWN) 
            continue;

        pos = strrchr(ent->d_name,'.');
        if(pos == NULL)
        {
            continue;
        }
        if(strcasecmp(pos,".conf")==0)
        {
            snprintf(pathname,512,"%s/%s",dirname,ent->d_name);
            printf("pathname = %s\n", pathname);
            tawflexer_t* t = tawflexer_new();
            if(tawflexer_readfile(t,pathname)==0)
            {
                //ts_list_add_tail(flexer_head,&t->next);
                ts_list_add_tail(&t->next, flexer_head);
            }
            else
            {
                tawflexer_free(t);
            }
        }
    }
    closedir(d);
    return ret; 
}
