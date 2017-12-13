
#ifdef UNIT_TEST

#include <ngtawstd/zytest.h>
#include <ngtawstd/zytypes.h>
/*
   BEFORETEST(functions)
   {
   return 0;
   }

   AFTERTEST(functions)
   {
   return 0;
   }
 */
// base test
extern u_int64_t _get_map_hash(const void* ptr,int size);
TESTCASE(functions) //{
TEST(func_EnclosureSeparator)
{
    //	func_EnclosureSeparator(char* str, ZYList* loglist, char sep, char quote_start, char quote_end, int max_field);

    int ret = 0 ;
    ZYList* list = zylist();
    char* str=NULL;
    char sep=' ';
    char quote_start='"';
    char quote_end='"';


    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,0);

    str=strdup("");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,0);
    free(str);

    str=strdup("key=\"value\"");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,1);
    const char* result = zylist_get_str(list,0);

    //zyprintf("${1@LPJ}",list);
    CU_ASSERT_STRING_EQUAL("key=value",result);
    free(str);
    zylist_clean(list);

    str=strdup("key1=\"value1\" key2=\"value2\"");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,2);
    result = zylist_get_str(list,0);
    CU_ASSERT_STRING_EQUAL("key1=value1",result);
    result = zylist_get_str(list,1);
    CU_ASSERT_STRING_EQUAL("key2=value2",result);
    //zyprintf("${1@LPJ}",list);
    free(str);
    zylist_clean(list);

    str=strdup("    key1=\"value1\"     key2=\"value2\"    ");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,2);
    result = zylist_get_str(list,0);
    CU_ASSERT_STRING_EQUAL("key1=value1",result);
    result = zylist_get_str(list,1);
    CU_ASSERT_STRING_EQUAL("key2=value2",result);
    //zyprintf("${1@LPJ}",list);
    free(str);
    zylist_clean(list);


    str=strdup("key1=\"value1\" key2=\"value 2\"");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,2);
    result = zylist_get_str(list,0);
    CU_ASSERT_STRING_EQUAL("key1=value1",result);
    result = zylist_get_str(list,1);
    CU_ASSERT_STRING_EQUAL("key2=value 2",result);
    //zyprintf("${1@LPJ}",list);
    free(str);
    zylist_clean(list);

    str=strdup("key1=value1 key2=value\\ 2 key3=\"value3\\\"");
    ret = func_EnclosureSeparator(str,list,sep,quote_start,quote_end,100);
    CU_ASSERT_EQUAL(ret,3);
    result = zylist_get_str(list,0);
    CU_ASSERT_STRING_EQUAL("key1=value1",result);
    result = zylist_get_str(list,1);
    CU_ASSERT_STRING_EQUAL("key2=value 2",result);
    result = zylist_get_str(list,2);
    CU_ASSERT_STRING_EQUAL("key3=value3\"",result);
    //zyprintf("${1@LPJ}",list);
    free(str);
    zylist_clean(list);


}
ENDTEST(func_EnclosureSeparator);

TEST(func_WELFParse)
{
    //	func_EnclosureSeparator(char* str, ZYList* loglist, char sep, char quote_start, char quote_end, int max_field);

    int ret = 0 ;
    ZYMap* map= zymap();
    char* str=NULL;

    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,0);

    str=strdup("");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,0);
    free(str);

    str=strdup("key=\"value\"");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,1);
    const char* result = zymap_get_str(map,_K("key"));
    //zyprintf("${1@MPJ}",map);
    CU_ASSERT_STRING_EQUAL("value",result);
    free(str);
    zymap_clean(map);

    str=strdup("key1=\"value1\" key2=\"value2\"");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,2);
    result = zymap_get_str(map,_K("key1"));
    CU_ASSERT_STRING_EQUAL("value1",result);
    result = zymap_get_str(map,_K("key2"));
    CU_ASSERT_STRING_EQUAL("value2",result);
    //zyprintf("${1@MPJ}",map);
    free(str);
    zymap_clean(map);

    str=strdup("    key1=\"value1\"     key2=\"value2\"    ");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,2);
    result = zymap_get_str(map,_K("key1"));
    CU_ASSERT_STRING_EQUAL("value1",result);
    result = zymap_get_str(map,_K("key2"));
    CU_ASSERT_STRING_EQUAL("value2",result);
    //zyprintf("${1@MPJ}",map);
    free(str);
    zymap_clean(map);


    str=strdup("key1=\"value1\" key2=\"value 2\"");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,2);
    result = zymap_get_str(map,_K("key1"));
    CU_ASSERT_STRING_EQUAL("value1",result);
    result = zymap_get_str(map,_K("key2"));
    CU_ASSERT_STRING_EQUAL("value 2",result);
    //zyprintf("${1@MPJ}",map);
    free(str);
    zymap_clean(map);

    str=strdup("key1=value1 key2=value\\ 2 key3=\"value3\\\"");
    ret = func_WELFParse(str,map,0);
    CU_ASSERT_EQUAL(ret,3);
    result = zymap_get_str(map,_K("key1"));
    CU_ASSERT_STRING_EQUAL("value1",result);
    result = zymap_get_str(map,_K("key2"));
    CU_ASSERT_STRING_EQUAL("value 2",result);
    result = zymap_get_str(map,_K("key3"));
    CU_ASSERT_STRING_EQUAL("value3\"",result);
    //zyprintf("${1@MPJ}",map);
    free(str);
    zymap_clean(map);

}
ENDTEST(func_WELFParse);

TEST(func_FormatMac)
{
    const char* str="12-34-56-78-9a-bc";
    const char* format="HH-HH-HH-HH-HH-HH";
    char result[6];
    func_FormatMac(format ,str,result);
    CU_ASSERT_NSTRING_EQUAL("\x12\x34\x56\x78\x9a\xbc",result,6);

    str="12:34:56:78:9a:bc";
    format="HH:HH:HH:HH:HH:HH";
    func_FormatMac(format ,str,result);
    CU_ASSERT_NSTRING_EQUAL("\x12\x34\x56\x78\x9a\xbc",result,6);
    
    str="1234-5678-9ABC";
    format="HHHH-HHHH-HHHH";
    func_FormatMac(format ,str,result);
    CU_ASSERT_NSTRING_EQUAL("\x12\x34\x56\x78\x9a\xbc",result,6);
    
    str="1234.5678.9ABC";
    format="HHHH.HHHH.HHHH";
    func_FormatMac(format ,str,result);
    CU_ASSERT_NSTRING_EQUAL("\x12\x34\x56\x78\x9a\xbc",result,6);
    
    str="123456789ABC";
    format="HHHHHHHHHHHH";
    func_FormatMac(format ,str,result);
    CU_ASSERT_NSTRING_EQUAL("\x12\x34\x56\x78\x9a\xbc",result,6);
    /*for(i=0;i<6;i++)
    {
        printf("%x:",(unsigned char)result[i]);
    }
    printf("\n");*/
}
ENDTEST(func_FormatMac);


ENDTESTCASE

#endif

