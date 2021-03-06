#ifndef _KEY_VALUE_H_
#define _KEY_VALUE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PCRE_H
# include <pcre.h>
#endif






//http的请求方法
typedef enum {
	HTTP_METHOD_UNSET = -1,
	HTTP_METHOD_GET,
	HTTP_METHOD_POST,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_OPTIONS,
	HTTP_METHOD_PROPFIND,  /* WebDAV */
	HTTP_METHOD_MKCOL,
	HTTP_METHOD_PUT,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_COPY,
	HTTP_METHOD_MOVE,
	HTTP_METHOD_PROPPATCH,
	HTTP_METHOD_REPORT, /* DeltaV */
	HTTP_METHOD_CHECKOUT,
	HTTP_METHOD_CHECKIN,
	HTTP_METHOD_VERSION_CONTROL,
	HTTP_METHOD_UNCHECKOUT,
	HTTP_METHOD_MKACTIVITY,
	HTTP_METHOD_MERGE,
	HTTP_METHOD_LOCK,
	HTTP_METHOD_UNLOCK,
	HTTP_METHOD_LABEL,
	HTTP_METHOD_CONNECT
} http_method_t;









//http的版本
typedef enum { HTTP_VERSION_UNSET = -1, HTTP_VERSION_1_0, HTTP_VERSION_1_1 } http_version_t;











//keyvalue结构体定义
typedef struct {
	int key;
	char *value;
} keyvalue;









//s_keyvalue结构体定义
typedef struct {
	char *key;
	char *value;
} s_keyvalue;










//pcre_keyvalue结构体定义
typedef struct {
#ifdef HAVE_PCRE_H
	pcre *key;
	pcre_extra *key_extra;
#endif

	buffer *value;
} pcre_keyvalue;












// http的验证方法
typedef enum { HTTP_AUTH_BASIC, HTTP_AUTH_DIGEST } httpauth_type;










//httpauth_keyvalue结构体定义
typedef struct {
	char *key;
	char *realm;
	httpauth_type type;
} httpauth_keyvalue;








/*
#define语句中的#是把参数字符串化，##是连接两个参数成为一个整体。
#define FACTORY_REF(name) { #name, Make##name }
中#name就是将传入的name进行字符串化，Make##name就是将Make跟name进行连接，使它们成为一个整体。
*/
#define KVB(x) \
typedef struct {\
	x **kv; \
	size_t used;\
	size_t size;\
} x ## _buffer

KVB(keyvalue);
KVB(s_keyvalue);
KVB(httpauth_keyvalue);
KVB(pcre_keyvalue);










const char *get_http_status_name(int i);
const char *get_http_version_name(int i);
const char *get_http_method_name(http_method_t i);
const char *get_http_status_body_name(int i);
int get_http_version_key(const char *s);
http_method_t get_http_method_key(const char *s);

const char *keyvalue_get_value(keyvalue *kv, int k);
int keyvalue_get_key(keyvalue *kv, const char *s);

keyvalue_buffer *keyvalue_buffer_init(void);
int keyvalue_buffer_append(keyvalue_buffer *kvb, int k, const char *value);
void keyvalue_buffer_free(keyvalue_buffer *kvb);

s_keyvalue_buffer *s_keyvalue_buffer_init(void);
int s_keyvalue_buffer_append(s_keyvalue_buffer *kvb, const char *key, const char *value);
void s_keyvalue_buffer_free(s_keyvalue_buffer *kvb);

httpauth_keyvalue_buffer *httpauth_keyvalue_buffer_init(void);
int httpauth_keyvalue_buffer_append(httpauth_keyvalue_buffer *kvb, const char *key, const char *realm, httpauth_type type);
void httpauth_keyvalue_buffer_free(httpauth_keyvalue_buffer *kvb);

pcre_keyvalue_buffer *pcre_keyvalue_buffer_init(void);
int pcre_keyvalue_buffer_append(pcre_keyvalue_buffer *kvb, const char *key, const char *value);
void pcre_keyvalue_buffer_free(pcre_keyvalue_buffer *kvb);

#endif
