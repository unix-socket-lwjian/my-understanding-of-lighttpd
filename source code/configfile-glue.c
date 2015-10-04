#include <string.h>

#include "base.h"
#include "buffer.h"
#include "array.h"
#include "log.h"
#include "plugin.h"

#include "configfile.h"

/**
 * like all glue code this file contains functions which
 * are the external interface of lighttpd. The functions
 * are used by the server itself and the plugins.
 *
 * The main-goal is to have a small library in the end
 * which is linked against both and which will define
 * the interface itself in the end.
 *
 */


/* handle global options */

/* parse config array */
 // 















//该函数用于完成用户配置到程序变量的转换
int config_insert_values_internal(server *srv, array *ca, const config_values_t cv[]) {
	size_t i;
	data_unset *du;

	for (i = 0; cv[i].key; i++) {
		//根据key获取配置项
		if (NULL == (du = array_get_element(ca, cv[i].key))) { //从ca->data里获取key=cv[i].key的元素放入du
			/* no found */
		//没有找到对应的配置项，即使用默认配置值，继续下一个处理
			continue;
		}

		switch (cv[i].type) {
		case T_CONFIG_ARRAY:
		/*
			数组类型的配置信息有：
			server.modules={"mod_indexfiles" "mod_dirlisting" "mod_staticfile" "mod_access" "mod_auth" "mod_accesslog"}
		*/
			if (du->type == TYPE_ARRAY) { //数组类型的配置信息
				size_t j;
				data_array *da = (data_array *)du; //将du的值赋给da

				for (j = 0; j < da->value->used; j++) {
			//必定是string类型		
					if (da->value->data[j]->type == TYPE_STRING) {
						data_string *ds = data_string_init();

						buffer_copy_string_buffer(ds->value, ((data_string *)(da->value->data[j]))->value); //将da->value->data[j]->value复制到ds->value
						if (!da->is_index_key) {
							/* the id's were generated automaticly, as we copy now we might have to renumber them
							 * this is used to prepend server.modules by mod_indexfiles as it has to be loaded
							 * before mod_fastcgi and friends */
							buffer_copy_string_buffer(ds->key, ((data_string *)(da->value->data[j]))->key);
						}

						array_insert_unique(cv[i].destination, (data_unset *)ds);
					} else {
						log_error_write(srv, __FILE__, __LINE__, "sssd",
								"the key of an array can only be a string or a integer, variable:",
								cv[i].key, "type:", da->value->data[j]->type);

						return -1;
					}
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ss", cv[i].key, "should have been a array of strings like ... = ( \"...\" )");

				return -1;
			}
			break;
		case T_CONFIG_STRING://字符串类型
		/*
			字符串类型配置信息：
			server.document-root="/home/lenky/source/lighttpd-1.4.20/lenky/"
		*/
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;

				buffer_copy_string_buffer(cv[i].destination, ds->value);
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ssss", cv[i].key, "should have been a string like ... = \"...\"");

				return -1;
			}
			break;
		case T_CONFIG_SHORT: //短整型类型的配置信息
		/*
			短整型的配置信息：
			server.port=3000
			server.max-worker=4
			server.max-fds=800
		*/
			switch(du->type) {
			case TYPE_INTEGER: {
				data_integer *di = (data_integer *)du;

				*((unsigned short *)(cv[i].destination)) = di->value;
				break;
			}
			case TYPE_STRING: {
				data_string *ds = (data_string *)du;

				log_error_write(srv, __FILE__, __LINE__, "ssb", "got a string but expected a short:", cv[i].key, ds->value);

				return -1;
			}
			default:
				log_error_write(srv, __FILE__, __LINE__, "ssds", "unexpected type for key:", cv[i].key, du->type, "expected a integer, range 0 ... 65535");
				return -1;
			}
			break;
		case T_CONFIG_BOOLEAN: //布尔类型配置信息
		/*
			布尔型的配置信息：
			dir-listing.sctivate="enable"
			$HTTP["url"]=~"^/www/"{
			dir-listing.sctivate="disable"
		*/
			if (du->type == TYPE_STRING) {
				data_string *ds = (data_string *)du;

				if (buffer_is_equal_string(ds->value, CONST_STR_LEN("enable"))) {
					*((unsigned short *)(cv[i].destination)) = 1;
				} else if (buffer_is_equal_string(ds->value, CONST_STR_LEN("disable"))) {
					*((unsigned short *)(cv[i].destination)) = 0;
				} else {
					log_error_write(srv, __FILE__, __LINE__, "ssbs", "ERROR: unexpected value for key:", cv[i].key, ds->value, "(enable|disable)");

					return -1;
				}
			} else {
				log_error_write(srv, __FILE__, __LINE__, "ssss", "ERROR: unexpected type for key:", cv[i].key, "(string)", "\"(enable|disable)\"");

				return -1;
			}
			break;
		case T_CONFIG_LOCAL: //本地类型和位置类型不获取值
		case T_CONFIG_UNSET: 
			break;
		case T_CONFIG_UNSUPPORTED: //不支持类型
			log_error_write(srv, __FILE__, __LINE__, "ssss", "ERROR: found unsupported key:", cv[i].key, "-", (char *)(cv[i].destination));

			srv->config_unsupported = 1;

			break;
		case T_CONFIG_DEPRECATED: //已被摒弃
			log_error_write(srv, __FILE__, __LINE__, "ssss", "ERROR: found deprecated key:", cv[i].key, "-", (char *)(cv[i].destination));

			srv->config_deprecated = 1;

			break;
		}
	}

	return 0;
}



























//该函数用于逐个记录那些被转换了的配置信息（记录在srv－>config_touched中）
int config_insert_values_global(server *srv, array *ca, const config_values_t cv[]) {
	size_t i;
	data_unset *du;
	//对将要被转换的配置值逐个判断以记录被使用了的配置项
	for (i = 0; cv[i].key; i++) {
		data_string *touched;

		if (NULL == (du = array_get_element(ca, cv[i].key))) {
			/* no found */
			//配置文件里没有对其的配置项
			continue;
		}

		/* touched */ //有配置
		touched = data_string_init();

		buffer_copy_string_len(touched->value, CONST_STR_LEN("")); //并不关心其配置值
		buffer_copy_string_buffer(touched->key, du->key); //获取其配置项的Key

		array_insert_unique(srv->config_touched, (data_unset *)touched); //记录被使用的配置项
	}

	return config_insert_values_internal(srv, ca, cv); //调用函数config_insert_values_internal()获取配置值
}














unsigned short sock_addr_get_port(sock_addr *addr) {
/*
	函数 ntohs()声明在头文件srpa/inet.h内，原型为uint16_t ntohs(uint16_t netshort);用来将参数netshort指定的16位无符号整型由
	网络字符顺序转换成主机字节顺序。
*/
#ifdef HAVE_IPV6
	return ntohs(addr->plain.sa_family ? addr->ipv6.sin6_port : addr->ipv4.sin_port);
#else
	return ntohs(addr->ipv4.sin_port);
#endif
}

static cond_result_t config_check_cond_cached(server *srv, connection *con, data_config *dc);



























static cond_result_t config_check_cond_nocache(server *srv, connection *con, data_config *dc) {
	buffer *l; 
	server_socket *srv_sock = con->srv_socket; //socket 插座、接口
	
	/* check parent first */
	if (dc->parent && dc->parent->context_ndx) { //如果父节点存在，但父节点未被判断或父节点是错误的，那么子节点也不能进行判断或子节点是错误的
		/**
		 * a nested conditional 
		 *
		 * if the parent is not decided yet or false, we can't be true either 
		 */
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "sb", "go parent", dc->parent->key);
		}

		switch (config_check_cond_cached(srv, con, dc->parent)) {
		case COND_RESULT_FALSE:
			return COND_RESULT_FALSE;
		case COND_RESULT_UNSET:
			return COND_RESULT_UNSET;
		default:
			break;
		}
	}

	if (dc->prev) {
		/**
		 * a else branch
		 *
		 * we can only be executed, if all of our previous brothers 
		 * are false
		 */
		 //存在前驱块，那么需要先判断前驱块状态
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "sb", "go prev", dc->prev->key);
		}

		/* make sure prev is checked first */
		config_check_cond_cached(srv, con, dc->prev);

		/* one of prev set me to FALSE */
		//在判断前驱块状态时候有可能就已经设置了本快的状态（config_check_cond_cached函数调用如前驱块为真，该前驱块以下的块将全都设置为假），如果为假则直接返回。
		switch (con->cond_cache[dc->context_ndx].result) {
		case COND_RESULT_FALSE:
			return con->cond_cache[dc->context_ndx].result;
		default:
			break;
		}
	}

	if (!con->conditional_is_valid[dc->comp]) {
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "dss", 
				dc->comp,
				dc->key->ptr,
				con->conditional_is_valid[dc->comp] ? "yeah" : "nej");
		}

		return COND_RESULT_UNSET;
	}

	/* pass the rules */
	//开始实际的连接状态判断，Lighttpd1.4.20提供的条件配置有10个，分别为server_socket HTTP_URL HTTP_HOST HTTP_REFERER HTTP_USER_AGENT HTTP_COOKIE
	//HTTP_REMOTE_IP HTTP_QUERY_STRING HTTP_SCHEME HTTP_REQUEST_METHOD

	switch (dc->comp) {
	case COMP_HTTP_HOST: {
		char *ck_colon = NULL, *val_colon = NULL;

		if (!buffer_is_empty(con->uri.authority)) { //authority内保存是请求连接的Host信息（可能是域名也可能是IP地址）

			/*
			 * append server-port to the HTTP_POST if necessary
			 */

			l = con->uri.authority;

			switch(dc->cond) {
			case CONFIG_COND_NE:
			case CONFIG_COND_EQ:
				ck_colon = strchr(dc->string->ptr, ':');
				val_colon = strchr(l->ptr, ':');

				if (ck_colon == val_colon) { //请求连接的Host信息与条件配置块的Host条件设置格式一致（即两者都包含有端口号或都没有包含端口号），则什么都不做。
					/* nothing to do with it */
					break;
				}
				if (ck_colon) { //请求连接的Host信息没有半酣端口号而条件配置块的Host包含端口号，因此给请求连接的Host加上端口号
					/* condition "host:port" but client send "host" */
					buffer_copy_string_buffer(srv->cond_check_buf, l);
					buffer_append_string_len(srv->cond_check_buf, CONST_STR_LEN(":"));
					buffer_append_long(srv->cond_check_buf, sock_addr_get_port(&(srv_sock->addr)));
					l = srv->cond_check_buf;
				} else if (!ck_colon) { //请求连接的Host信息包含端口号而条件配置信息块的Host没有包含端口号，因此将请求连接Host的端口号去掉。
					/* condition "host" but client send "host:port" */
					buffer_copy_string_len(srv->cond_check_buf, l->ptr, val_colon - l->ptr);
					l = srv->cond_check_buf;
				}
				break;
			default:
				break;
			}
		} else {
			l = srv->empty_string;
		}
		break;
	}
	case COMP_HTTP_REMOTE_IP: { //REMOTE adj 遥远的
		char *nm_slash;
		/* handle remoteip limitations
		 *
		 * "10.0.0.1" is provided for all comparisions
		 *
		 * only for == and != we support
		 *
		 * "10.0.0.1/24"
		 */

		if ((dc->cond == CONFIG_COND_EQ ||
		     dc->cond == CONFIG_COND_NE) &&
		    (con->dst_addr.plain.sa_family == AF_INET) &&
		    (NULL != (nm_slash = strchr(dc->string->ptr, '/')))) {
			int nm_bits;
			long nm;
			char *err;
			struct in_addr val_inp;

			if (*(nm_slash+1) == '\0') { //无分类域间路由选择CIDR(CIDR记法，斜线记法)，这里对CIDR格式字符串进行检验
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: no number after / ", dc->string); //CIDR格式不对，缺少表示网络前缀位数的数字

				return COND_RESULT_FALSE;
			}
			/*
				函数strtol()声明在头文件stdlib.h内，原型为long int strtol(const char *nptr,char **endptr,int base);用于将参数nptr字符串根据
				base指定的进制转换成对应的长整型数。参数base范围从2至36，或0（即默认采用十进制做转换，但遇到如'0x'前置字符则会使用十六进制做转换）。
				strtol()会扫描参数nptr字符串，跳过前面的空格字符，知道遇上数字或正负号才开始做转换，在遇到非数字或字符串结束时('\0')结束转换，并将结果返回。
				若参数endptr不为NULL，则会将不符合调节而终止的nptr中的字符指针由endptr返回。该函数执行成功返回转换后的长整型数，否则返回ERANGE(表示指定的专函字符串超出合法范围)
				并将错误代码存入errno中，此处用于获取端口十进制的整型数。
			*/
			nm_bits = strtol(nm_slash + 1, &err, 10);

			if (*err) {
				log_error_write(srv, __FILE__, __LINE__, "sbs", "ERROR: non-digit found in netmask:", dc->string, err);

				return COND_RESULT_FALSE;
			}

			/* take IP convert to the native */
			buffer_copy_string_len(srv->cond_check_buf, dc->string->ptr, nm_slash - dc->string->ptr);
#ifdef __WIN32
			if (INADDR_NONE == (val_inp.s_addr = inet_addr(srv->cond_check_buf->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: ip addr is invalid:", srv->cond_check_buf);

				return COND_RESULT_FALSE;
			}

#else
			/*
				函数inet_ston()声明在头文件sys/scoket.h内，原型为int inet_aton(const char *cp,struct in_addr *inp); 用于将参数cp所指的字符串形式的网络地址
				转换成网络地址成网络使用的二进制数形式，然后存于参数inp所指的in_addr结构中。
			*/
			if (0 == inet_aton(srv->cond_check_buf->ptr, &val_inp)) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "ERROR: ip addr is invalid:", srv->cond_check_buf);

				return COND_RESULT_FALSE;
			}
#endif

			/* build netmask */
			/*
				函数htonl()声明在头文件srpa/inet.h内，原型为unint32_t htonl(uint32_t hostlong); 用来将参数hostlong指定的32位无符号长整型由主机字节顺序转换成网络字符顺序。
			*/
			nm = htonl(~((1 << (32 - nm_bits)) - 1));

			if ((val_inp.s_addr & nm) == (con->dst_addr.ipv4.sin_addr.s_addr & nm)) { //当前连接的客户端IP地址与条件配置信息块的条件设置匹配，按需返回结果
				return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
			} else { //不匹配
				return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
			}
		} else {
			l = con->dst_addr_buf;
		}
		break;
	}
	case COMP_HTTP_SCHEME:
		l = con->uri.scheme;
		break;

	case COMP_HTTP_URL:
		l = con->uri.path;
		break;

	case COMP_HTTP_QUERY_STRING:
		l = con->uri.query;
		break;

	case COMP_SERVER_SOCKET:
		l = srv_sock->srv_token;
		break;

	case COMP_HTTP_REFERER: {
		data_string *ds;

		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Referer"))) {
			l = ds->value;
		} else {
			l = srv->empty_string;
		}
		break;
	}
	case COMP_HTTP_COOKIE: {
		data_string *ds;
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "Cookie"))) {
			l = ds->value;
		} else {
			l = srv->empty_string;
		}
		break;
	}
	case COMP_HTTP_USER_AGENT: {
		data_string *ds;
		if (NULL != (ds = (data_string *)array_get_element(con->request.headers, "User-Agent"))) {
			l = ds->value;
		} else {
			l = srv->empty_string;
		}
		break;
	}
	case COMP_HTTP_REQUEST_METHOD: {
		/*
			get_http_method_name()函数根据当前连接的请求方法（通过分析请求行得知）返回对应的字符串，比如"GET"、"POST"等
		*/
		const char *method = get_http_method_name(con->request.http_method);

		/* we only have the request method as const char but we need a buffer for comparing */
		//为了后面的统一匹配比较，利用该字符串初始化buffer结构体。
		buffer_copy_string(srv->tmp_buf, method);

		l = srv->tmp_buf;

		break;
	}
	default:
		return COND_RESULT_FALSE;
	}

	if (NULL == l) { //当前连接匹配字段为空，则返回假
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "bsbs", dc->comp_key,
					"(", l, ") compare to NULL");
		}
		return COND_RESULT_FALSE;
	}

	if (con->conf.log_condition_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "bsbsb", dc->comp_key,
				"(", l, ") compare to ", dc->string);
	}
	switch(dc->cond) {
	case CONFIG_COND_NE:
	case CONFIG_COND_EQ:
		if (buffer_is_equal(l, dc->string)) { //相等或不等匹配
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			return (dc->cond == CONFIG_COND_EQ) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
		break;
#ifdef HAVE_PCRE_H
	/*
		正则式匹配需要相应库的支持，GNU/Linux下有两套正则式编程支持库：POSIX库和PCRE库，POSIX库不需要单独安装，能满足一般需求，但是速度稍慢些，
		读者查看MAN手册。PCRE库久负盛名，功能强大，匹配速度快，但是可能需要单独安装。关于PCRE库的更多介绍，读者可以查阅站点：http://www.pcre.org/。
		此处用的是PCRE库。
	*/
	case CONFIG_COND_NOMATCH:
	case CONFIG_COND_MATCH: {
		cond_cache_t *cache = &con->cond_cache[dc->context_ndx];
		int n;

#ifndef elementsof
#define elementsof(x) (sizeof(x) / sizeof(x[0]))
#endif
		n = pcre_exec(dc->regex, dc->regex_study, l->ptr, l->used - 1, 0, 0,
				cache->matches, elementsof(cache->matches)); //利用PCRE库函数pcre_exec()执行匹配操作，如果不匹配或执行出错则返回一个负值（其中，不匹配则返回PCRE_ERROR_NOMATCH(该宏值为-1)），
				                                             //如果匹配成功将返回一个正数。关于函数pcre_exec()的详细说明可以参考说明文档：http://www.pcre.org/prce.txt.

		cache->patterncount = n;
		if (n > 0) { //匹配成功
			cache->comp_value = l;
			cache->comp_type  = dc->comp;
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_TRUE : COND_RESULT_FALSE;
		} else {
			/* cache is already cleared */
			return (dc->cond == CONFIG_COND_MATCH) ? COND_RESULT_FALSE : COND_RESULT_TRUE;
		}
		break;
	}
#endif
	default:
		/* no way */
		break;
	}

	return COND_RESULT_FALSE;
}






























//该函数被config_check_cond调用，判断connection结构体con是否能获得某个条件配置值
static cond_result_t config_check_cond_cached(server *srv, connection *con, data_config *dc) {
	cond_cache_t *caches = con->cond_cache;
	/*
		dc->context_ndx记录该dc在srv->config_context->data[]数组中存储位置的下标，而cond_cache_t与data_config一一对应。
	*/
//缓存未命中
	if (COND_RESULT_UNSET == caches[dc->context_ndx].result) {
//调用函数config_check_cond_nocache()进行条件配置块的条件设置匹配		
		if (COND_RESULT_TRUE == (caches[dc->context_ndx].result = config_check_cond_nocache(srv, con, dc))) { 
//if-else条件配置连接块if块或某else块取值为真，那么该块后面取值则都为假。
			if (dc->next) {
				data_config *c;
				if (con->conf.log_condition_handling) {
					log_error_write(srv, __FILE__, __LINE__, "s",
							"setting remains of chaining to false");
				}
				for (c = dc->next; c; c = c->next) {
					caches[c->context_ndx].result = COND_RESULT_FALSE;
				}
			}
		}
		caches[dc->context_ndx].comp_type = dc->comp;

		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__, "dss", dc->context_ndx,
					"(uncached) result:",
					caches[dc->context_ndx].result == COND_RESULT_UNSET ? "unknown" :
						(caches[dc->context_ndx].result == COND_RESULT_TRUE ? "true" : "false"));
		}
	} 
//缓存命中的情况
	else {
		if (con->conf.log_condition_handling) { 
			log_error_write(srv, __FILE__, __LINE__, "dss", dc->context_ndx,
					"(cached) result:",
					caches[dc->context_ndx].result == COND_RESULT_UNSET ? "unknown" : 
						(caches[dc->context_ndx].result == COND_RESULT_TRUE ? "true" : "false"));
		}
	}
	return caches[dc->context_ndx].result;
}























//将被config_cond_cache_reset调用将connection结构体的cond_cache_t缓存器重置
void config_cond_cache_reset_item(server *srv, connection *con, comp_key_t item) {
	size_t i;

	for (i = 0; i < srv->config_context->used; i++) {
		if (item == COMP_LAST_ELEMENT || 
		    con->cond_cache[i].comp_type == item) {
			con->cond_cache[i].result = COND_RESULT_UNSET;
			con->cond_cache[i].patterncount = 0;
			con->cond_cache[i].comp_value = NULL;
		}
	}
}




















/**
 * reset the config cache to its initial state at connection start
 */
//将connection结构体的cond_cache_t缓存器重置
void config_cond_cache_reset(server *srv, connection *con) {
	size_t i;

	config_cond_cache_reset_all_items(srv, con);

	for (i = 0; i < COMP_LAST_ELEMENT; i++) {
		con->conditional_is_valid[i] = 0;
	}
}




























//判断connection结构体con是否能获得某个条件配置值
int config_check_cond(server *srv, connection *con, data_config *dc) {
	if (con->conf.log_condition_handling) {
		log_error_write(srv, __FILE__, __LINE__,  "s",  "=== start of condition block ===");
	}
	return (config_check_cond_cached(srv, con, dc) == COND_RESULT_TRUE);
}








int config_append_cond_match_buffer(connection *con, data_config *dc, buffer *buf, int n)
{
	cond_cache_t *cache = &con->cond_cache[dc->context_ndx];
	if (n >= cache->patterncount) {
		return 0;
	}

	n <<= 1; /* n *= 2 */
	buffer_append_string_len(buf,
			cache->comp_value->ptr + cache->matches[n],
			cache->matches[n + 1] - cache->matches[n]);
	return 1;
}

