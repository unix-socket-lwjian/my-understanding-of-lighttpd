#include <sys/stat.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "request.h"
#include "keyvalue.h"
#include "log.h"

static int request_check_hostname(server *srv, connection *con, buffer *host) {
	enum { DOMAINLABEL, TOPLABEL } stage = TOPLABEL;
	size_t i;
	int label_len = 0;
	size_t host_len;
	char *colon;
	int is_ip = -1; /* -1 don't know yet, 0 no, 1 yes */
	int level = 0;

	UNUSED(srv);
	UNUSED(con);

	/*
	 *       hostport      = host [ ":" port ]
	 *       host          = hostname | IPv4address | IPv6address
	 *       hostname      = *( domainlabel "." ) toplabel [ "." ]
	 *       domainlabel   = alphanum | alphanum *( alphanum | "-" ) alphanum
	 *       toplabel      = alpha | alpha *( alphanum | "-" ) alphanum
	 *       IPv4address   = 1*digit "." 1*digit "." 1*digit "." 1*digit
	 *       IPv6address   = "[" ... "]"
	 *       port          = *digit
	 */

	/* no Host: */
	if (!host || host->used == 0) return 0;

	host_len = host->used - 1;

	/* IPv6 adress */
	if (host->ptr[0] == '[') {
		char *c = host->ptr + 1;
		int colon_cnt = 0;

		/* check portnumber */
		for (; *c && *c != ']'; c++) {
			if (*c == ':') {
				if (++colon_cnt > 7) {
					return -1;
				}
			} else if (!light_isxdigit(*c)) {
				return -1;
			}
		}

		/* missing ] */
		if (!*c) {
			return -1;
		}

		/* check port */
		if (*(c+1) == ':') {
			for (c += 2; *c; c++) {
				if (!light_isdigit(*c)) {
					return -1;
				}
			}
		}
		return 0;
	}

	if (NULL != (colon = memchr(host->ptr, ':', host_len))) {
		char *c = colon + 1;

		/* check portnumber */
		for (; *c; c++) {
			if (!light_isdigit(*c)) return -1;
		}

		/* remove the port from the host-len */
		host_len = colon - host->ptr;
	}

	/* Host is empty */
	if (host_len == 0) return -1;

	/* if the hostname ends in a "." strip it */
	if (host->ptr[host_len-1] == '.') host_len -= 1;

	/* scan from the right and skip the \0 */
	for (i = host_len - 1; i + 1 > 0; i--) {
		const char c = host->ptr[i];

		switch (stage) {
		case TOPLABEL:
			if (c == '.') {
				/* only switch stage, if this is not the last character */
				if (i != host_len - 1) {
					if (label_len == 0) {
						return -1;
					}

					/* check the first character at right of the dot */
					if (is_ip == 0) {
						if (!light_isalpha(host->ptr[i+1])) {
							return -1;
						}
					} else if (!light_isdigit(host->ptr[i+1])) {
						is_ip = 0;
					} else if ('-' == host->ptr[i+1]) {
						return -1;
					} else {
						/* just digits */
						is_ip = 1;
					}

					stage = DOMAINLABEL;

					label_len = 0;
					level++;
				} else if (i == 0) {
					/* just a dot and nothing else is evil */
					return -1;
				}
			} else if (i == 0) {
				/* the first character of the hostname */
				if (!light_isalpha(c)) {
					return -1;
				}
				label_len++;
			} else {
				if (c != '-' && !light_isalnum(c)) {
					return -1;
				}
				if (is_ip == -1) {
					if (!light_isdigit(c)) is_ip = 0;
				}
				label_len++;
			}

			break;
		case DOMAINLABEL:
			if (is_ip == 1) {
				if (c == '.') {
					if (label_len == 0) {
						return -1;
					}

					label_len = 0;
					level++;
				} else if (!light_isdigit(c)) {
					return -1;
				} else {
					label_len++;
				}
			} else {
				if (c == '.') {
					if (label_len == 0) {
						return -1;
					}

					/* c is either - or alphanum here */
					if ('-' == host->ptr[i+1]) {
						return -1;
					}

					label_len = 0;
					level++;
				} else if (i == 0) {
					if (!light_isalnum(c)) {
						return -1;
					}
					label_len++;
				} else {
					if (c != '-' && !light_isalnum(c)) {
						return -1;
					}
					label_len++;
				}
			}

			break;
		}
	}

	/* a IP has to consist of 4 parts */
	if (is_ip == 1 && level != 3) {
		return -1;
	}

	if (label_len == 0) {
		return -1;
	}

	return 0;
}

#if 0
#define DUMP_HEADER
#endif

int http_request_split_value(array *vals, buffer *b) {
	char *s;
	size_t i;
	int state = 0;
	/*
	 * parse
	 *
	 * val1, val2, val3, val4
	 *
	 * into a array (more or less a explode() incl. striping of whitespaces
	 */

	if (b->used == 0) return 0;

	s = b->ptr;

	for (i =0; i < b->used - 1; ) {
		char *start = NULL, *end = NULL;
		data_string *ds;

		switch (state) {
		case 0: /* ws */

			/* skip ws */
			for (; (*s == ' ' || *s == '\t') && i < b->used - 1; i++, s++);


			state = 1;
			break;
		case 1: /* value */
			start = s;

			for (; *s != ',' && i < b->used - 1; i++, s++);
			end = s - 1;

			for (; (*end == ' ' || *end == '\t') && end > start; end--);

			if (NULL == (ds = (data_string *)array_get_unused_element(vals, TYPE_STRING))) {
				ds = data_string_init();
			}

			buffer_copy_string_len(ds->value, start, end-start+1);
			array_insert_unique(vals, (data_unset *)ds);

			if (*s == ',') {
				state = 0;
				i++;
				s++;
			} else {
				/* end of string */

				state = 2;
			}
			break;
		default:
			i++;
			break;
		}
	}
	return 0;
}

int request_uri_is_valid_char(unsigned char c) {
	if (c <= 32) return 0;
	if (c == 127) return 0;
	if (c == 255) return 0;

	return 1;
}














































//http_request_parse函数功能：解析客户端发过来的请求 返回值：1表示有后续的POST数据到达 0表示其他
int http_request_parse(server *srv, connection *con) { 
	char *uri = NULL, *proto = NULL, *method = NULL, con_length_set;
	/*
		头域是由关键字(field-name)、冒号和可选值(field-value)组成的（message-header = field-name ":" [field-value]）,
		这里设置变量is_key用于标记区分当前处理的字符属于哪部分，为1表示属于关键字部分，为0表示属于field-value部分。
	*/
	int is_key = 1, key_len = 0, is_ws_after_key = 0, in_folding;
	char *value = NULL, *key = NULL;

	enum { HTTP_CONNECTION_UNSET, HTTP_CONNECTION_KEEPALIVE, HTTP_CONNECTION_CLOSE } keep_alive_set = HTTP_CONNECTION_UNSET;

	int line = 0;

	int request_line_stage = 0;
	size_t i, first;

	int done = 0;
	/*
		正则式形式的请求消息格式，三行分别表示为Request-Line、header（包括general-header、request-header、entity-header）和CRLF的对应正则式。
	*/
	/*
	 * Request: "^(GET|POST|HEAD) ([^ ]+(\\?[^ ]+|)) (HTTP/1\\.[01])$"
	 * Option : "^([-a-zA-Z]+): (.+)$"
	 * End    : "^$"
	 */


//日志记录
	if (con->conf.log_request_header) { 
		log_error_write(srv, __FILE__, __LINE__, "sdsdSb",
				"fd:", con->fd,
				"request-len:", con->request.request->used,
				"\n", con->request.request);
	}



/*
	根据RFC 2616第4.1节，一般来说，健壮性足够好的服务器应该忽略任意请求行（Request-Line）前面的空行。也就是说，在服务器开始消息流的时候发现了一个CRLF则
	应该忽略这个CRLF。而由于某些有问题的HTTP/1.0客户端会在POST请求消息之后产生额外的CRLF，如果是Keep-Alive连接，则这个额外的CRLF会保留到下一次请求处理中，
	因此Lighttpd服务器应该忽略它们。判断"con->request_count > 1 "表示前面处理过连接，即之前客户端POST过请求消息并且连接是Keep-Alive。复制到con->parse_request
	接下来对其进行解析。
*/
	if (con->request_count > 1 &&
	    con->request.request->ptr[0] == '\r' &&
	    con->request.request->ptr[1] == '\n') {
		buffer_copy_string_len(con->parse_request, con->request.request->ptr + 2, con->request.request->used - 1 - 2);
	} 
	else {
		/* fill the local request buffer */
		buffer_copy_string_buffer(con->parse_request, con->request.request);
	}





	keep_alive_set = 0;
	con_length_set = 0;



//按照请求行Request-Line的格式进行 逐个字符 解析处理




//对请求行（起始行）进行解析：<method> <uri> <protocol>\r\n
	for (i = 0, first = 0; i < con->parse_request->used && line == 0; i++) { 
		char *cur = con->parse_request->ptr + i;

		switch(*cur) {
			/*
				正常的请求行应该是以\r\n结束	
			*/
		case '\r':
			//判断下一个符号是否为'\n'
			if (con->parse_request->ptr[i+1] == '\n') { 
				http_method_t r;
				char *nuri = NULL;
				size_t j;

				
			/*
				截取请求行：利用函数buffer_copy_string_len()将con->parse_request的前i个字符（即请求行）复制到con->request.request_line内。
			*/	
			/*转换： \r\n -> \0\0 */
				con->parse_request->ptr[i] = '\0';
				con->parse_request->ptr[i+1] = '\0';
				buffer_copy_string_len(con->request.request_line, con->parse_request->ptr, i);



			/*
				变量request_line_stage用来记录已经遇到的空格数，正常的请求行逐个字符解析完后，request_line_stage应该等于2，
				即"<method> <uri> <protocol>\r\n"格式的请求行只包含两个空格字符，否则就是错误的请求，因此设置状态码为400(Bad Request)。
			*/	
				if (request_line_stage != 2) {
					con->http_status = 400;
					con->response.keep_alive = 0;
					con->keep_alive = 0;

					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "s", "incomplete request line -> 400");
						log_error_write(srv, __FILE__, __LINE__, "Sb",
								"request-header:\n",
								con->request.request);
					}
					return 0;
				}





			/*截取请求行内的method、uri、protocol。*/
				proto = con->parse_request->ptr + first;
				*(uri - 1) = '\0';	/*在method和uri之间截断*/	
				*(proto - 1) = '\0';/*在uri和protocol之间截断*/	








				/*
					记录Request方法，函数get_http_method_key功能为获取给定字符串对应的枚举值。如果没有对应枚举值，则返回-1。
					设置状态码501(Not Implemented)表示未实现该请求method。
				*/
				if (-1 == (r = get_http_method_key(method))) {
					con->http_status = 501;
					con->response.keep_alive = 0;
					con->keep_alive = 0;

					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "s", "unknown http-method -> 501");
						log_error_write(srv, __FILE__, __LINE__, "Sb",
								"request-header:\n",
								con->request.request);
					}

					return 0;
				}
				con->request.http_method = r; //对应method的枚举值







				
				 /*
					记录HTTP协议版本号；HTTP协议使用"<major>.<major>"的数字模式来指明协议的版本号，即包括主版本号和副版本号，它们之间用点（.）分割开。
				 */
				if (0 == strncmp(proto, "HTTP/", sizeof("HTTP/") - 1)) {
					//主版本号
					char * major = proto + sizeof("HTTP/") - 1; 
					//副版本号
					char * minor = strchr(major, '.');  
					char *err = NULL;
					int major_num = 0, minor_num = 0;

					int invalid_version = 0;
				/*
					没找到点或没有主版本号或没有副版本号都是错误的HTTP协议的版本号。
				*/
					if (NULL == minor || /* no dot */
					    minor == major || /* no major */
					    *(minor + 1) == '\0' /* no minor */) 
					{
						invalid_version = 1;
					} 
					else { 
					/*
						将字符串对版本号转换成整型
						在major和minor之间截断，便于接下来的strtol()函数调用转换主版本号。
						strtol函数会将参数nptr字符串根据参数base（表示进制）来转换成长整型数。long int strtol(const char *nptr,char *endptr,int base);
					*/
						*minor = '\0';
						major_num = strtol(major, &err, 10); 

						if (*err != '\0') invalid_version = 1;

						*minor++ = '.'; //还原
						minor_num = strtol(minor, &err, 10); //转换

						if (*err != '\0') invalid_version = 1;
					}

					//错误的HTTP协议的版本号
					if (invalid_version) { 
						con->http_status = 400;
						con->keep_alive = 0;

						if (srv->srvconf.log_request_header_on_error) {
							log_error_write(srv, __FILE__, __LINE__, "s", "unknown protocol -> 400");
							log_error_write(srv, __FILE__, __LINE__, "Sb",
									"request-header:\n",
									con->request.request);
						}
						return 0;
					}


					/*
					HTTP_VERSION_1_1和HTTP_VERSION_1_0为枚举值，定义在keyvalue.h头文件内。
					*/
					if (major_num == 1 && minor_num == 1) {
						con->request.http_version = con->conf.allow_http11 ? HTTP_VERSION_1_1 : HTTP_VERSION_1_0;
					} else if (major_num == 1 && minor_num == 0) {
						con->request.http_version = HTTP_VERSION_1_0;
					} 
					else {
						con->http_status = 505;

						if (srv->srvconf.log_request_header_on_error) {
							log_error_write(srv, __FILE__, __LINE__, "s", "unknown HTTP version -> 505");
							log_error_write(srv, __FILE__, __LINE__, "Sb",
									"request-header:\n",
									con->request.request);
						}
						return 0;
					}
				} 

				//不是HTTP协议
				else { 
					con->http_status = 400;
					con->keep_alive = 0;

					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "s", "unknown protocol -> 400");
						log_error_write(srv, __FILE__, __LINE__, "Sb",
								"request-header:\n",
								con->request.request);
					}
					return 0;
				}







				//记录uri
				if (0 == strncmp(uri, "http://", 7) &&
				    NULL != (nuri = strchr(uri + 7, '/'))) {
					/* ignore the host-part */
				/*
					忽略掉主机部分，即当请求行内的uri为absolutelyRUI时。如请求行为为"GET http://www.baidu.com/www/index.html HTTP/1.1",
					此时uri内的主机部分"http://www.baidu.com"将被去掉。
				*/
					buffer_copy_string_len(con->request.uri, nuri, proto - nuri - 1);
				} else {
					/* everything looks good so far */
					buffer_copy_string_len(con->request.uri, uri, proto - uri - 1);
				}
				/*
					下面代码用于检查uri字符的合法性，这儿的uri是经过客户端编码了的。
				*/
				for (j = 0; j < con->request.uri->used - 1; j++) {
				/*
					函数request_uri_is_valid_char()定义在request.c源文件内，用于检查参数c是否为uri合法字符，合法返回1，否则返回0值。
				*/
					if (!request_uri_is_valid_char(con->request.uri->ptr[j])) {
					//捕获非法字符	
						unsigned char buf[2];
						con->http_status = 400;
						con->keep_alive = 0;

						if (srv->srvconf.log_request_header_on_error) {
							buf[0] = con->request.uri->ptr[j];
							buf[1] = '\0';

							if (con->request.uri->ptr[j] > 32 &&
							    con->request.uri->ptr[j] != 127) {
								/* the character is printable -> print it */
								log_error_write(srv, __FILE__, __LINE__, "ss",
										"invalid character in URI -> 400",
										buf);
							} else {
								/* a control-character, print ascii-code */
								log_error_write(srv, __FILE__, __LINE__, "sd",
										"invalid character in URI -> 400",
										con->request.uri->ptr[j]);
							}

							log_error_write(srv, __FILE__, __LINE__, "Sb",
									"request-header:\n",
									con->request.request);
						}

						return 0;
					}
				}
				/*
					转存请求uri
				*/
				buffer_copy_string_buffer(con->request.orig_uri, con->request.uri);

				con->http_status = 0;

				i++;
				line++; 	//请求行已经处理完毕，设置变量跳出for循环
				first = i+1;
			}
			break;





		//正常的客户端请求行格式为：<method> <uri> <protocol>\r\n 即分为三个阶段 request_line_stage用于记录当前分析处于哪个阶段（或几个空格）
		case ' ': 
			switch(request_line_stage) {
			//第一阶段为<method>	
			case 0: 
				
				method = con->parse_request->ptr + first;
				first = i + 1;
				break;
			//第二阶段为<uri>	
			case 1: 
				
				uri = con->parse_request->ptr + first;
				first = i + 1;
				break;
			//request_line_stage大于等于2时就表示客户端请求行内的空格字符多于两个，即为错误请求	
			default: 
				con->http_status = 400;
				con->response.keep_alive = 0;
				con->keep_alive = 0;

				if (srv->srvconf.log_request_header_on_error) {
					log_error_write(srv, __FILE__, __LINE__, "s", "overlong request line -> 400");
					log_error_write(srv, __FILE__, __LINE__, "Sb",
							"request-header:\n",
							con->request.request);
				}
				return 0;
			}
			request_line_stage++; //遇到一个空格就加一
			break;


		} //switch(*cur)


	} //对请求行（起始行）进行解析循环体






	/*
		HTTP/1.1将"\r\n"字符串定义为除了实体主体外的其他任何协议元素的行结尾标示。但是，HTTP/1.1的消息头域值可以折叠成多行，
		其紧接着的折叠行由空格(SP)或水平制表符(HT)折叠标记开始。变量in_folding就是用于标记折叠行。
	*/
	in_folding = 0;
	/*
		检查是否指定了请求的uri地址。与1比较而不是与0比较是因为如果buffer结构体保存的数据是字符串，则其used字段的计算将是包括最后的'\0'字符。
	*/
	if (con->request.uri->used == 1) {
		con->http_status = 400;
		con->response.keep_alive = 0;
		con->keep_alive = 0;

		log_error_write(srv, __FILE__, __LINE__, "s", "no uri specified -> 400");
		if (srv->srvconf.log_request_header_on_error) {
			log_error_write(srv, __FILE__, __LINE__, "Sb",
							"request-header:\n",
							con->request.request);
		}
		return 0;
	}









//对首部进行解析
	for (; i < con->parse_request->used && !done; i++) { 
	//如果进入到此步骤 则i已经指向HTTP报文的首部 
		/*
			解析请求头，is_key用于标记区分当前处理的字符属于哪部分，为1表示属于field-name部分，为0表示属于field-value部分，两部分之间通过冒号分割。
		*/
		char *cur = con->parse_request->ptr + i;
		//如果为field-name部分
		if (is_key) { 
			size_t j;
			//标记 遇到冒号则进入field-value处理部分
			int got_colon = 0; 


			switch(*cur) {

			case ':':
				//遇到冒号进入进入field-value处理部分
				is_key = 0; 
				//value为field-value开始字符位置
				value = cur + 1; 

				if (is_ws_after_key == 0) {
					//field-name字符串实际长度 
					key_len = i - first; 
				}
				is_ws_after_key = 0;
				break;


			//遇到上面这些字符，即表示field-name字符串内会包含这些字符则都是错误情况。
			case '(':
			case ')':
			case '<':
			case '>':
			case '@':
			case ',':
			case ';':
			case '\\':
			case '\"':
			case '/':
			case '[':
			case ']':
			case '?':
			case '=':
			case '{':
			case '}':
				con->http_status = 400;
				con->keep_alive = 0;
				con->response.keep_alive = 0;

				log_error_write(srv, __FILE__, __LINE__, "sbsds",
						"invalid character in key", con->request.request, cur, *cur, "-> 400");
				return 0;


			case ' ':
			case '\t':
				//是否是消息头域的开始，如果是则表示消息头域值(field-value)折叠成多行。设置is_key和in_folding标记，然后break跳出。
				if (i == first) { 
					is_key = 0;
					in_folding = 1;
					value = cur;

					break;
				}


/*
	不是field-value折叠情况，则有另外两种可能，一是field-name内包含有空格或水平制表符，根据前面的注释可以知道这种情况是非法头域；
	二是field-name和冒号之间有空格或水平制表符，下面这个for循环对这两种情况进行处理。
*/

				key_len = i - first;
				/* skip every thing up to the : */
				for (j = 1; !got_colon; j++) {
					switch(con->parse_request->ptr[j + i]) {
					case ' ':
					case '\t': //第二种情况
						/* skip WS */
						continue;
					case ':':
						/* ok, done */

						i += j - 1;
						got_colon = 1;

						break;
					default: //第一种情况，出错
						/* error */

						if (srv->srvconf.log_request_header_on_error) {
							log_error_write(srv, __FILE__, __LINE__, "s", "WS character in key -> 400");
							log_error_write(srv, __FILE__, __LINE__, "Sb",
								"request-header:\n",
								con->request.request);
						}

						con->http_status = 400;
						con->response.keep_alive = 0;
						con->keep_alive = 0;

						return 0;
					}
				}

				break;



			case '\r':
				if (con->parse_request->ptr[i+1] == '\n' && i == first) {
				//遇到仅包含CRLF的空行，头域解析结束。	
					/* End of Header */
					con->parse_request->ptr[i] = '\0';
					con->parse_request->ptr[i+1] = '\0';

					i++;

					done = 1;

					break;
				} 
				else { //丢失换行符号
					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "s", "CR without LF -> 400");
						log_error_write(srv, __FILE__, __LINE__, "Sb",
							"request-header:\n",
							con->request.request);
					}

					con->http_status = 400;
					con->keep_alive = 0;
					con->response.keep_alive = 0;
					return 0;
				}
				/* fall thru */
				//发现有控制字符，报错
			case 0: /* illegal characters (faster than a if () :) */
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 10:
			case 11:
			case 12:
			case 14:
			case 15:
			case 16:
			case 17:
			case 18:
			case 19:
			case 20:
			case 21:
			case 22:
			case 23:
			case 24:
			case 25:
			case 26:
			case 27:
			case 28:
			case 29:
			case 30:
			case 31:
			case 127:
				con->http_status = 400;
				con->keep_alive = 0;
				con->response.keep_alive = 0;

				if (srv->srvconf.log_request_header_on_error) {
					log_error_write(srv, __FILE__, __LINE__, "sbsds",
						"CTL character in key", con->request.request, cur, *cur, "-> 400");

					log_error_write(srv, __FILE__, __LINE__, "Sb",
						"request-header:\n",
						con->request.request);
				}

				return 0;
			default:
				/* ok */
				break;
			}
		} 



		//field-value部分解析处理	
		else { 
			switch(*cur) {

			case '\r':
				if (con->parse_request->ptr[i+1] == '\n') {
					data_string *ds = NULL;
				/*
					一行消息的解析工作结束，该行可能是一个新的消息头域，也可能是上一个消息头域值(field-value)的折叠。
				*/
					con->parse_request->ptr[i] = '\0';
					con->parse_request->ptr[i+1] = '\0';



					//该行信息为上一个消息头域值(field-value)的折叠。
					if (in_folding) { 
						buffer *key_b;
					
						//头域里没有任何内容，除了空白字符
						if (!key || !key_len) { 
							/* 400 */

							if (srv->srvconf.log_request_header_on_error) {
								log_error_write(srv, __FILE__, __LINE__, "s", "WS at the start of first line -> 400");

								log_error_write(srv, __FILE__, __LINE__, "Sb",
									"request-header:\n",
									con->request.request);
							}


							con->http_status = 400;
							con->keep_alive = 0;
							con->response.keep_alive = 0;
							return 0;
						}




						/*
							找到保存上一个消息头域的ds(通过field-name来查找)，然后将本行信息作为field-value的折叠值添加到后面。
							消息头域的field-name和field-value存储在一个data_string结构体内，然后将这个data_string结构体作为array结构体(con->request.headers)
							的数据存储在其data字段内。
						*/
						key_b = buffer_init();
						buffer_copy_string_len(key_b, key, key_len);

						if (NULL != (ds = (data_string *)array_get_element(con->request.headers, key_b->ptr))) {
							buffer_append_string(ds->value, value);
						}

						buffer_free(key_b);
					} 
					//该行信息为一个新的消息头域
					else { 
						int s_len;
						key = con->parse_request->ptr + first; //key指向field-name的第一个字符

						s_len = cur - value; //cur在此指向了当前字符

						/* strip trailing white-spaces */ //剥去末尾空白字符
						for (; s_len > 0 && 
								(value[s_len - 1] == ' ' || 
								 value[s_len - 1] == '\t'); s_len--);

						value[s_len] = '\0';

						if (s_len > 0) { //如果field-value有值存在，则保存该头域。
							int cmp = 0;  //获得一个未使用的data
							if (NULL == (ds = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING))) {
								ds = data_string_init();
							}
							buffer_copy_string_len(ds->key, key, key_len);
							buffer_copy_string_len(ds->value, value, s_len);

							

//						******************************************下面几个if判断都是根据解析出来的每个头域值field-value来设置相应的变量**************************************	



							//需用头域Connection允许发送者指定某一特定连接中的选项，该选项一般取值包括有Keep-Alive和Close。
							if (0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Connection")))) { 
								array *vals;
								size_t vi;

								/* split on , */

								vals = srv->split_vals;

								array_reset(vals);
								/*
									函数http_request_split_value()将保存在ds->value内的类似于"val1,val2,val3,val4"形式的字符串按","分割（同时会去掉每个val的前后空格）后创建初始化对应data_string结构并保存到vals中。
									
								*/		
								http_request_split_value(vals, ds->value); 

								for (vi = 0; vi < vals->used; vi++) { //对每个值进行比较判断。
									data_string *dsv = (data_string *)vals->data[vi];

									if (0 == buffer_caseless_compare(CONST_BUF_LEN(dsv->value), CONST_STR_LEN("keep-alive"))) {
										keep_alive_set = HTTP_CONNECTION_KEEPALIVE;

										break;
									} else if (0 == buffer_caseless_compare(CONST_BUF_LEN(dsv->value), CONST_STR_LEN("close"))) {
										keep_alive_set = HTTP_CONNECTION_CLOSE;

										break;
									}
								}

							}


							/*
								实体头域Content—Length用来按十进制或八位字节数指明了发给接收到端的实体主体大小。或是在使用HEAD方法的情况下指明若请求为GET方法时响应应该发送的实体主体大小。
								任何大于等于0的Content-Length均为有效值。
							*/ 
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Content-Length")))) {
								char *err;
								unsigned long int r;
								size_t j;

								if (con_length_set) { //请求头重复，错误请求
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate Content-Length-header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}	
									array_insert_unique(con->request.headers, (data_unset *)ds); //该值被插入，因为已经存在，所以这里的插入是将该值添加到之前存在的值的后面。
									return 0;
								}
									
								if (ds->value->used == 0) SEGFAULT(); //确保有值

								for (j = 0; j < ds->value->used - 1; j++) { //根据上面的BNF检查错误
									char c = ds->value->ptr[j];
									if (!isdigit((unsigned char)c)) {
										log_error_write(srv, __FILE__, __LINE__, "sbs",
												"content-length broken:", ds->value, "-> 400");

										con->http_status = 400;
										con->keep_alive = 0;

										array_insert_unique(con->request.headers, (data_unset *)ds);
										return 0;
									}
								}

								r = strtoul(ds->value->ptr, &err, 10); //转换成十进制无符号整数

								if (*err == '\0') { //成功转换，设置相应变量
									con_length_set = 1;
									con->request.content_length = r;
								} else {
									log_error_write(srv, __FILE__, __LINE__, "sbs",
											"content-length broken:", ds->value, "-> 400");

									con->http_status = 400;
									con->keep_alive = 0;

									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}
							} 





							/*
								实体头域Content-Type用来指明发给接收端的实体主体的媒体类型，或在HEAD方法中指明若请求为GET时将发送的媒体类型。	
							*/
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Content-Type")))) {
								/* if dup, only the first one will survive */ //如果重复，那么只有第一次的值会被记录
								if (!con->request.http_content_type) {
									con->request.http_content_type = ds->value->ptr;
								} else {
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate Content-Type-header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}
									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}
							} 


							/*
								请求头域Expect用于指明客户端需要的特定服务器行为。Lighttpd目前无法满足任何的Expection，因此直接以417(期望失败)状态吗响应
							*/	
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Expect")))) {
								/* HTTP 2616 8.2.3
								 * Expect: 100-continue
								 *
								 *   -> (10.1.1)  100 (read content, process request, send final status-code)
								 *   -> (10.4.18) 417 (close)
								 *
								 * (not handled at all yet, we always send 417 here)
								 *
								 * What has to be added ?
								 * 1. handling of chunked request body
								 * 2. out-of-order sending from the HTTP/1.1 100 Continue
								 *    header
								 *
								 */

								con->http_status = 417;
								con->keep_alive = 0;

								array_insert_unique(con->request.headers, (data_unset *)ds);
								return 0;
							} 


							/*
								请求头域Host用于指明正在请求资源的网络主机和端口号。
							*/
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Host")))) {
								if (!con->request.http_host) {
									con->request.http_host = ds->value;
								} else {
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate Host-header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}
									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}
							} 



							/*
								请求头域If-Modified-Since主要用来让请求方法成为条件方法，即如果想知道Web服务器请求的资源自从由该头域里指定的时间之后都没有发生改变，
								那么Web服务器不会返回实体，而是以304（没有改变）状态码进行响应，同时返回消息也没有消息主体
							*/
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("If-Modified-Since")))) {
								/* Proxies sometimes send dup headers
								 * if they are the same we ignore the second
								 * if not, we raise an error */
								if (!con->request.http_if_modified_since) { //代理服务器有时会发送重复的请求头，如果它们相同则忽略第二个，否则抛出一个错误。
									con->request.http_if_modified_since = ds->value->ptr;
								} else if (0 == strcasecmp(con->request.http_if_modified_since,
											ds->value->ptr)) {
									/* ignore it if they are the same */

									ds->free((data_unset *)ds);
									ds = NULL;
								} else {
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate If-Modified-Since header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}
									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}
							}



							/*
								请求头域If-None-Match和If-Modified-Since类似，也是用来让请求方法成为条件方法，它通过比较请求实体的标签来验证已经获取的实体中是否有不存在于服务器当前实体中的实体，
								这个特性允许通过以一个最小事务开销来更新客户端缓存信息。
							*/
							else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("If-None-Match")))) { 
								/* if dup, only the first one will survive */
								if (!con->request.http_if_none_match) {
									con->request.http_if_none_match = ds->value->ptr;
								} else {
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate If-None-Match-header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}
									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}


								/*
									HTTP/1.1允许一个客户请求响应实体的一部分。利用请求头域Range可以请求一个或多个实体主体的某一范围内字节，而不是整个实体主体。
								*/
							} else if (cmp > 0 && 0 == (cmp = buffer_caseless_compare(CONST_BUF_LEN(ds->key), CONST_STR_LEN("Range")))) {
								if (!con->request.http_range) {
									/* bytes=.*-.* */

									if (0 == strncasecmp(ds->value->ptr, "bytes=", 6) &&
									    NULL != strchr(ds->value->ptr+6, '-')) {

										/* if dup, only the first one will survive */
										con->request.http_range = ds->value->ptr + 6;
									}
								} else {
									con->http_status = 400;
									con->keep_alive = 0;

									if (srv->srvconf.log_request_header_on_error) {
										log_error_write(srv, __FILE__, __LINE__, "s",
												"duplicate Range-header -> 400");
										log_error_write(srv, __FILE__, __LINE__, "Sb",
												"request-header:\n",
												con->request.request);
									}
									array_insert_unique(con->request.headers, (data_unset *)ds);
									return 0;
								}
							} 
							//将解析到的头域信息存储到con->request.headers内。
							if (ds) array_insert_unique(con->request.headers, (data_unset *)ds);
						}

						else { //空值的头域则直接忽略
							/* empty header-fields are not allowed by HTTP-RFC, we just ignore them */
						}
					}	
					i++; //变量复原，重新开始对下一个头域field-name的解析处理
					first = i+1;
					is_key = 1;
					value = 0;
#if 0
					/**
					 * for Bug 1230 keep the key_len a live
					 */
					key_len = 0; 
#endif
					in_folding = 0;
				} //(con->parse_request->ptr[i+1] == '\n') 
				else {
					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "sbs",
								"CR without LF", con->request.request, "-> 400");
					}

					con->http_status = 400;
					con->keep_alive = 0;
					con->response.keep_alive = 0;
					return 0;
				}
				break;

			case ' ':
			case '\t':
				/* strip leading WS */
				if (value == cur) value = cur+1;

			default:
				if (*cur >= 0 && *cur < 32) {
					if (srv->srvconf.log_request_header_on_error) {
						log_error_write(srv, __FILE__, __LINE__, "sds",
								"invalid char in header", (int)*cur, "-> 400");
					}

					con->http_status = 400;
					con->keep_alive = 0;

					return 0;
				}
				break;
			} //switch(*cur)主体
		}//field-value部分解析处理主体
	}//对首部进行解析





	con->header_len = i;

	/* do some post-processing */

//设置是否为keep_alive
	if (con->request.http_version == HTTP_VERSION_1_1) {
		if (keep_alive_set != HTTP_CONNECTION_CLOSE) {

			con->keep_alive = 1;
		} else {
			con->keep_alive = 0;
		}

		if (con->request.http_host == NULL ||
		    buffer_is_empty(con->request.http_host)) {
			con->http_status = 400;
			con->response.keep_alive = 0;
			con->keep_alive = 0;

			if (srv->srvconf.log_request_header_on_error) {
				log_error_write(srv, __FILE__, __LINE__, "s", "HTTP/1.1 but Host missing -> 400");
				log_error_write(srv, __FILE__, __LINE__, "Sb",
						"request-header:\n",
						con->request.request);
			}
			return 0;
		}
	} else {
		if (keep_alive_set == HTTP_CONNECTION_KEEPALIVE) {

			con->keep_alive = 1;
		} else {
			con->keep_alive = 0;
		}
	}

	/* check hostname field if it is set */
	if (NULL != con->request.http_host &&
	    0 != request_check_hostname(srv, con, con->request.http_host)) {

		if (srv->srvconf.log_request_header_on_error) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					"Invalid Hostname -> 400");
			log_error_write(srv, __FILE__, __LINE__, "Sb",
					"request-header:\n",
					con->request.request);
		}

		con->http_status = 400;
		con->response.keep_alive = 0;
		con->keep_alive = 0;

		return 0;
	}


	switch(con->request.http_method) {
	//保证get和head方法没有content_length首部 
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		if (con_length_set && con->request.content_length != 0) {
			/* content-length is missing */
			log_error_write(srv, __FILE__, __LINE__, "s",
					"GET/HEAD with content-length -> 400");

			con->keep_alive = 0;
			con->http_status = 400;
			return 0;
		}
		break;
	//保证post方法有content_length首部 
	case HTTP_METHOD_POST:
		/* content-length is required for them */
		if (!con_length_set) {
			/* content-length is missing */
			log_error_write(srv, __FILE__, __LINE__, "s",
					"POST-request, but content-length missing -> 411");

			con->keep_alive = 0;
			con->http_status = 411;
			return 0;

		}
		break;
	default:
		/* the may have a content-length */
		break;
	}


	
	if (con_length_set) {
		//判断数据量是否过大
		if (con->request.content_length > SSIZE_MAX) {
			con->http_status = 413;
			con->keep_alive = 0;

			log_error_write(srv, __FILE__, __LINE__, "sds",
					"request-size too long:", con->request.content_length, "-> 413");
			return 0;
		}

		//判断数据是否超过限制 
		if (srv->srvconf.max_request_size != 0 &&
		    (con->request.content_length >> 10) > srv->srvconf.max_request_size) {

			con->http_status = 413;
			con->keep_alive = 0;

			log_error_write(srv, __FILE__, __LINE__, "sds",
					"request-size too long:", con->request.content_length, "-> 413");
			return 0;
		}

		//有post数据需要读
		if (con->request.content_length != 0) {
			return 1;
		}
	}

	return 0;
}


































int http_request_header_finished(server *srv, connection *con) {
	UNUSED(srv);

	if (con->request.request->used < 5) return 0;

	if (0 == memcmp(con->request.request->ptr + con->request.request->used - 5, "\r\n\r\n", 4)) return 1;
	if (NULL != strstr(con->request.request->ptr, "\r\n\r\n")) return 1;

	return 0;
}
