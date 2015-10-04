#ifndef _BASE_H_
#define _BASE_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include "buffer.h"
#include "array.h"
#include "chunk.h"
#include "keyvalue.h"
#include "settings.h"
#include "fdevent.h"
#include "sys-socket.h"
#include "splaytree.h"
#include "etag.h"


#if defined HAVE_LIBSSL && defined HAVE_OPENSSL_SSL_H
# define USE_OPENSSL
# include <openssl/ssl.h>
#endif

#ifdef HAVE_FAM_H
# include <fam.h>
#endif

#ifndef O_BINARY
# define O_BINARY 0
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#ifndef SIZE_MAX
# ifdef SIZE_T_MAX
#  define SIZE_MAX SIZE_T_MAX
# else
#  define SIZE_MAX ((size_t)~0)
# endif
#endif

#ifndef SSIZE_MAX
# define SSIZE_MAX ((size_t)~0 >> 1)
#endif

#ifdef __APPLE__
#include <crt_externs.h>
#define environ (* _NSGetEnviron())
#else
extern char **environ;
#endif

/* for solaris 2.5 and NetBSD 1.3.x */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* solaris and NetBSD 1.3.x again */
#if (!defined(HAVE_STDINT_H)) && (!defined(HAVE_INTTYPES_H)) && (!defined(uint32_t))
# define uint32_t u_int32_t
#endif


#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#include "settings.h"















typedef enum { T_CONFIG_UNSET, //未知
		T_CONFIG_STRING, //字符串
		T_CONFIG_SHORT, //短整类型
		T_CONFIG_BOOLEAN, //布尔类型
		T_CONFIG_ARRAY, //数组类型
		T_CONFIG_LOCAL, //本地类型
		T_CONFIG_DEPRECATED, //已被摒弃
		T_CONFIG_UNSUPPORTED //不被支持类型
} config_values_type_t;



















typedef enum { T_CONFIG_SCOPE_UNSET, //作用域未知
		T_CONFIG_SCOPE_SERVER, //服务器全局作用域
		T_CONFIG_SCOPE_CONNECTION //请求连接局部作用域
} config_scope_type_t;














typedef struct {
	const char *key; //配置信息key
	void *destination; //配置信息值的保存位置，根据值类型不同而指向不同类型的变量

	config_values_type_t type; //类型
	config_scope_type_t scope; //作用域
} config_values_t;


















typedef enum { DIRECT, EXTERNAL } connection_type;

















typedef struct {
	char *key;
	connection_type type;
	char *value;
} request_handler;





















typedef struct {
	char *key;
	char *host;
	unsigned short port;
	int used;
	short factor;
} fcgi_connections;




























typedef union {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
#endif
	struct sockaddr_in ipv4;
#ifdef HAVE_SYS_UN_H
	struct sockaddr_un un;
#endif
	struct sockaddr plain;
} sock_addr;



























/* fcgi_response_header contains ... */
#define HTTP_STATUS         BV(0)
#define HTTP_CONNECTION     BV(1)
#define HTTP_CONTENT_LENGTH BV(2)
#define HTTP_DATE           BV(3)
#define HTTP_LOCATION       BV(4)

typedef struct {
	/** HEADER */
	/* the request-line */
	buffer *request;
	buffer *uri;

	buffer *orig_uri;

	http_method_t  http_method;
	http_version_t http_version;

	buffer *request_line;

	/* strings to the header */
	buffer *http_host; /* not alloced */
	const char   *http_range;
	const char   *http_content_type;
	const char   *http_if_modified_since;
	const char   *http_if_none_match;

	array  *headers;

	/* CONTENT */
	size_t content_length; /* returned by strtoul() */

	/* internal representation */
	int     accept_encoding;

	/* internal */
	buffer *pathinfo;
} request;














typedef struct {
	off_t   content_length;
	int     keep_alive;               /* used by  the subrequests in proxy, cgi and fcgi to say the subrequest was keep-alive or not */

	array  *headers;

	enum {
		HTTP_TRANSFER_ENCODING_IDENTITY, HTTP_TRANSFER_ENCODING_CHUNKED
	} transfer_encoding;
} response;














typedef struct {
	buffer *scheme;
	buffer *authority;
	buffer *path;
	buffer *path_raw;
	buffer *query;
} request_uri;



















typedef struct {
	buffer *path;
	buffer *basedir; /* path = "(basedir)(.*)" */

	buffer *doc_root; /* path = doc_root + rel_path */
	buffer *rel_path;

	buffer *etag;
} physical;



























//定义文件状态缓冲器的结构体
typedef struct {
//保存文件名
	buffer *name; 
//保存文件对应ETag
	buffer *etag; 
//保存文件状态信息
	struct stat st; 
//刚被放入文件缓器伸展树时的时间戳 time_t存的是1970年1月1日0时0分0秒起至今的UTC时间所经过的秒数，long int型。
	time_t stat_ts; 
#ifdef HAVE_LSTAT
//符号链接标记
	char is_symlink; 
#endif
//FAM相关字段
#ifdef HAVE_FAM_H 
//文件目录版本号
	int    dir_version; 
//父目录索引（hash值），即FAM监控伸展树对应的节点索引
	int    dir_ndx; 
#endif
//文件类型
	buffer *content_type;  
} stat_cache_entry;































//存放全部的文件状态缓冲器和fam监控的结构体定义
typedef struct {
//所有的文件状态缓冲器节点都放在此伸展树files中
	splay_tree *files;
	buffer *dir_name; /* for building the dirname from the filename */
//所有的fam监控节点都放在此伸展树dirs中
#ifdef HAVE_FAM_H
	splay_tree *dirs; /* the nodes of the tree are fam_dir_entry */
	FAMConnection *fam;
	int    fam_fcce_ndx;
#endif
//用于短暂保存寻找节点的hash－key
	buffer *hash_key;  /* temp-store for the hash-key */
} stat_cache;




























typedef struct {
	array *mimetypes;

	/* virtual-servers */
	buffer *document_root;
	buffer *server_name;
	buffer *error_handler;
	buffer *server_tag;
	buffer *dirlist_encoding;
	buffer *errorfile_prefix;

	unsigned short max_keep_alive_requests;
	unsigned short max_keep_alive_idle;
	unsigned short max_read_idle;
	unsigned short max_write_idle;
	unsigned short use_xattr;
	unsigned short follow_symlink;
	unsigned short range_requests;

	/* debug */

	unsigned short log_file_not_found;
	unsigned short log_request_header;
	unsigned short log_request_handling;
	unsigned short log_response_header;
	unsigned short log_condition_handling;
	unsigned short log_ssl_noise;


	/* server wide */
	buffer *ssl_pemfile;
	buffer *ssl_ca_file;
	buffer *ssl_cipher_list;
	unsigned short ssl_use_sslv2;

	unsigned short use_ipv6;
	unsigned short is_ssl;
	unsigned short allow_http11;
	unsigned short etag_use_inode;
	unsigned short etag_use_mtime;
	unsigned short etag_use_size;
	unsigned short force_lowercase_filenames; /* if the FS is case-insensitive, force all files to lower-case */
	unsigned short max_request_size;

	unsigned short kbytes_per_second; /* connection kb/s limit */

	/* configside */
	unsigned short global_kbytes_per_second; /*  */

	off_t  global_bytes_per_second_cnt;
	/* server-wide traffic-shaper
	 *
	 * each context has the counter which is inited once
	 * a second by the global_kbytes_per_second config-var
	 *
	 * as soon as global_kbytes_per_second gets below 0
	 * the connected conns are "offline" a little bit
	 *
	 * the problem:
	 * we somehow have to loose our "we are writable" signal
	 * on the way.
	 *
	 */
	off_t *global_bytes_per_second_cnt_ptr; /*  */

#ifdef USE_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
} specific_config;





























/* the order of the items should be the same as they are processed
 * read before write as we use this later */
typedef enum {
	CON_STATE_CONNECT,
	CON_STATE_REQUEST_START,
	CON_STATE_READ,
	CON_STATE_REQUEST_END,
	CON_STATE_READ_POST,
	CON_STATE_HANDLE_REQUEST,
	CON_STATE_RESPONSE_START,
	CON_STATE_WRITE,
	CON_STATE_RESPONSE_END,
	CON_STATE_ERROR,
	CON_STATE_CLOSE
} connection_state_t;




























//缓存条件配置值的结构体定义
typedef enum { COND_RESULT_UNSET, COND_RESULT_FALSE, COND_RESULT_TRUE } cond_result_t;
typedef struct {
	cond_result_t result;
	int patterncount;
	int matches[3 * 10];
	buffer *comp_value; /* just a pointer */
	
	comp_key_t comp_type;
} cond_cache_t;



























//定义connection结构体
typedef struct {

//连接在某时刻的状态
	connection_state_t state;

	/* timestamps */
	time_t read_idle_ts;
	time_t close_timeout_ts;
	time_t write_request_ts;

//记录连接时的时间戳
	time_t connection_start;
	time_t request_start;

	struct timeval start_tv;

	size_t request_count;        /* number of requests handled in this connection */
	size_t loops_per_request;    /* to catch endless loops in a single request
				      *
				      * used by mod_rewrite, mod_fastcgi, ... and others
				      * this is self-protection
				      */

//记录已连接套接字的描述符
	int fd;        
//该描述符是否已添加到i/o复用中 
	int fde_ndx;               
//server结构体中connetions的位置
	int ndx;                    

	/* fd states */
	int is_readable;
	int is_writable;

	int     keep_alive;           /* only request.c can enable it, all other just disable */

	int file_started;
	int file_finished;

	chunkqueue *write_queue;      /* a large queue for low-level write ( HTTP response ) [ file, mem ] */
// 用于存储客户端发送过来的请求信息
	chunkqueue *read_queue;       /* a small queue for low-level read ( HTTP request ) [ mem ] */
//POST:存放请求信息的主体部分
	chunkqueue *request_content_queue; /* takes request-content into tempfile if necessary [ tempfile, mem ]*/

	int traffic_limit_reached;

	off_t bytes_written;          /* used by mod_accesslog, mod_rrd */
	off_t bytes_written_cur_second; /* used by mod_accesslog, mod_rrd */
//从客户端中读取的字节数
	off_t bytes_read;             /* used by mod_accesslog, mod_rrd */
	off_t bytes_header;

	int http_status;

//对端（即客户端）地址信息。
	sock_addr dst_addr;
//客户端IP地址信息
	buffer *dst_addr_buf;

	/* request */
//存放需要解释的请求信息
	buffer *parse_request;
	unsigned int parsed_response; /* bitfield which contains the important header-fields of the parsed response header */
//从read_queue链中获取完整的请求头域信息
	request  request;

	request_uri uri;
	physical physical;
	response response;

	size_t header_len;

	buffer *authed_user;
	array  *environment; /* used to pass lighttpd internal stuff to the FastCGI/CGI apps, setenv does that */

	/* response */
	int    got_response;

	int    in_joblist;

	connection_type mode;

//用于记录各个插件的连接环境信息
	void **plugin_ctx;          

	specific_config conf;        /* global connection specific config */
	cond_cache_t *cond_cache;

	buffer *server_name;

	/* error-handler */
	buffer *error_handler;
	int error_handler_saved_status;
	int in_error_handler;

//监听套接字描述符的信息
	void *srv_socket;  

#ifdef USE_OPENSSL
	SSL *ssl;
	buffer *ssl_error_want_reuse_buffer;
#endif
	/* etag handling */
	etag_flags_t etag_flags;

	int conditional_is_valid[COMP_LAST_ELEMENT]; 
} connection;

































typedef struct {
	connection **ptr;
	size_t size;
	size_t used;
} connections;




























#ifdef HAVE_IPV6
typedef struct {
	int family;
	union {
		struct in6_addr ipv6;
		struct in_addr  ipv4;
	} addr;
	char b2[INET6_ADDRSTRLEN + 1];
	time_t ts;
} inet_ntop_cache_type;
#endif

























typedef struct {
	buffer *uri;
	time_t mtime;
	int http_status;
} realpath_cache_type;





















typedef struct {
	time_t  mtime;  /* the key */
	buffer *str;    /* a buffer for the string represenation */
} mtime_cache_type;




















//用于记录各个插件
typedef struct {
	void  *ptr;
	size_t used;
	size_t size;
} buffer_plugin;

























typedef struct {
	unsigned short port;
	buffer *bindhost;

	buffer *errorlog_file;
	unsigned short errorlog_use_syslog;

	unsigned short dont_daemonize;
	buffer *changeroot;
	buffer *username;
	buffer *groupname;

	buffer *pid_file;

	buffer *event_handler;

	buffer *modules_dir;
//记录读写方式
	buffer *network_backend;
	
	array *modules;
	array *upload_tempdirs;

	unsigned short max_worker;
	unsigned short max_fds;
	unsigned short max_conns;
	unsigned short max_request_size;

	unsigned short log_request_header_on_error;
	unsigned short log_state_handling;

	enum { STAT_CACHE_ENGINE_UNSET,
			STAT_CACHE_ENGINE_NONE,
			STAT_CACHE_ENGINE_SIMPLE,
#ifdef HAVE_FAM_H
			STAT_CACHE_ENGINE_FAM
#endif
	} stat_cache_engine;
	unsigned short enable_cores;
} server_config;



























typedef struct {
	sock_addr addr;
	int       fd;
	int       fde_ndx;

	buffer *ssl_pemfile;
	buffer *ssl_ca_file;
	buffer *ssl_cipher_list;
	unsigned short ssl_use_sslv2;
	unsigned short use_ipv6;
	unsigned short is_ssl;

	buffer *srv_token;

#ifdef USE_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
       unsigned short is_proxy_ssl;
} server_socket;































typedef struct {
	server_socket **ptr;

	size_t size;
	size_t used;
} server_socket_array;


































typedef struct server {

//记录监听套接字描述符数组（可能含有多个基于IP/端口的虚拟主机Web站点监听套接口描述符）
	server_socket_array srv_sockets;

	/* the errorlog */
	int errorlog_fd;
	enum { ERRORLOG_STDERR, ERRORLOG_FILE, ERRORLOG_SYSLOG } errorlog_mode;
	buffer *errorlog_buf;

//记录i/o模型处理器
	fdevents *ev, *ev_ins;

//记录各种插件
	buffer_plugin plugins;
	void *plugin_slots;

//当前连接数目
	int con_opened;
	int con_read;
	int con_written;
	int con_closed;

	int ssl_is_init;

	int max_fds;    /* max possible fds */
//当前打开的文件描述符数目
	int cur_fds;    /* currently used fds */
	int want_fds;   /* waiting fds */
	int sockets_disabled;
//最大连接数
	size_t max_conns;

	/* buffers */
	buffer *parse_full_path;
	buffer *response_header;
	buffer *response_range;
	buffer *tmp_buf;

	buffer *tmp_chunk_len;

	buffer *empty_string; /* is necessary for cond_match */

	buffer *cond_check_buf;

	/* caches */
#ifdef HAVE_IPV6
	inet_ntop_cache_type inet_ntop_cache[INET_NTOP_CACHE_MAX];
#endif
	mtime_cache_type mtime_cache[FILE_CACHE_MAX];

	array *split_vals;

	/* Timestamps */
	time_t cur_ts;
	time_t last_generated_date_ts;
	time_t last_generated_debug_ts;
	time_t startup_ts;

	buffer *ts_debug_str;
	buffer *ts_date_str;

	/* config-file */
//指向config_context ->data[0],也就是global配置信息	
	array *config; 
//记录曾被Lighttpd使用过的配置信息key记录	
	array *config_touched; 
//Lighttpd配置文件解析后的上下文，包含配置文件里所有有用的信息
	array *config_context; 
//存储被Lighttpd使用过的配置信息	
	specific_config **config_storage; 
//和Lighttpd服务相关极近的基本全局配置信息，例如服务的IP地址、端口、I/O多路复用技术等。
	server_config  srvconf; 
//是否包含有被Lighttpd所摒弃的配置信息标记
	short int config_deprecated; 
//是否包含有不被Lighttpd所支持的配置信息标记	
	short int config_unsupported; 

//存放conntion结构体的数组
	connections *conns;
	connections *joblist;
	connections *fdwaitqueue;

// 记录文件状态缓冲器
	stat_cache  *stat_cache;

	array *status;

	fdevent_handler_t event_handler;

	int (* network_backend_write)(struct server *srv, connection *con, int fd, chunkqueue *cq);
	int (* network_backend_read)(struct server *srv, connection *con, int fd, chunkqueue *cq);
#ifdef USE_OPENSSL
	int (* network_ssl_backend_write)(struct server *srv, connection *con, SSL *ssl, chunkqueue *cq);
	int (* network_ssl_backend_read)(struct server *srv, connection *con, SSL *ssl, chunkqueue *cq);
#endif

	uid_t uid;
	gid_t gid;
} server;


#endif
