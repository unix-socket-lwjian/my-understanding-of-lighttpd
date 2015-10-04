#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "connections.h"
#include "plugin.h"
#include "joblist.h"

#include "network_backends.h"
#include "sys-mmap.h"
#include "sys-socket.h"

#ifdef USE_OPENSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
#endif











//处理监听套接字的可读（register时指定用该函数）
handler_t network_server_handle_fdevent(void *s, void *context, int revents) {
	server     *srv = (server *)s;
	server_socket *srv_socket = (server_socket *)context;
	connection *con;
	int loops = 0;
	UNUSED(context);
	/*
		首先要判断传入的event事件是否是FDEVENT_IN，也就是说，只可能在fd有可读数据的时候才触发该函数，其他的情况都错误。
	*/
	if (revents != FDEVENT_IN) {
		log_error_write(srv, __FILE__, __LINE__, "sdd",
				"strange event for server socket",
				srv_socket->fd,
				revents);
		return HANDLER_ERROR;
	}

	 /*
		接收客户端连接请求，每个监听套接口描述符一次接收请求数目最大为100，使得各监听套接口上的连接请求都得到及时处理。
	 */
//connection_accept()函数用来完成连接套接口描述符的创建		
	for (loops = 0; loops < 100 && NULL != (con=connection_accept(srv, srv_socket)); loops++) { 
		handler_t r;

//connection_state_machine()函数（连接状态转换管理器）和plugins_call_handle_joblist()函数用于对请求连接进行处理。
		connection_state_machine(srv, con); 
		switch(r = plugins_call_handle_joblist(srv, con)) {
		case HANDLER_FINISHED:
		case HANDLER_GO_ON:
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "d", r);
			break;
		}
	}
	return HANDLER_GO_ON;
}







































//创建监听套接字，该函数被network_init调用
int network_server_init(server *srv, buffer *host_token, specific_config *s) {
	int val;
	socklen_t addr_len;
	server_socket *srv_socket;
	char *sp;
	unsigned int port = 0;
	const char *host;
	buffer *b;

//判断是否为unix域套接字
	int is_unix_domain_socket = 0;

	int fd;

#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;
#endif

#ifdef __WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		    /* Tell the user that we could not find a usable */
		    /* WinSock DLL.                                  */
		    return -1;
	}
#endif
//为srv_socket分配内存空间并赋值
	srv_socket = calloc(1, sizeof(*srv_socket));
	srv_socket->fd = -1;
	srv_socket->srv_token = buffer_init();
	buffer_copy_string_buffer(srv_socket->srv_token, host_token);




/* ipv4:port
 * [ipv6]:port
 */
//分割IP与端口号
	b = buffer_init();
	buffer_copy_string_buffer(b, host_token);
	if (NULL == (sp = strrchr(b->ptr, ':'))) { 
		log_error_write(srv, __FILE__, __LINE__, "sb", "value of $SERVER[\"socket\"] has to be \"ip:port\".", b);

		return -1;
	}

//获取地址
	host = b->ptr;


//去除[ipv6]中的’［‘、’］‘号
	if (b->ptr[0] == '[' && *(sp-1) == ']') {
//去掉']'		
		*(sp-1) = '\0'; 
//去掉'['		
		host++;		
//该地址是ipv6
		srv_socket->use_ipv6 = 1;
	}


//去除‘：’号
	*(sp++) = '\0';


//获取port
	port = strtol(sp, NULL, 10); //字符转长整型数



//若其地址为’／‘开头的，则是unix域套接字的创建
	if (host[0] == '/') { 
	/*
		使用UNIX域协议，UNIX域协议关联一个以空字符结尾的路径名（此路径名必须是绝对路径名而不是一个相对路径名，所以字符串第一个字符应该为字符'/'），
		因此这里通过检测传递的地址字符串第一个字符是否为'/'字符来判断是否使用UNIX域协议。
		PS：UNIX域主要用来做同一域内的进程间通信，在处理一个进程和多个进程间通信执行类似于服务器/客户通信时，UNIX域是一种比较方便和快速的办法。
			它所使用的API与在不同的主机上执行服务器/客户所用的API（套接口API）完全相同，便于代码共享。UNIX域也提供了两类套接口：字节流套接口和数据
			报套接口。总的来说，在同一台主机上的多个进程之间通信，UNIX域有如下优点：（1）利用常规的SOCKET编写的TCP套接口
			快；（2）UNIX域套接口可以在不同进程之间传递描述字；（3）UNIX域套接口较新的实现把客户的凭证（用户ID和组ID）提供给服务器，从而能够
			提供额外的安全检查措施。
	*/
//该地址是路径名
		is_unix_domain_socket = 1;
	} 


//检查端口号是否正确
	else if (port == 0 || port > 65535) {
		log_error_write(srv, __FILE__, __LINE__, "sd", "port out of range:", port);

		return -1;
	}

//地址为空
	if (*host == '\0') host = NULL;



//创建使用UNIX域协议的套接口
	if (is_unix_domain_socket) { 
#ifdef HAVE_SYS_UN_H

		srv_socket->addr.plain.sa_family = AF_UNIX;
		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, 0))) { 
			return -1;
		}
#else
		log_error_write(srv, __FILE__, __LINE__, "s",
				"ERROR: Unix Domain sockets are not supported.");
		return -1;
#endif
	}





//创建使用IPv6协议的字节流套接口，使用TCP传输协议。
#ifdef HAVE_IPV6
	if (s->use_ipv6) { 
		srv_socket->addr.plain.sa_family = AF_INET6;

		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, IPPROTO_TCP))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			return -1;
		}
		srv_socket->use_ipv6 = 1;
	}
#endif



//未创建使用IPv6协议的字节流套接口或创建失败的情况下则创建使用IPv4协议的字节流套接口，使用TCP传输协议。
	if (srv_socket->fd == -1) { 
		srv_socket->addr.plain.sa_family = AF_INET;
		if (-1 == (srv_socket->fd = socket(srv_socket->addr.plain.sa_family, SOCK_STREAM, IPPROTO_TCP))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "socket failed:", strerror(errno));
			return -1;
		}
	}




//记录最近使用的套接字 
	srv->cur_fds = srv_socket->fd;

	



//设置套接口选项，SO_REUSEADDR套接口选项的作用就是允许重用本地地址。
	val = 1;
	if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) { 
		log_error_write(srv, __FILE__, __LINE__, "ss", "socketsockopt failed:", strerror(errno));
		return -1;
	}




//创建套接字地址结构体
	switch(srv_socket->addr.plain.sa_family) {
#ifdef HAVE_IPV6
	case AF_INET6:
		memset(&srv_socket->addr, 0, sizeof(struct sockaddr_in6));
		srv_socket->addr.ipv6.sin6_family = AF_INET6;
//未指定绑定地址则使用通配地址in6addr_any
		if (host == NULL) { 
			srv_socket->addr.ipv6.sin6_addr = in6addr_any;
		} 
//使用用户指定ip
		else {
			struct addrinfo hints, *res; 
			int r;

			memset(&hints, 0, sizeof(hints)); 

			hints.ai_family   = AF_INET6;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			if (0 != (r = getaddrinfo(host, NULL, &hints, &res))) { //函数getaddrinfo()是IPv6新引入的API，它是协议无关的，既可以用于IPv4也可以用于IPv6.该函数用于获得一个addrinfo结构体列表，该列表通过第四个参数隐性传出，调用执行成功返回0，否则返回非0值。
				log_error_write(srv, __FILE__, __LINE__,
						"sssss", "getaddrinfo failed: ",
						gai_strerror(r), "'", host, "'");

				return -1;
			}

			memcpy(&(srv_socket->addr), res->ai_addr, res->ai_addrlen);

			freeaddrinfo(res); 
		}
//port赋值
		srv_socket->addr.ipv6.sin6_port = htons(port);
		addr_len = sizeof(struct sockaddr_in6);
		break;
#endif
//ipv4
	case AF_INET:
		memset(&srv_socket->addr, 0, sizeof(struct sockaddr_in));
		srv_socket->addr.ipv4.sin_family = AF_INET;
		if (host == NULL) {
			srv_socket->addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY); //将主机字节顺序的无符号长整型数转换成网络字节顺序格式
		} else {
			struct hostent *he; //hostent结构体定义在/usr/include/netdb.h内
			if (NULL == (he = gethostbyname(host))) { //函数gethostbyname()返回对应于给定主机名的包含主机名字和地址等信息的hostent结构指针。
				log_error_write(srv, __FILE__, __LINE__,
						"sds", "gethostbyname failed: ",
						h_errno, host);
				return -1;
			}

			if (he->h_addrtype != AF_INET) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-type != AF_INET: ", he->h_addrtype);
				return -1;
			}

			if (he->h_length != sizeof(struct in_addr)) {
				log_error_write(srv, __FILE__, __LINE__, "sd", "addr-length != sizeof(in_addr): ", he->h_length);
				return -1;
			}

			memcpy(&(srv_socket->addr.ipv4.sin_addr.s_addr), he->h_addr_list[0], he->h_length);
		}
		srv_socket->addr.ipv4.sin_port = htons(port);

		addr_len = sizeof(struct sockaddr_in);

		break;
//unix域套接字
	case AF_UNIX:
		srv_socket->addr.un.sun_family = AF_UNIX;
		strcpy(srv_socket->addr.un.sun_path, host);

#ifdef SUN_LEN
		addr_len = SUN_LEN(&srv_socket->addr.un); //SUN_LEN宏定义在/usr/include/sys/un.h SUN_lEN(ptr) ((size_t)(((struct sockaddr_un *) 0)->sun_path) + strlen((ptr)->sun_path))
		//从定义内容可以看到，宏SUN_LEN 用于计算一个sockaddr_un结构体（通过ptr指针指向）的长度大小，这个长度并不是为该结构体分配的字节空间的长度，注意其中路径名sun_path字段仅计算其中的非空格字符在内。
#else
		/* stevens says: */
		addr_len = strlen(host) + 1 + sizeof(srv_socket->addr.un.sun_family);
#endif

		/* check if the socket exists and try to connect to it. */
		if (-1 != (fd = connect(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len))) { //检测一下是否可以连接上，正常情况下这里当然是失败的（因为套接字的端口和IP尚未被绑定），但是如果连接上了则说明有其他进程或服务在使用本套接口，因此报错退出。
			close(fd);

			log_error_write(srv, __FILE__, __LINE__, "ss",
				"server socket is still in use:",
				host);


			return -1;
		}

		/* connect failed */
		switch(errno) {
		case ECONNREFUSED: //虽然被服务器端拒绝属于正常情况，但是当监听套接口队列已满是也会设置ECONNREFUSED错误码。
			unlink(host); //删除先前某次运行生成的或已经存在的路径名
			break;
		case ENOENT: //路径名不存在，属于我们想要的正常情况
			break;
		default: //其他错误属于异常，报错返回
			log_error_write(srv, __FILE__, __LINE__, "sds",
				"testing socket failed:",
				host, strerror(errno));

			return -1;
		}

		break;
	default:
		addr_len = 0;

		return -1;
	}






//使用bind邦定ip和port
	if (0 != bind(srv_socket->fd, (struct sockaddr *) &(srv_socket->addr), addr_len)) { 
		switch(srv_socket->addr.plain.sa_family) {
		case AF_UNIX:
			log_error_write(srv, __FILE__, __LINE__, "sds",
					"can't bind to socket:",
					host, strerror(errno));
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssds",
					"can't bind to port:",
					host, port, strerror(errno));
			break;
		}
		return -1;
	}





//使用listen函数使其套接字变成监听套接字
	if (-1 == listen(srv_socket->fd, 128 * 8)) { 
		log_error_write(srv, __FILE__, __LINE__, "ss", "listen failed: ", strerror(errno));
		return -1;
	}










	if (s->is_ssl) {  //这里是对SSL的处理
#ifdef USE_OPENSSL
		if (srv->ssl_is_init == 0) {
			SSL_load_error_strings();
			SSL_library_init();
			srv->ssl_is_init = 1;

			if (0 == RAND_status()) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						"not enough entropy in the pool");
				return -1;
			}
		}

		if (NULL == (s->ssl_ctx = SSL_CTX_new(SSLv23_server_method()))) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
					ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}

		if (!s->ssl_use_sslv2) {
			/* disable SSLv2 */
			if (SSL_OP_NO_SSLv2 != SSL_CTX_set_options(s->ssl_ctx, SSL_OP_NO_SSLv2)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (!buffer_is_empty(s->ssl_cipher_list)) {
			/* Disable support for low encryption ciphers */
			if (SSL_CTX_set_cipher_list(s->ssl_ctx, s->ssl_cipher_list->ptr) != 1) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return -1;
			}
		}

		if (buffer_is_empty(s->ssl_pemfile)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "ssl.pemfile has to be set");
			return -1;
		}

		if (!buffer_is_empty(s->ssl_ca_file)) {
			if (1 != SSL_CTX_load_verify_locations(s->ssl_ctx, s->ssl_ca_file->ptr, NULL)) {
				log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
						ERR_error_string(ERR_get_error(), NULL), s->ssl_ca_file);
				return -1;
			}
		}

		if (SSL_CTX_use_certificate_file(s->ssl_ctx, s->ssl_pemfile->ptr, SSL_FILETYPE_PEM) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (SSL_CTX_use_PrivateKey_file (s->ssl_ctx, s->ssl_pemfile->ptr, SSL_FILETYPE_PEM) < 0) {
			log_error_write(srv, __FILE__, __LINE__, "ssb", "SSL:",
					ERR_error_string(ERR_get_error(), NULL), s->ssl_pemfile);
			return -1;
		}

		if (SSL_CTX_check_private_key(s->ssl_ctx) != 1) {
			log_error_write(srv, __FILE__, __LINE__, "sssb", "SSL:",
					"Private key does not match the certificate public key, reason:",
					ERR_error_string(ERR_get_error(), NULL),
					s->ssl_pemfile);
			return -1;
		}
		SSL_CTX_set_default_read_ahead(s->ssl_ctx, 1);
		SSL_CTX_set_mode(s->ssl_ctx, SSL_CTX_get_mode(s->ssl_ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		srv_socket->ssl_ctx = s->ssl_ctx;
#else

		buffer_free(srv_socket->srv_token);
		free(srv_socket);

		buffer_free(b);

		log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
				"ssl requested but openssl support is not compiled in");

		return -1;
#endif
	} 
else {
#ifdef SO_ACCEPTFILTER
		/*
			SO_ACCEPTFILTER是FreeBSD支持的一个选项SOL_SOCKET，称为“接收过滤器”(accept filter),其主要用来推迟函数accept()调用的返回，即只有当HTTP状态发生改变时（如一个HTTP请求到达），
			进程才从函数accept()阻塞中返回，因此延缓了对该连接进行处理的子进程需求，这样做的好处就是对于一定数量的子进程能处理更多的链接。另外由于accept()调用返回就表示有请求到达，
			所以使得子进程能迅速地完成请求响应，减少上下文切换。
		*/
		/*
		 * FreeBSD accf_http filter
		 *
		 */
		memset(&afa, 0, sizeof(afa));
		strcpy(afa.af_name, "httpready");
		if (setsockopt(srv_socket->fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
			if (errno != ENOENT) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "can't set accept-filter 'httpready': ", strerror(errno));
			}
		}
#endif
	}

	srv_socket->is_ssl = s->is_ssl;

	srv_socket->fde_ndx = -1;



/*记录已经创建了的监听套接口*/
	if (srv->srv_sockets.size == 0) {
		srv->srv_sockets.size = 4;
		srv->srv_sockets.used = 0;
		srv->srv_sockets.ptr = malloc(srv->srv_sockets.size * sizeof(server_socket));
	} else if (srv->srv_sockets.used == srv->srv_sockets.size) {
		srv->srv_sockets.size += 4;
		srv->srv_sockets.ptr = realloc(srv->srv_sockets.ptr, srv->srv_sockets.size * sizeof(server_socket));
	}
	srv->srv_sockets.ptr[srv->srv_sockets.used++] = srv_socket;
	buffer_free(b);

	return 0;
}

































int network_close(server *srv) {
	size_t i;
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];

		if (srv_socket->fd != -1) {
			/* check if server fd are already registered */
			if (srv_socket->fde_ndx != -1) {
				fdevent_event_del(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd);
				fdevent_unregister(srv->ev, srv_socket->fd);
			}

			close(srv_socket->fd);
		}

		buffer_free(srv_socket->srv_token);

		free(srv_socket);
	}

	free(srv->srv_sockets.ptr);

	return 0;
}

typedef enum {
	NETWORK_BACKEND_UNSET,
	NETWORK_BACKEND_WRITE,
	NETWORK_BACKEND_WRITEV,
	NETWORK_BACKEND_LINUX_SENDFILE,
	NETWORK_BACKEND_FREEBSD_SENDFILE,
	NETWORK_BACKEND_SOLARIS_SENDFILEV
} network_backend_t;





































//获取那些创建监听套接字必须的用户配置信息，并调用network_server_init函数创建监听套接字描述符
int network_init(server *srv) {
	buffer *b;
	size_t i;


//记录采用的读写方式
	network_backend_t backend; 
	


	//类似于之前讲过得I/O 复用技术的选择，这里Lighttpd也按照所谓的优劣次序选择服务器向客户端 发送 数据的方式。
	//这些方式包括有所谓的“零拷贝”方式（这是目前性能最优的网络数据传递方式）、散布读/聚集写方式以及一般的读写方式。
	struct nb_map {
		network_backend_t nb;
		const char *name;
	} network_backends[] = {
		/* lowest id wins */
#if defined USE_LINUX_SENDFILE
		{ NETWORK_BACKEND_LINUX_SENDFILE,       "linux-sendfile" },
#endif
#if defined USE_FREEBSD_SENDFILE
		{ NETWORK_BACKEND_FREEBSD_SENDFILE,     "freebsd-sendfile" },
#endif
#if defined USE_SOLARIS_SENDFILEV
		{ NETWORK_BACKEND_SOLARIS_SENDFILEV,	"solaris-sendfilev" },
#endif
#if defined USE_WRITEV
		{ NETWORK_BACKEND_WRITEV,		"writev" },
#endif
		{ NETWORK_BACKEND_WRITE,		"write" },
		{ NETWORK_BACKEND_UNSET,        	NULL }
	};

	


//#part1
	//创建主Web站点的监听套接口描述符，绑定的IP地址由配置server.bind指定，端口又配置项server.port指定。
	//如果用户未指定配置项，server.bind则自动绑定到通配地址INADDR_ANY，而配置项server.port未指定则默认为HTTP常规端口80。
	b = buffer_init();
//从用户配置信息中获取用于创建监听套接字的ip和port
	buffer_copy_string_buffer(b, srv->srvconf.bindhost);
	buffer_append_string_len(b, CONST_STR_LEN(":"));
	buffer_append_long(b, srv->srvconf.port);

//调用函数network_server_init()实际创建监听套接口描述符。
	if (0 != network_server_init(srv, b, srv->config_storage[0])) { 
		return -1;
	}
	buffer_free(b);



//#part1
#ifdef USE_OPENSSL
	srv->network_ssl_backend_write = network_write_chunkqueue_openssl;
#endif

//默认选择系统支持的最好的数据读写方式
	backend = network_backends[0].nb; 

//用户实际选择数据读写方式
	if (!buffer_is_empty(srv->srvconf.network_backend)) { 
		for (i = 0; network_backends[i].name; i++) {
			/**/
			if (buffer_is_equal_string(srv->srvconf.network_backend, network_backends[i].name, strlen(network_backends[i].name))) {
				backend = network_backends[i].nb;
				break;
			}
		}
//用户选择了一个无效的读写方式，则记录错误，并程序退出	
		if (NULL == network_backends[i].name) { 
			/* we don't know it */

			log_error_write(srv, __FILE__, __LINE__, "sb",
					"server.network-backend has a unknown value:",
					srv->srvconf.network_backend);

			return -1;
		}
	}



//根据最终选择的数据读写方式来发送数据，关联回调函数
	switch(backend) {  
	case NETWORK_BACKEND_WRITE:
		srv->network_backend_write = network_write_chunkqueue_write;
		break;
#ifdef USE_WRITEV
	case NETWORK_BACKEND_WRITEV:
		srv->network_backend_write = network_write_chunkqueue_writev;
		break;
#endif
#ifdef USE_LINUX_SENDFILE
	case NETWORK_BACKEND_LINUX_SENDFILE:
		srv->network_backend_write = network_write_chunkqueue_linuxsendfile;
		break;
#endif
#ifdef USE_FREEBSD_SENDFILE
	case NETWORK_BACKEND_FREEBSD_SENDFILE:
		srv->network_backend_write = network_write_chunkqueue_freebsdsendfile;
		break;
#endif
#ifdef USE_SOLARIS_SENDFILEV
	case NETWORK_BACKEND_SOLARIS_SENDFILEV:
		srv->network_backend_write = network_write_chunkqueue_solarissendfilev;
		break;
#endif
	default:
		return -1;
	}



	// 创建基于IP/端口的虚拟主机Web站点监听套接口描述符。
	/* check for $SERVER["socket"] */
	/*
		配置正确格式如下：
		$SERVER["socket"] == "127.0.0.1:3001" {...}
		0下标元素保存到的是基本全局配置信息，因此从索引1开始。
	*/
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		specific_config *s = srv->config_storage[i];
		size_t j;

		/* not our stage */ //不是虚拟主机配置项
		if (COMP_SERVER_SOCKET != dc->comp) continue;

		if (dc->cond != CONFIG_COND_EQ) { //对于虚拟主机配置项只运行相等比较
			log_error_write(srv, __FILE__, __LINE__, "s", "only == is allowed for $SERVER[\"socket\"].");

			return -1;
		}

		/* check if we already know this socket,
		 * if yes, don't init it */
		 /*
			srv->srv_socket为server_socket_array结构体类型，相关结构体都定义在头文件base.h内；
			我们在下一个network_server_init()函数的分析中可以看到，所有已经被创建了监听套接口描述符的对应server_socket信息都会被记录在该字段内，
			因此此处通过和该字段内保存的记录做比较可以知道该server_socket信息对应的监听套接口是否已经被创建
		 */
		for (j = 0; j < srv->srv_sockets.used; j++) { 
			if (buffer_is_equal(srv->srv_sockets.ptr[j]->srv_token, dc->string)) {
				break;
			}
		}

		if (j == srv->srv_sockets.used) { //比较完所有项都未匹配则表示还没创建
			if (0 != network_server_init(srv, dc->string, s)) return -1;
		}
	}

	return 0;
}

































//将所有已创建的监听套接字描述符加入i／o复用中
int network_register_fdevents(server *srv) {
	size_t i;

//重置i/o模型处理器fdevents结构体
	if (-1 == fdevent_reset(srv->ev)) {
		return -1;
	}


	/* register fdevents after reset */
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];
//当此srv_socket->fd就绪时，调用network_server_handle_fdevent函数进行处理
		fdevent_register(srv->ev, srv_socket->fd, network_server_handle_fdevent, srv_socket);
		fdevent_event_add(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd, FDEVENT_IN);
	}
	return 0;
}

















//向客户端发送数据，被connection_handle_write函数调用
int network_write_chunkqueue(server *srv, connection *con, chunkqueue *cq) {
	int ret = -1;
	off_t written = 0;
#ifdef TCP_CORK
	int corked = 0;
#endif
	server_socket *srv_socket = con->srv_socket;

	//达到设定的最大数据传输率
	if (con->conf.global_kbytes_per_second &&
	    *(con->conf.global_bytes_per_second_cnt_ptr) > con->conf.global_kbytes_per_second * 1024) {
		con->traffic_limit_reached = 1;
		joblist_append(srv, con);

		return 1;
	}

	written = cq->bytes_out;

//设置套接字TCP_CORK选项
#ifdef TCP_CORK
	/* Linux: put a cork into the socket as we want to combine the write() calls
	 * but only if we really have multiple chunks
	 */
	if (cq->first && cq->first->next) {
		corked = 1;
		setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
	}
#endif

	//调用数据发送函数
	if (srv_socket->is_ssl) {
#ifdef USE_OPENSSL
		ret = srv->network_ssl_backend_write(srv, con, con->ssl, cq);
#endif
	} 
	else {
		//函数返回本次被发送完在cp链的chunk数目
		ret = srv->network_backend_write(srv, con, con->fd, cq);
	}

	//清理本次被发送完在cp链的chunk，并判断是否全部chunk都发送完来设置ret
	if (ret >= 0) {
		chunkqueue_remove_finished_chunks(cq);
		ret = chunkqueue_is_empty(cq) ? 0 : 1;
	}
	
//取消套接字TCP_CORK选项
#ifdef TCP_CORK
	if (corked) {
		corked = 0;
		setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof(corked));
	}
#endif

	written = cq->bytes_out - written;
	con->bytes_written += written;
	con->bytes_written_cur_second += written;

	*(con->conf.global_bytes_per_second_cnt_ptr) += written;

	if (con->conf.kbytes_per_second &&
	    (con->bytes_written_cur_second > con->conf.kbytes_per_second * 1024)) {
		/* we reached the traffic limit */

		con->traffic_limit_reached = 1;
		joblist_append(srv, con);
	}
	return ret;
}
