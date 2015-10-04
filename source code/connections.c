#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "buffer.h"
#include "server.h"
#include "log.h"
#include "connections.h"
#include "fdevent.h"

#include "request.h"
#include "response.h"
#include "network.h"
#include "http_chunk.h"
#include "stat_cache.h"
#include "joblist.h"

#include "plugin.h"

#include "inet_ntop_cache.h"

#ifdef USE_OPENSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

typedef struct {
	        PLUGIN_DATA;
} plugin_data;





static connection *connections_get_new_connection(server *srv) {
	connections *conns = srv->conns;
	size_t i;

	if (conns->size == 0) {
		conns->size = 128;
		conns->ptr = NULL;
		conns->ptr = malloc(sizeof(*conns->ptr) * conns->size);
		for (i = 0; i < conns->size; i++) {
			conns->ptr[i] = connection_init(srv);
		}
	} else if (conns->size == conns->used) {
		conns->size += 128;
		conns->ptr = realloc(conns->ptr, sizeof(*conns->ptr) * conns->size);

		for (i = conns->used; i < conns->size; i++) {
			conns->ptr[i] = connection_init(srv);
		}
	}

	connection_reset(srv, conns->ptr[conns->used]);
#if 0
	fprintf(stderr, "%s.%d: add: ", __FILE__, __LINE__);
	for (i = 0; i < conns->used + 1; i++) {
		fprintf(stderr, "%d ", conns->ptr[i]->fd);
	}
	fprintf(stderr, "\n");
#endif

	conns->ptr[conns->used]->ndx = conns->used;
	return conns->ptr[conns->used++];
}

static int connection_del(server *srv, connection *con) {
	size_t i;
	connections *conns = srv->conns;
	connection *temp;

	if (con == NULL) return -1;

	if (-1 == con->ndx) return -1;

	i = con->ndx;

	/* not last element */

	if (i != conns->used - 1) {
		temp = conns->ptr[i];
		conns->ptr[i] = conns->ptr[conns->used - 1];
		conns->ptr[conns->used - 1] = temp;

		conns->ptr[i]->ndx = i;
		conns->ptr[conns->used - 1]->ndx = -1;
	}

	conns->used--;

	con->ndx = -1;
#if 0
	fprintf(stderr, "%s.%d: del: (%d)", __FILE__, __LINE__, conns->used);
	for (i = 0; i < conns->used; i++) {
		fprintf(stderr, "%d ", conns->ptr[i]->fd);
	}
	fprintf(stderr, "\n");
#endif
	return 0;
}

int connection_close(server *srv, connection *con) {
#ifdef USE_OPENSSL
	server_socket *srv_sock = con->srv_socket;
#endif

#ifdef USE_OPENSSL
	if (srv_sock->is_ssl) {
		if (con->ssl) SSL_free(con->ssl);
		con->ssl = NULL;
	}
#endif

	fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
	fdevent_unregister(srv->ev, con->fd);
#ifdef __WIN32
	if (closesocket(con->fd)) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"(warning) close:", con->fd, strerror(errno));
	}
#else
	if (close(con->fd)) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"(warning) close:", con->fd, strerror(errno));
	}
#endif

	srv->cur_fds--;
#if 0
	log_error_write(srv, __FILE__, __LINE__, "sd",
			"closed()", con->fd);
#endif

	connection_del(srv, con);
	connection_set_state(srv, con, CON_STATE_CONNECT);

	return 0;
}

#if 0
static void dump_packet(const unsigned char *data, size_t len) {
	size_t i, j;

	if (len == 0) return;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) fprintf(stderr, "  ");

		fprintf(stderr, "%02x ", data[i]);

		if ((i + 1) % 16 == 0) {
			fprintf(stderr, "  ");
			for (j = 0; j <= i % 16; j++) {
				unsigned char c;

				if (i-15+j >= len) break;

				c = data[i-15+j];

				fprintf(stderr, "%c", c > 32 && c < 128 ? c : '.');
			}

			fprintf(stderr, "\n");
		}
	}

	if (len % 16 != 0) {
		for (j = i % 16; j < 16; j++) {
			fprintf(stderr, "   ");
		}

		fprintf(stderr, "  ");
		for (j = i & ~0xf; j < len; j++) {
			unsigned char c;

			c = data[j];
			fprintf(stderr, "%c", c > 32 && c < 128 ? c : '.');
		}
		fprintf(stderr, "\n");
	}
}
#endif

static int connection_handle_read_ssl(server *srv, connection *con) {
#ifdef USE_OPENSSL
	int r, ssl_err, len;
	buffer *b = NULL;

	if (!con->conf.is_ssl) return -1;

	/* don't resize the buffer if we were in SSL_ERROR_WANT_* */

	ERR_clear_error();
	do {
		if (!con->ssl_error_want_reuse_buffer) {
			b = buffer_init();
			buffer_prepare_copy(b, SSL_pending(con->ssl) + (16 * 1024)); /* the pending bytes + 16kb */

			/* overwrite everything with 0 */
			memset(b->ptr, 0, b->size);
		} else {
			b = con->ssl_error_want_reuse_buffer;
		}

		len = SSL_read(con->ssl, b->ptr, b->size - 1);
		con->ssl_error_want_reuse_buffer = NULL; /* reuse it only once */

		if (len > 0) {
			b->used = len;
			b->ptr[b->used++] = '\0';

		       	/* we move the buffer to the chunk-queue, no need to free it */

			chunkqueue_append_buffer_weak(con->read_queue, b);
			con->bytes_read += len;
			b = NULL;
		}
	} while (len > 0);


	if (len < 0) {
		switch ((r = SSL_get_error(con->ssl, len))) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			con->is_readable = 0;
			con->ssl_error_want_reuse_buffer = b;

			b = NULL;

			/* we have to steal the buffer from the queue-queue */
			return 0;
		case SSL_ERROR_SYSCALL:
			/**
			 * man SSL_get_error()
			 *
			 * SSL_ERROR_SYSCALL
			 *   Some I/O error occurred.  The OpenSSL error queue may contain more
			 *   information on the error.  If the error queue is empty (i.e.
			 *   ERR_get_error() returns 0), ret can be used to find out more about
			 *   the error: If ret == 0, an EOF was observed that violates the
			 *   protocol.  If ret == -1, the underlying BIO reported an I/O error
			 *   (for socket I/O on Unix systems, consult errno for details).
			 *
			 */
			while((ssl_err = ERR_get_error())) {
				/* get all errors from the error-queue */
				log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
						r, ERR_error_string(ssl_err, NULL));
			}

			switch(errno) {
			default:
				log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL:",
						len, r, errno,
						strerror(errno));
				break;
			}

			break;
		case SSL_ERROR_ZERO_RETURN:
			/* clean shutdown on the remote side */

			if (r == 0) {
				/* FIXME: later */
			}

			/* fall thourgh */
		default:
			while((ssl_err = ERR_get_error())) {
				switch (ERR_GET_REASON(ssl_err)) {
				case SSL_R_SSL_HANDSHAKE_FAILURE:
				case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
				case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
				case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
					if (!con->conf.log_ssl_noise) continue;
					break;
				default:
					break;
				}
				/* get all errors from the error-queue */
				log_error_write(srv, __FILE__, __LINE__, "sds", "SSL:",
				                r, ERR_error_string(ssl_err, NULL));
			}
			break;
		}

		connection_set_state(srv, con, CON_STATE_ERROR);

		buffer_free(b);

		return -1;
	} else if (len == 0) {
		con->is_readable = 0;
		/* the other end close the connection -> KEEP-ALIVE */

		/* pipelining */
		buffer_free(b);

		return -2;
	}

	return 0;
#else
	UNUSED(srv);
	UNUSED(con);
	return -1;
#endif
}
















































//读取客户端发送过来的请求信息，该函数由connection_handle_read_state调用
static int connection_handle_read(server *srv, connection *con) {
	int len;
	buffer *b;
	int toread; 

//SSL情况调用特定SSL读取函数
	if (con->conf.is_ssl) { 
		return connection_handle_read_ssl(srv, con);
	}

#if defined(__WIN32)
	b = chunkqueue_get_append_buffer(con->read_queue);
	buffer_prepare_copy(b, 4 * 1024);
	len = recv(con->fd, b->ptr, b->size - 1, 0);
#else

	/*利用FIONREAD获取当前socket套接口描述符内可读的字节数目*/
	if (ioctl(con->fd, FIONREAD, &toread)) {
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"unexpected end-of-file:",
				con->fd);
		return -1;
	}

//获取一个mem类型的chunk并添加到con->read_queue尾部，返回用于保存数据的buffer结构体字段	
	b = chunkqueue_get_append_buffer(con->read_queue); 

//为该buffer结构体字段分配数据存储空间，大小为可读数据字节长度+1，	
	buffer_prepare_copy(b, toread + 1); 

//接着调用系统函数read()读取数据
	len = read(con->fd, b->ptr, b->size - 1);
#endif

//读取出错
	if (len < 0) { 
 //将读取状态设置为不可读		
		con->is_readable = 0;

		if (errno == EAGAIN) return 0;
//read()被信号中断，则说明应该是有数据可读，因此将读取状态仍设置为可读
		if (errno == EINTR) {
			con->is_readable = 1;
			return 0;
		}
		/*
			这种情况下的ECONNRESET表示与客户端的连接被出乎意料的断开，如客户端浏览器在发送请求数据时异常崩溃、网络中断等导致服务器与客户端之间的连接被强行断开。
			如果不是ECONNRESET则表示read()出错，记录日志
		*/
		if (errno != ECONNRESET) {
			/* expected for keep-alive */
			log_error_write(srv, __FILE__, __LINE__, "ssd", "connection closed - read failed: ", strerror(errno), errno);
		}

		connection_set_state(srv, con, CON_STATE_ERROR);

		return -1;
	} 
//客户端关闭连接
	else if (len == 0) { 
		con->is_readable = 0;

		return -2;
	} 
//读取数据量比预期少，等待下一次fd事件，将fd加入i/o复用中
	else if ((size_t)len < b->size - 1) { 

		con->is_readable = 0;
	}

	b->used = len;
	b->ptr[b->used++] = '\0';

	con->bytes_read += len;
#if 0
	dump_packet(b->ptr, len);
#endif

	return 0;
}





























static int connection_handle_write_prepare(server *srv, connection *con) {
	if (con->mode == DIRECT) {
		/* static files */
		switch(con->request.http_method) {
		case HTTP_METHOD_GET:
		case HTTP_METHOD_POST:
		case HTTP_METHOD_HEAD:
		case HTTP_METHOD_PUT:
		case HTTP_METHOD_MKCOL:
		case HTTP_METHOD_DELETE:
		case HTTP_METHOD_COPY:
		case HTTP_METHOD_MOVE:
		case HTTP_METHOD_PROPFIND:
		case HTTP_METHOD_PROPPATCH:
		case HTTP_METHOD_LOCK:
		case HTTP_METHOD_UNLOCK:
			break;
		//准备options请求的响应信息
		case HTTP_METHOD_OPTIONS:
	
			if ((!con->http_status || con->http_status == 200) && con->uri.path->used &&
			    con->uri.path->ptr[0] != '*') {
				//加入首部字段	Allow:OPTIONS,GET,HEAD,POST
				response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));
				//因为options响应没有主体部分，所以不用主体传输编码
				con->response.transfer_encoding &= ~HTTP_TRANSFER_ENCODING_CHUNKED;
				con->parsed_response &= ~HTTP_CONTENT_LENGTH;

				con->http_status = 200;
				con->file_finished = 1;

				chunkqueue_reset(con->write_queue);
			}
			break;
		default:
			switch(con->http_status) {
			case 400: /* bad request */
			case 414: /* overload request header */
			case 505: /* unknown protocol */
			case 207: /* this was webdav */
				break;
			//其他方法统一设状态码为501（未实现）
			default:
				con->http_status = 501;
				break;
			}
			break;
		}
	}


	//若之前的请求没有被内部处理，则设状态码为403（禁止访问）
	if (con->http_status == 0) {
		con->http_status = 403;
	}


	switch(con->http_status) {
	//对于204，205，304的响应都是只有响应头域而没有消息主体，因此禁止用主体传输编码
	case 204: 
	case 205:
	case 304:
		con->response.transfer_encoding &= ~HTTP_TRANSFER_ENCODING_CHUNKED;
		con->parsed_response &= ~HTTP_CONTENT_LENGTH;
		chunkqueue_reset(con->write_queue);
		con->file_finished = 1;
		break;
	//其他响应码的响应消息有头域和主体
	default: 
		//若是被其他模块处理，则跳出
		if (con->mode != DIRECT) break;

		//仅对状态码为4xx和5xx的响应进行自组建响应状态码内容
		if (con->http_status < 400 || con->http_status >= 600) break;
		con->file_finished = 0;

		buffer_reset(con->physical.path);

		//尝试发送错误静态页面
		if (!buffer_is_empty(con->conf.errorfile_prefix)) {
			//自定义错误页面
			stat_cache_entry *sce = NULL;

			buffer_copy_string_buffer(con->physical.path, con->conf.errorfile_prefix);
			buffer_append_long(con->physical.path, con->http_status);
			buffer_append_string_len(con->physical.path, CONST_STR_LEN(".html"));

			if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
				//自定义错误页面存在
				con->file_finished = 1;
				//自定义错误页面加入发送链
				http_chunk_append_file(srv, con, con->physical.path, 0, sce->st.st_size);
				//重写响应头域
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(sce->content_type));
			}
		}
		//自组织错误页面内容
		if (!con->file_finished) {
			buffer *b;

			buffer_reset(con->physical.path);

			con->file_finished = 1;
			b = chunkqueue_get_append_buffer(con->write_queue);

			/* build default error-page */
			buffer_copy_string_len(b, CONST_STR_LEN(
					   "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
					   "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
					   "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
					   "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
					   " <head>\n"
					   "  <title>"));
			buffer_append_long(b, con->http_status);
			buffer_append_string_len(b, CONST_STR_LEN(" - "));
			buffer_append_string(b, get_http_status_name(con->http_status));

			buffer_append_string_len(b, CONST_STR_LEN(
					     "</title>\n"
					     " </head>\n"
					     " <body>\n"
					     "  <h1>"));
			buffer_append_long(b, con->http_status);
			buffer_append_string_len(b, CONST_STR_LEN(" - "));
			buffer_append_string(b, get_http_status_name(con->http_status));

			buffer_append_string_len(b, CONST_STR_LEN("</h1>\n"
					     " </body>\n"
					     "</html>\n"
					     ));
			//重写响应头域
			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN("text/html"));
		}
		break;
	}


	//响应资源已准备好
	if (con->file_finished) {
		//发送消息有消息主体并且消息主体未进行块传输编码
		if ((!(con->parsed_response & HTTP_CONTENT_LENGTH)) &&
		    (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) == 0) {
			off_t qlen = chunkqueue_length(con->write_queue);

			//下面条件的状态码响应不含消息主体，所以去掉Content-Length头域
			if ((con->http_status >= 100 && con->http_status < 200) ||
			    con->http_status == 204 ||
			    con->http_status == 304) {
				data_string *ds;
				if (NULL != (ds = (data_string*) array_get_element(con->response.headers, "Content-Length"))) {
					buffer_reset(ds->value); /* Headers with empty values are ignored for output */
				}
			} 
			//有消息主体且不是head请求，添加Content-Length头域
			else if (qlen > 0 || con->request.http_method != HTTP_METHOD_HEAD) {
				buffer_copy_off_t(srv->tmp_buf, qlen);
				response_header_overwrite(srv, con, CONST_STR_LEN("Content-Length"), CONST_BUF_LEN(srv->tmp_buf));
			}
		}
	} 

	//响应资源没准备好
	else {
		/**
		 * the file isn't finished yet, but we have all headers
		 *
		 * to get keep-alive we either need:
		 * - Content-Length: ... (HTTP/1.0 and HTTP/1.0) or
		 * - Transfer-Encoding: chunked (HTTP/1.1)
		 */

		if (((con->parsed_response & HTTP_CONTENT_LENGTH) == 0) &&
		    ((con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) == 0)) {
			con->keep_alive = 0;
		}

		/**
		 * if the backend sent a Connection: close, follow the wish
		 *
		 * NOTE: if the backend sent Connection: Keep-Alive, but no Content-Length, we
		 * will close the connection. That's fine. We can always decide the close 
		 * the connection
		 *
		 * FIXME: to be nice we should remove the Connection: ... 
		 */
		if (con->parsed_response & HTTP_CONNECTION) {
			/* a subrequest disable keep-alive although the client wanted it */
			if (con->keep_alive && !con->response.keep_alive) {
				con->keep_alive = 0;
			}
		}
	}
	//head请求不响应消息主体
	if (con->request.http_method == HTTP_METHOD_HEAD) {

		con->file_finished = 1;

		chunkqueue_reset(con->write_queue);
		con->response.transfer_encoding &= ~HTTP_TRANSFER_ENCODING_CHUNKED;
	}
//get和post的响应是一致的，都有消息主体
	http_response_write_header(srv, con);

	return 0;
}




























//向客户端发送数据
static int connection_handle_write(server *srv, connection *con) {
	//Lighttpd实际实际是调用network_write_chunkqueue发送数据
	switch(network_write_chunkqueue(srv, con, con->write_queue)) {
	case 0:
		//全部数据发送完毕
		if (con->file_finished) {
			//转换状态为CON_STATE_RESPONSE_END：发送响应结束
			connection_set_state(srv, con, CON_STATE_RESPONSE_END);
			joblist_append(srv, con);
		}
		break;
	//执行失败，服务器端出错
	case -1: 
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"connection closed: write failed on fd", con->fd);
		connection_set_state(srv, con, CON_STATE_ERROR);
		joblist_append(srv, con);
		break;
	//执行失败，客户端关闭连接
	case -2: 
		connection_set_state(srv, con, CON_STATE_ERROR);
		joblist_append(srv, con);
		break;
	//执行成功，但数据没有完全发送出去
	case 1:
		con->is_writable = 0;

		/* not finished yet -> WRITE */
		break;
	}

	return 0;
}























//初始化connection结构体
connection *connection_init(server *srv) {
	connection *con;

	UNUSED(srv);

	con = calloc(1, sizeof(*con));

	con->fd = 0;
	con->ndx = -1;
	con->fde_ndx = -1;
	con->bytes_written = 0;
	con->bytes_read = 0;
	con->bytes_header = 0;
	con->loops_per_request = 0;

#define CLEAN(x) \
	con->x = buffer_init();

	CLEAN(request.uri);
	CLEAN(request.request_line);
	CLEAN(request.request);
	CLEAN(request.pathinfo);

	CLEAN(request.orig_uri);

	CLEAN(uri.scheme);
	CLEAN(uri.authority);
	CLEAN(uri.path);
	CLEAN(uri.path_raw);
	CLEAN(uri.query);

	CLEAN(physical.doc_root);
	CLEAN(physical.path);
	CLEAN(physical.basedir);
	CLEAN(physical.rel_path);
	CLEAN(physical.etag);
	CLEAN(parse_request);

	CLEAN(authed_user);
	CLEAN(server_name);
	CLEAN(error_handler);
	CLEAN(dst_addr_buf);

#undef CLEAN
	con->write_queue = chunkqueue_init();
	con->read_queue = chunkqueue_init();
	con->request_content_queue = chunkqueue_init();
	chunkqueue_set_tempdirs(con->request_content_queue, srv->srvconf.upload_tempdirs);

	con->request.headers      = array_init();
	con->response.headers     = array_init();
	con->environment     = array_init();

	/* init plugin specific connection structures */

	con->plugin_ctx = calloc(1, (srv->plugins.used + 1) * sizeof(void *));

	con->cond_cache = calloc(srv->config_context->used, sizeof(cond_cache_t)); 
	config_setup_connection(srv, con); //获取固定的全局配置值

	return con;
}

























//connection结构体释放
void connections_free(server *srv) {
	connections *conns = srv->conns;
	size_t i;

	for (i = 0; i < conns->size; i++) {
		connection *con = conns->ptr[i];

		connection_reset(srv, con);

		chunkqueue_free(con->write_queue);
		chunkqueue_free(con->read_queue);
		chunkqueue_free(con->request_content_queue);
		array_free(con->request.headers);
		array_free(con->response.headers);
		array_free(con->environment);

#define CLEAN(x) \
	buffer_free(con->x);

		CLEAN(request.uri);
		CLEAN(request.request_line);
		CLEAN(request.request);
		CLEAN(request.pathinfo);

		CLEAN(request.orig_uri);

		CLEAN(uri.scheme);
		CLEAN(uri.authority);
		CLEAN(uri.path);
		CLEAN(uri.path_raw);
		CLEAN(uri.query);

		CLEAN(physical.doc_root);
		CLEAN(physical.path);
		CLEAN(physical.basedir);
		CLEAN(physical.etag);
		CLEAN(physical.rel_path);
		CLEAN(parse_request);

		CLEAN(authed_user);
		CLEAN(server_name);
		CLEAN(error_handler);
		CLEAN(dst_addr_buf);
#undef CLEAN
		free(con->plugin_ctx);
		free(con->cond_cache);

		free(con);
	}

	free(conns->ptr);
}



























//重设connection结构体
int connection_reset(server *srv, connection *con) {
	size_t i;

	plugins_call_connection_reset(srv, con);

	con->is_readable = 1;
	con->is_writable = 1;
	con->http_status = 0;
	con->file_finished = 0;
	con->file_started = 0;
	con->got_response = 0;

	con->parsed_response = 0;

	con->bytes_written = 0;
	con->bytes_written_cur_second = 0;
	con->bytes_read = 0;
	con->bytes_header = 0;
	con->loops_per_request = 0;

	con->request.http_method = HTTP_METHOD_UNSET;
	con->request.http_version = HTTP_VERSION_UNSET;

	con->request.http_if_modified_since = NULL;
	con->request.http_if_none_match = NULL;

	con->response.keep_alive = 0;
	con->response.content_length = -1;
	con->response.transfer_encoding = 0;

	con->mode = DIRECT;

#define CLEAN(x) \
	if (con->x) buffer_reset(con->x);

	CLEAN(request.uri);
	CLEAN(request.request_line);
	CLEAN(request.pathinfo);
	CLEAN(request.request);

	CLEAN(request.orig_uri);

	CLEAN(uri.scheme);
	CLEAN(uri.authority);
	CLEAN(uri.path);
	CLEAN(uri.path_raw);
	CLEAN(uri.query);

	CLEAN(physical.doc_root);
	CLEAN(physical.path);
	CLEAN(physical.basedir);
	CLEAN(physical.rel_path);
	CLEAN(physical.etag);

	CLEAN(parse_request);

	CLEAN(authed_user);
	CLEAN(server_name);
	CLEAN(error_handler);
#undef CLEAN

#define CLEAN(x) \
	if (con->x) con->x->used = 0;

#undef CLEAN

#define CLEAN(x) \
		con->request.x = NULL;

	CLEAN(http_host);
	CLEAN(http_range);
	CLEAN(http_content_type);
#undef CLEAN
	con->request.content_length = 0;

	array_reset(con->request.headers);
	array_reset(con->response.headers);
	array_reset(con->environment);

	chunkqueue_reset(con->write_queue);
	chunkqueue_reset(con->request_content_queue);

	/* the plugins should cleanup themself */
	for (i = 0; i < srv->plugins.used; i++) {
		plugin *p = ((plugin **)(srv->plugins.ptr))[i];
		plugin_data *pd = p->data;

		if (!pd) continue;

		if (con->plugin_ctx[pd->id] != NULL) {
			log_error_write(srv, __FILE__, __LINE__, "sb", "missing cleanup in", p->name);
		}

		con->plugin_ctx[pd->id] = NULL;
	}

	/* The cond_cache gets reset in response.c */
	/* config_cond_cache_reset(srv, con); */

#ifdef USE_OPENSSL
	if (con->ssl_error_want_reuse_buffer) {
		buffer_free(con->ssl_error_want_reuse_buffer);
		con->ssl_error_want_reuse_buffer = NULL;
	}
#endif

	con->header_len = 0;
	con->in_error_handler = 0;

	config_setup_connection(srv, con);

	return 0;
}













































//读取客户端发送过来的请求信息
int connection_handle_read_state(server *srv, connection *con)  {
	connection_state_t ostate = con->state;
	chunk *c, *last_chunk;
	off_t last_offset;

	chunkqueue *cq = con->read_queue;
	chunkqueue *dst_cq = con->request_content_queue;
	int is_closed = 0; 


//如果有数据可读，则调用函数connection_handle_read()读取客户端请求数据
	if (con->is_readable) { 
		con->read_idle_ts = srv->cur_ts;
//函数connection_handle_read()读取客户端请求数据
		switch(connection_handle_read(srv, con)) {
		case -1:
			return -1;
		case -2:
			is_closed = 1;
			break;
		default:
			break;
		}
	}

	/*
		阅读函数connection_handle_read()源码知道，该函数会向con->read_queue链末尾新添加一个chunk块，然后从socket套接口描述符内
		读取数据存储到该新增chunk块内，但是也有可能没有读到数据而导致该新增chunk块为空闲块，因此这里整理操作，将没有被使用(即c->mem->used==0)
		的chunk块都归入到unused chunk链中。
	*/
	for (c = cq->first; c;) {
//第一块为空，则移到未使用链		
		if (cq->first == c && c->mem->used == 0) { 

			cq->first = c->next;
			if (cq->first == NULL) cq->last = NULL;

			c->next = cq->unused;
			cq->unused = c;
			cq->unused_chunks++;

			c = cq->first;
		} 
//下一块为空，移动到未使用链
		else if (c->next && c->next->mem->used == 0) { 
			chunk *fc;


			fc = c->next;
			c->next = fc->next;

			fc->next = cq->unused;
			cq->unused = fc;
			cq->unused_chunks++;

			/* the last node was empty */
			if (c->next == NULL) {
				cq->last = c;
			}

			c = c->next;
		} 
//判断下一个chunk
		else {
			c = c->next;
		}
	}



	switch(ostate) {
//从获取的请求信息中寻找请求HTTP请求头域数据		
	case CON_STATE_READ: 
		/*
			下面代码用于查找请求头域（起始行和首部）结束，即查找"\r\n\r\n"字符串。
		*/
		last_chunk = NULL;
		last_offset = 0;
		
		/*
			有可能客户端的请求头信息数据分多个包(packet)到达Lighttpd，此时状态CON_STATE_READ状态将持续多次，每次读取的数据存在con->read_queue链末尾新添加一个chunk块，
			因此此处循环处理每个chunk块。
		*/
		for (c = cq->first; !last_chunk && c; c = c->next) {
			buffer b;
			size_t i;

			b.ptr = c->mem->ptr + c->offset;
			b.used = c->mem->used - c->offset;


			//对每个接收到的请求数据字符逐个查找.							
			for (i = 0; !last_chunk && i < b.used; i++) {
				
				char ch = b.ptr[i];
				size_t have_chars = 0;

				switch (ch) {
				case '\r':
					/* we have to do a 4 char lookup */
				/*
					查找到字符'\r'并且该chunk块内待查找字符多于4个，则直接利用字符串比较函数strncmp()判断是否已经找到请求头域结束字符串"\r\n\r\n"，
					函数strncmp()的第三个参数为需要比较字符的个数。
				*/
					have_chars = b.used - i - 1;
					//带查找字符多于4个时
					if (have_chars >= 4) {
						// 判断是否找到请求头域结束字符串"\r\n\r\n
						if (0 == strncmp(b.ptr + i, "\r\n\r\n", 4)) {
							last_chunk = c;
							last_offset = i + 4;

							break;
						}
					
					} 
/*
						查找到字符'\r'但是该chunk块内待查找字符不足4个，这种情况下，我们待找的请求头域结束字符串"\r\n\r\n"有可能被分割存在了两个chunk块内，
						即前一个chunk块内保存字符串"\r\n\r\n"的前面几个字符，接着的后一个chunk块保存字符串"\r\n\r\n"的后面几个字符，因此需要进行分别比较。
*/	
					else {
						//后一个chunk块
						chunk *lookahead_chunk = c->next;
						size_t missing_chars;
						//可能保存后一个chunk块中的字符串"\r\n\r\n"内字符个数
						missing_chars = 4 - have_chars;
						//后一个chunk块存在并且类型正确的情况下执行
						if (lookahead_chunk && lookahead_chunk->type == MEM_CHUNK) { 
							//the chunk足够容纳剩下的字符
							if (lookahead_chunk->mem->used > missing_chars) { 
								//"\r\n\r\n" + have_chars的用法将得到"\r\n\r\n"+hava_chars为开始的后几位。
								if (0 == strncmp(b.ptr + i, "\r\n\r\n", have_chars) &&
								    0 == strncmp(lookahead_chunk->mem->ptr, "\r\n\r\n" + have_chars, missing_chars)) { 
									last_chunk = lookahead_chunk;
									last_offset = missing_chars;

									break;
								}
							} 

							else {

								break;
							}
						}
					}

					break;
				}
			}
		}


//只有找到了请求头域结束字符串"\r\n\r\n"时，变量last_chunk才会由初始值NULL赋值转换为指向某个chunk块。
		if (last_chunk) { 
//这里讲HTTP请求头数据从con->read_queue复制到con->request.request
			buffer_reset(con->request.request); 

			for (c = cq->first; c; c = c->next) {
				buffer b;
//确定复制数据的区域
				b.ptr = c->mem->ptr + c->offset; 
				b.used = c->mem->used - c->offset; 
//如果是最后一个chunk块，确保只复制到请求域结束字符串"\r\n\r\n"数据为止
				if (c == last_chunk) {
					b.used = last_offset + 1;
				}
//执行拷贝
				buffer_append_string_buffer(con->request.request, &b);
//复制请求头域数据结束标志块时，跳出
				if (c == last_chunk) {
					c->offset += last_offset;

					break; 
				}
				 else {
					/* the whole packet was copied */
					c->offset = c->mem->used - 1;
				}
			}
//CON_STATE_REQUEST_END：调用http_request_parse函数从获取的请求头域数据中解析客户端请求数据
			connection_set_state(srv, con, CON_STATE_REQUEST_END);
		}

//未找到请求头域数据的情况
//如果没有查找到"\r\n\r\n"并且缓冲区数据长度大于64*1024，也就是64KB，那么就返回414错误，也就是说，对于lighttpd而言，一般的HTTP请求不能超多64KB。切换连接状态为CON_HANDLE_REQUEST。
		else if (chunkqueue_length(cq) > 64 * 1024) {
			log_error_write(srv, __FILE__, __LINE__, "s", "oversized request-header -> sending Status 414");

			con->http_status = 414; /* Request-URI too large */
			con->keep_alive = 0;
			connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
		} 
//如果没有查找到"\r\n\r\n"并且缓冲区数据长度又没有超过64*1024，那么此时状态依旧是CON_STATE_READ，以便下一次继续读取请求数据到con->read_queue链中再进行处理。
		break;



//读取http请求主体数据
	case CON_STATE_READ_POST: 
//将存放已读取的头数据con->read_queue链中各chunk块内的数据逐个转存到con->request_content_queue链内，字段dst_cq->bytes_in内存储当前已经被转移的字节数。
		for (c = cq->first; c && (dst_cq->bytes_in != (off_t)con->request.content_length); c = c->next) { 
			off_t weWant, weHave, toRead;
			weWant = con->request.content_length - dst_cq->bytes_in;

			assert(c->mem->used);
			// con->read_queue链中当前被处理chunk块内包含的数据量	
			weHave = c->mem->used - c->offset - 1;
			//从该块内实际可以读取的数据量
			toRead = weHave > weWant ? weWant : weHave; 


//大量的POST数据时则需要读取到临时文件。
			if (con->request.content_length > 64 * 1024) { 
				chunk *dst_c = NULL;
		
				//直接利用最后一块，如果其满足这些条件
				if (dst_cq->last &&
				    dst_cq->last->type == FILE_CHUNK &&
				    dst_cq->last->file.is_temp &&
				    dst_cq->last->offset == 0) {
					
					//最后这块对应的文件大小未超过1MB，则可以继续添加数据
			 		if (dst_cq->last->file.length < 1 * 1024 * 1024) { 
						dst_c = dst_cq->last;

						if (dst_c->file.fd == -1) {
				
							dst_c->file.fd = open(dst_c->file.name->ptr, O_WRONLY | O_APPEND);
						}
					} 
					//最后这块对应的文件大小已经超过1MB，则重新建立一个文件类型的chunk块
					else { 
					
						dst_c = dst_cq->last;

						if (dst_c->file.fd != -1) {
							close(dst_c->file.fd);
							dst_c->file.fd = -1;
						}
						dst_c = chunkqueue_get_append_tempfile(dst_cq);
					}
				} 
				//直接获取一个新的文件类型chunk块
				else { 
					dst_c = chunkqueue_get_append_tempfile(dst_cq);
				}

				//文件出错
				if (dst_c->file.fd == -1) { 
		
					log_error_write(srv, __FILE__, __LINE__, "sbs",
							"denying upload as opening to temp-file for upload failed:",
							dst_c->file.name, strerror(errno));

					con->http_status = 413; 
					con->keep_alive = 0;
					connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);

					break;
				}


				//因为一些原因导致文件读写出错
				if (toRead != write(dst_c->file.fd, c->mem->ptr + c->offset, toRead)) { 
	
					log_error_write(srv, __FILE__, __LINE__, "sbs",
							"denying upload as writing to file failed:",
							dst_c->file.name, strerror(errno));

					con->http_status = 413; 
					con->keep_alive = 0;
					connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);

					close(dst_c->file.fd);
					dst_c->file.fd = -1;

					break;
				}

				dst_c->file.length += toRead;
				//读完所有需要的数据
				if (dst_cq->bytes_in + toRead == (off_t)con->request.content_length) {
					close(dst_c->file.fd);
					dst_c->file.fd = -1;
				}
			} 

//如果数据量少于1MB，数据直接保存到mem块中。
			else { 
				buffer *b;

				b = chunkqueue_get_append_buffer(dst_cq);
				buffer_copy_string_len(b, c->mem->ptr + c->offset, toRead);
			}
			 //更新记录
			c->offset += toRead;
			dst_cq->bytes_in += toRead;
		}
		/*POST数据已经全部读完，切换到CON_STATE_HANDLE_REQUEST状态开始请求处理，否则状态保持在CON_STATE_READ_POST*/
		if (dst_cq->bytes_in == (off_t)con->request.content_length) {
			connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
		}
		break;



	default: break;
	}

//连接被对方关闭并且连接状态未切换，则将状态换为CON_STATE_ERROR
	if (is_closed && ostate == con->state) { 
		connection_set_state(srv, con, CON_STATE_ERROR);
	}
//从链表头开始清理已经使用完毕的chunk，释放内存
	chunkqueue_remove_finished_chunks(cq); 

	return 0;
}



















































//已连接套接字的就绪时调用的处理函数（由该套接字在register时指定）
handler_t connection_handle_fdevent(void *s, void *context, int revents) {
	server     *srv = (server *)s;
	connection *con = context;

	joblist_append(srv, con);

	if (revents & FDEVENT_IN) {
		con->is_readable = 1;
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sd", "read-wait - done", con->fd);
#endif
	}
	if (revents & FDEVENT_OUT) {
		con->is_writable = 1;
		/* we don't need the event twice */
	}


	if (revents & ~(FDEVENT_IN | FDEVENT_OUT)) {
		/* looks like an error */

		/* FIXME: revents = 0x19 still means that we should read from the queue */
		if (revents & FDEVENT_HUP) {
			if (con->state == CON_STATE_CLOSE) {
				con->close_timeout_ts = 0;
			} else {
				/* sigio reports the wrong event here
				 *
				 * there was no HUP at all
				 */
#ifdef USE_LINUX_SIGIO
				if (srv->ev->in_sigio == 1) {
					log_error_write(srv, __FILE__, __LINE__, "sd",
						"connection closed: poll() -> HUP", con->fd);
				} else {
					connection_set_state(srv, con, CON_STATE_ERROR);
				}
#else
				connection_set_state(srv, con, CON_STATE_ERROR);
#endif

			}
		} else if (revents & FDEVENT_ERR) {
#ifndef USE_LINUX_SIGIO
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"connection closed: poll() -> ERR", con->fd);
#endif
			connection_set_state(srv, con, CON_STATE_ERROR);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "sd",
					"connection closed: poll() -> ???", revents);
		}
	}

	if (con->state == CON_STATE_READ ||
	    con->state == CON_STATE_READ_POST) {
		connection_handle_read_state(srv, con);
	}

	if (con->state == CON_STATE_WRITE &&
	    !chunkqueue_is_empty(con->write_queue) &&
	    con->is_writable) {

		if (-1 == connection_handle_write(srv, con)) {
			connection_set_state(srv, con, CON_STATE_ERROR);

			log_error_write(srv, __FILE__, __LINE__, "ds",
					con->fd,
					"handle write failed.");
		} else if (con->state == CON_STATE_WRITE) {
			con->write_request_ts = srv->cur_ts;
		}
	}

	if (con->state == CON_STATE_CLOSE) {
		/* flush the read buffers */
		int b;

		if (ioctl(con->fd, FIONREAD, &b)) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"ioctl() failed", strerror(errno));
		}

		if (b > 0) {
			char buf[1024];
			log_error_write(srv, __FILE__, __LINE__, "sdd",
					"CLOSE-read()", con->fd, b);

			/* */
			read(con->fd, buf, sizeof(buf));
		} else {
			/* nothing to read */

			con->close_timeout_ts = 0;
		}
	}

	return HANDLER_FINISHED;
}
































































//connection_accept()函数用来完成连接套接口描述符的创建
connection *connection_accept(server *srv, server_socket *srv_socket) {

//记录已经完成连接的TCP请求的描述符
	int cnt;

//记录客户端的信息
	sock_addr cnt_addr;
	socklen_t cnt_len;


//检查是否超过最大连接数目限制
	if (srv->conns->used >= srv->max_conns) { 
		return NULL;
	}



	cnt_len = sizeof(cnt_addr);
//接收已经完成连接的TCP请求，并获取客户端的信息存于cnt_addr和cnt_len中
	if (-1 == (cnt = accept(srv_socket->fd, (struct sockaddr *) &cnt_addr, &cnt_len))) { 
		switch (errno) {
//EAGAIN和EWOULDBLOCK表示非阻塞socket描述符上当前没有连接请求接收。
		case EAGAIN:
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
//函数accept()调用在返回一个有效连接之前信号所中断。
		case EINTR: 
// this is a FreeBSD thingy:连接被中断。
		case ECONNABORTED: 
			break;
//进程可打开的文件数目达到最大值。			
		case EMFILE: 
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ssd", "accept failed:", strerror(errno), errno);
		}
		return NULL;
	} 
//接收已经完成连接的TCP请求成功
	else {
		connection *con;
//当前打开的文件描述符数目增1。
		srv->cur_fds++; 

	
#if 0
		log_error_write(srv, __FILE__, __LINE__, "sd",
				"appected()", cnt);
#endif

//当前连接数目增1.
		srv->con_opened++;  

//从srv->conns数组中取出一个空闲的connections结构体元素并经过初始化后使用，	con->is_readable = 1;con->is_writable = 1;
		con = connections_get_new_connection(srv);

		con->fd = cnt;
		con->fde_ndx = -1;
#if 0
		gettimeofday(&(con->start_tv), NULL);
#endif
//将连接套接口描述符在事件管理监控器中进行注册。		
		fdevent_register(srv->ev, con->fd, connection_handle_fdevent, con); 

/*
将连接的状态机设置为开始状态 connection_set_state函数在connections-glue.c中，
因为该监听套接字可能使用TCP_DEFER_ACCEPT选项，三次握手连接中，最后客户端发送的ack带有数据，所以直接读和响应请求，其已连接套接字不用加入i/o复用（connection只处理一次请求）
*/
		connection_set_state(srv, con, CON_STATE_REQUEST_START); 


//记录时间戳。
		con->connection_start = srv->cur_ts; 

//记录对端（即客户端）地址信息。		
		con->dst_addr = cnt_addr; 
		/*转存客户端IP地址信息*/
		buffer_copy_string(con->dst_addr_buf, inet_ntop_cache_get_ip(srv, &(con->dst_addr))); 
//记录监听套接字描述符的信息
		con->srv_socket = srv_socket;
//设置已连接描述符的套接字选项
		if (-1 == (fdevent_fcntl_set(srv->ev, con->fd))) { 
			log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed: ", strerror(errno));
			return NULL;
		}

#ifdef USE_OPENSSL
		/* connect FD to SSL */
		if (srv_socket->is_ssl) {
			if (NULL == (con->ssl = SSL_new(srv_socket->ssl_ctx))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));

				return NULL;
			}

			SSL_set_accept_state(con->ssl);
			con->conf.is_ssl=1;

			if (1 != (SSL_set_fd(con->ssl, cnt))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
						ERR_error_string(ERR_get_error(), NULL));
				return NULL;
			}
		}
#endif
		return con;
	}
}




















































//连接状态转换管理器
int connection_state_machine(server *srv, connection *con) {
	int done = 0, r;

#ifdef USE_OPENSSL
	server_socket *srv_sock = con->srv_socket;
#endif
//日志记录目前连接的状态
	if (srv->srvconf.log_state_handling) { 
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"state at start",
				con->fd,
				connection_get_state(con->state));
	}




	while (done == 0) {
		size_t ostate = con->state;
		int b;

//按照该连接的不同状态进行不同的处理
		switch (con->state) {

//CON_STATE_REQUEST_START: 等待读
		case CON_STATE_REQUEST_START: 
			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

			con->request_start = srv->cur_ts;
			con->read_idle_ts = srv->cur_ts;

			con->request_count++;
			con->loops_per_request = 0;


/*
进行转换状态为CON_STATE_READ，在该状态下将调用函数connection_handle_read_state()读HTTP请求头域数据，该函数执行成功则进入CON_STATE_REQUEST_END状态，
如果出现HTTP错误将进入CON_STATE_HANDLE_REQUEST状态。
*/
			connection_set_state(srv, con, CON_STATE_READ); 

#ifdef USE_OPENSSL
			con->conf.is_ssl = srv_sock->is_ssl;
#endif

			break;



//CON_STATE_REQUEST_END：从获取的请求头域数据中解析客户端请求数据
		case CON_STATE_REQUEST_END: 
			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}
//该函数将解析客户端请求，返回值为1，则表示有后续的POST数据到达，因此进入CON_STATE_READ_POST状态读取POST数据。
			if (http_request_parse(srv, con)) { 
/*
进行转换状态为CON_STATE_READ_POST，在该状态下将调用函数connection_handle_read_state()和函数connection_handle_read()函数
继续读取http请求主体部分的数据
*/
			connection_set_state(srv, con, CON_STATE_READ_POST); 

				break;
			}
/*
否则，进行转换状态为CON_STATE_HANDLE_REQUEST，在该状态下将调用函数http_response_prepare()函数开始对该请求进行处理
*/
			connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST); 

			break;



//CON_STATE_HANDLE_REQUEST: 内部处理请求（可能导致，等待子请求）
		case CON_STATE_HANDLE_REQUEST: 

			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

			//客户端请求已经解析，开始对该请求进行处理。http_response_prepare()函数将调用插件对该请求做处理，根据插件的处理结果决定下一步怎么走。
			switch (r = http_response_prepare(srv, con)) { 

			//请求处理完成
			case HANDLER_FINISHED:
				//con->mode用于标记该请求是否需要由Lighttpd来处理，为DIRECT则由lighttpd自己处理，否则表示有其他比较独立的插件处理。
				if (con->mode == DIRECT) { 
					//资料未找到或禁止访问
					if (con->http_status == 404 ||
					    con->http_status == 403) {
						//用户设置有默认的404或403错误页面，变量"con->conf.error_handler"内存储的全局配置值，配置值"con->error_handler"是仅针对当前状态的条件配置值。
						if (con->in_error_handler == 0 &&
						    (!buffer_is_empty(con->conf.error_handler) ||
						     !buffer_is_empty(con->error_handler))) { 
							//临时存储
							con->error_handler_saved_status = con->http_status;
							con->http_status = 0;
							//请求的地址重定向到自定义错误页面
							if (buffer_is_empty(con->error_handler)) { 
								buffer_copy_string_buffer(con->request.uri, con->conf.error_handler);
							} 
							else {
								buffer_copy_string_buffer(con->request.uri, con->error_handler);
							}
							buffer_reset(con->physical.path);
							//处理标记，防止死循环，如当自定义的错误页面配置路径不正确时。
							con->in_error_handler = 1; 
							/*重新进行处理*/
							connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);

							done = -1;
							break;
						} 
						//用户未设置错误页面，则复原状态码
						else if (con->in_error_handler) { 
							con->http_status = con->error_handler_saved_status;
						}
					} 
					//用户设置有默认的404或403错误页面找到或可以访问
					else if (con->in_error_handler) {
											
					}
				}
				//资源（正确文件资源或错误页面资源）找到了，设状态码200为 服务器已成功处理请求
				if (con->http_status == 0) con->http_status = 200; 
				//进行转换状态为CON_STATE_RESPONSE_START:开始响应准备 
				connection_set_state(srv, con, CON_STATE_RESPONSE_START);
				break;


			//加入fd等待队列，等待子请求。	
			case HANDLER_WAIT_FOR_FD: 
				srv->want_fds++;

				fdwaitqueue_append(srv, con);

				connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);

				break;

			/*当需要重新检查请求结构（request-structure）时，插件会返回HANDLER_COMEBACK状态码，如在插件mod_rewrite插件中用于重写URI*/	
			case HANDLER_COMEBACK:
				done = -1;

			/*当插件没有处理完请求并需要等待fd-event或者执行FDs时，需要返回HANDLER_WAIT_FOR_EVENT或HANDLER_WAIT_FOR_FD*/
			case HANDLER_WAIT_FOR_EVENT:
				/* come back here */
				connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
				break;

			/*只有当发生致命错误时返回HANDLE_ERROR状态码，用于终止当前连接*/
			case HANDLER_ERROR:
				/* something went wrong */
				connection_set_state(srv, con, CON_STATE_ERROR);
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "sdd", "unknown ret-value: ", con->fd, r);
				break;
			}//switch (r = http_response_prepare(srv, con)) 
			
			break;





//CON_STATE_RESPONSE_START:准备http响应报文的头域数据
		case CON_STATE_RESPONSE_START: 
			/*
			 * - create the HTTP-Response-Header
			 */

			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

//connection_handle_write_prepare()函数，用于准备响应http整个报文工作。
			if (-1 == connection_handle_write_prepare(srv, con)) { 
				connection_set_state(srv, con, CON_STATE_ERROR);

				break;
			}
/*
进行转换状态为CON_STATE_WRITE，在该状态下发送整个hhtp响应报文！
*/
			connection_set_state(srv, con, CON_STATE_WRITE);
			break;



		case CON_STATE_RESPONSE_END: /* transient */ //本次响应完成
			/* log the request */

			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

			plugins_call_handle_request_done(srv, con); //插件的回调函数调用

			srv->con_written++;

			if (con->keep_alive) { //需要保持连接
				connection_set_state(srv, con, CON_STATE_REQUEST_START);

#if 0
				con->request_start = srv->cur_ts;
				con->read_idle_ts = srv->cur_ts;
#endif 
			} else { //否则表示关闭连接，因此插件的回调函数调用
				switch(r = plugins_call_handle_connection_close(srv, con)) {
				case HANDLER_GO_ON:
				case HANDLER_FINISHED:
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "sd", "unhandling return value", r);
					break;
				}

#ifdef USE_OPENSSL
				if (srv_sock->is_ssl) {
					switch (SSL_shutdown(con->ssl)) {
					case 1:
						/* done */
						break;
					case 0:
						/* wait for fd-event
						 *
						 * FIXME: wait for fdevent and call SSL_shutdown again
						 *
						 */

						break;
					default:
						log_error_write(srv, __FILE__, __LINE__, "ss", "SSL:",
								ERR_error_string(ERR_get_error(), NULL));
					}
				}
#endif
				connection_close(srv, con); //连接关闭

				srv->con_closed++;
			}

			connection_reset(srv, con); //连接重置

			break;



		case CON_STATE_CONNECT:
			if (srv->srvconf.log_state_handling) { 
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}
			/*
				Lighttpd接收客户端请求的数据以及对客户端发送响应的数据就是通过chunk结构体来组织的。
				如果connection结构体处在CON_STATE_CONNECT状态则表示该Connection已经关闭，因此重置其数据
				存储chunkqueue以节省内存，等待下一个客户端连接到来。
			*/
			chunkqueue_reset(con->read_queue);
			con->request_count = 0;

			break;



		case CON_STATE_CLOSE: //连接准备关闭
			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

			if (con->keep_alive) {
			//FIONREAD用来确定套接口描述符con->fd内可以读取的数据量，该值通过整型参数b返回。
				if (ioctl(con->fd, FIONREAD, &b)) {
					log_error_write(srv, __FILE__, __LINE__, "ss",
							"ioctl() failed", strerror(errno));
				}
				if (b > 0) { //有数据读取
					char buf[1024];
					log_error_write(srv, __FILE__, __LINE__, "sdd",
							"CLOSE-read()", con->fd, b);

					/*读取数据，但是Lighttpd却并没有对读取的数据做进一步处理，因此这里的函数read()调用主要是为了清空套接口描述符con->fd内的缓存空间*/
					read(con->fd, buf, sizeof(buf));
				} else {
					/* nothing to read */

					con->close_timeout_ts = 0;
				}
			} else {
				con->close_timeout_ts = 0;
			}

			if (srv->cur_ts - con->close_timeout_ts > 1) { //需要关闭连接？
				connection_close(srv, con);

				if (srv->srvconf.log_state_handling) {
					log_error_write(srv, __FILE__, __LINE__, "sd",
							"connection closed for fd", con->fd);
				}
			}

			break;




//POST:读取http请求主体数据
		case CON_STATE_READ_POST:
//GET:读取http请求起始行和首部的数据
		case CON_STATE_READ:
			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}

			connection_handle_read_state(srv, con); 
			break;




//CON_STATE_WRITE: 发送整个hhtp响应报文！
		case CON_STATE_WRITE: 

			if (srv->srvconf.log_state_handling) {
				log_error_write(srv, __FILE__, __LINE__, "sds",
						"state for fd", con->fd, connection_get_state(con->state));
			}


			if (!chunkqueue_is_empty(con->write_queue)) {
#if 0
				log_error_write(srv, __FILE__, __LINE__, "dsd",
						con->fd,
						"packets to write:",
						con->write_queue->used);
#endif
			}

			if (!chunkqueue_is_empty(con->write_queue) && con->is_writable) {
				//向客户端发送数据
				if (-1 == connection_handle_write(srv, con)) { 
					log_error_write(srv, __FILE__, __LINE__, "ds",
							con->fd,
							"handle write failed.");
					connection_set_state(srv, con, CON_STATE_ERROR);
				} 
				else if (con->state == CON_STATE_WRITE) {
					con->write_request_ts = srv->cur_ts;
				}
			}

			break;





		case CON_STATE_ERROR: /* transient */ //重置连接（包括关闭）

			/* even if the connection was drop we still have to write it to the access log */
			if (con->http_status) { //插件链的回调函数调用
				plugins_call_handle_request_done(srv, con);
			}
#ifdef USE_OPENSSL
			if (srv_sock->is_ssl) {
				int ret, ssl_r;
				unsigned long err;
				ERR_clear_error();
				switch ((ret = SSL_shutdown(con->ssl))) {
				case 1:
					/* ok */
					break;
				case 0:
					ERR_clear_error();
					if (-1 != (ret = SSL_shutdown(con->ssl))) break;

					/* fall through */
				default:

					switch ((ssl_r = SSL_get_error(con->ssl, ret))) {
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;
					case SSL_ERROR_SYSCALL:
						/* perhaps we have error waiting in our error-queue */
						if (0 != (err = ERR_get_error())) {
							do {
								log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:",
										ssl_r, ret,
										ERR_error_string(err, NULL));
							} while((err = ERR_get_error()));
						} else {
							log_error_write(srv, __FILE__, __LINE__, "sddds", "SSL (error):",
									ssl_r, ret, errno,
									strerror(errno));
						}
	
						break;
					default:
						while((err = ERR_get_error())) {
							log_error_write(srv, __FILE__, __LINE__, "sdds", "SSL:",
									ssl_r, ret,
									ERR_error_string(err, NULL));
						}
	
						break;
					}
				}
			}
			ERR_clear_error();
#endif

			switch(con->mode) {
			case DIRECT:
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"emergency exit: direct",
						con->fd);
#endif
				break;
			default:
				switch(r = plugins_call_handle_connection_close(srv, con)) { //插件链的回调函数调用
				case HANDLER_GO_ON:
				case HANDLER_FINISHED:
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "");
					break;
				}
				break;
			}

			connection_reset(srv, con);

			/* close the connection */
			/*关闭连接*/
			if ((con->keep_alive == 1) &&
			    (0 == shutdown(con->fd, SHUT_WR))) {
				con->close_timeout_ts = srv->cur_ts;
				connection_set_state(srv, con, CON_STATE_CLOSE);

				if (srv->srvconf.log_state_handling) {
					log_error_write(srv, __FILE__, __LINE__, "sd",
							"shutdown for fd", con->fd);
				}
			} else {
				connection_close(srv, con);
			}

			con->keep_alive = 0;

			srv->con_closed++;

			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sdd",
					"unknown state:", con->fd, con->state);

			break;
		} //switch (con->state) 










//需要继续处理
		if (done == -1) { 
			done = 0;
		} 
//状态未变，不需要继续处理
		else if (ostate == con->state) { 
			done = 1;
		}

	}



	if (srv->srvconf.log_state_handling) {
		log_error_write(srv, __FILE__, __LINE__, "sds",
				"state at exit:",
				con->fd,
				connection_get_state(con->state));
	}


//在这三种状态下，有可能会受到客户端的请求数据，因此在socket描述符上加上可读事件监控。
	switch(con->state) { 
	case CON_STATE_READ_POST:
	case CON_STATE_READ:
	case CON_STATE_CLOSE:
		fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_IN);
		break;

	case CON_STATE_WRITE:
		 /*
			有数据要发送、当前不可写并且未达到传输速度限制上限，此时需要监控socket描述符何时可写，即发生可写事件
			时立即获得通知，便可以将待发数据发送出去。
		 */
		if (!chunkqueue_is_empty(con->write_queue) &&
		    (con->is_writable == 0) &&
		    (con->traffic_limit_reached == 0)) {
			fdevent_event_add(srv->ev, &(con->fde_ndx), con->fd, FDEVENT_OUT);
		} 
		else {
			/*
				无数据发送或socket描述符当前本来就是可写状态或者达到传输速度限制上限，此时删除监控socket描述符上可写事件
			*/
			fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
		}
		break;
	//其他情况需要删除socket描述符上监控事件
	default:
		fdevent_event_del(srv->ev, &(con->fde_ndx), con->fd);
		break;
	}


	return 0;
}
