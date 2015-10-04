#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

#include <stdio.h>

#include "response.h"
#include "keyvalue.h"
#include "log.h"
#include "stat_cache.h"
#include "chunk.h"

#include "configfile.h"
#include "connections.h"

#include "plugin.h"

#include "sys-socket.h"


































int http_response_write_header(server *srv, connection *con) {
	buffer *b;
	size_t i;
	int have_date = 0;
	int have_server = 0;
	//获取一个mem类型的chunk块并添加到con->write_queue头部作为第一个chunk元素，这样在向客户端发送响应数据时，该chunk块内保存的头域字符串将首先发送出去 
	b = chunkqueue_get_prepend_buffer(con->write_queue);

	//构建b响应头域的信息
	if (con->request.http_version == HTTP_VERSION_1_1) {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.1 "));
	} else {
		buffer_copy_string_len(b, CONST_STR_LEN("HTTP/1.0 "));
	}
	buffer_append_long(b, con->http_status);
	buffer_append_string_len(b, CONST_STR_LEN(" "));
	buffer_append_string(b, get_http_status_name(con->http_status));

	if (con->request.http_version != HTTP_VERSION_1_1 || con->keep_alive == 0) {
		buffer_append_string_len(b, CONST_STR_LEN("\r\nConnection: "));
		if (con->keep_alive) {
			buffer_append_string_len(b, CONST_STR_LEN("keep-alive"));
		} else {
			buffer_append_string_len(b, CONST_STR_LEN("close"));
		}
	}

	if (con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED) {
		buffer_append_string_len(b, CONST_STR_LEN("\r\nTransfer-Encoding: chunked"));
	}


	/* add all headers */
	for (i = 0; i < con->response.headers->used; i++) {
		data_string *ds;

		ds = (data_string *)con->response.headers->data[i];

		if (ds->value->used && ds->key->used &&
		    0 != strncasecmp(ds->key->ptr, CONST_STR_LEN("X-LIGHTTPD-")) &&
			0 != strcasecmp(ds->key->ptr, "X-Sendfile")) {
			if (0 == strcasecmp(ds->key->ptr, "Date")) have_date = 1;
			if (0 == strcasecmp(ds->key->ptr, "Server")) have_server = 1;
			if (0 == strcasecmp(ds->key->ptr, "Content-Encoding") && 304 == con->http_status) continue;

			buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
			buffer_append_string_buffer(b, ds->key);
			buffer_append_string_len(b, CONST_STR_LEN(": "));
#if 0
			/** 
			 * the value might contain newlines, encode them with at least one white-space
			 */
			buffer_append_string_encoded(b, CONST_BUF_LEN(ds->value), ENCODING_HTTP_HEADER);
#else
			buffer_append_string_buffer(b, ds->value);
#endif
		}
	}

	if (!have_date) {
		/* HTTP/1.1 requires a Date: header */
		buffer_append_string_len(b, CONST_STR_LEN("\r\nDate: "));

		/* cache the generated timestamp */
		if (srv->cur_ts != srv->last_generated_date_ts) {
			buffer_prepare_copy(srv->ts_date_str, 255);

			strftime(srv->ts_date_str->ptr, srv->ts_date_str->size - 1,
				 "%a, %d %b %Y %H:%M:%S GMT", gmtime(&(srv->cur_ts)));

			srv->ts_date_str->used = strlen(srv->ts_date_str->ptr) + 1;

			srv->last_generated_date_ts = srv->cur_ts;
		}

		buffer_append_string_buffer(b, srv->ts_date_str);
	}

	if (!have_server) {
		if (buffer_is_empty(con->conf.server_tag)) {
			buffer_append_string_len(b, CONST_STR_LEN("\r\nServer: " PACKAGE_NAME "/" PACKAGE_VERSION));
		} else if (con->conf.server_tag->used > 1) {
			buffer_append_string_len(b, CONST_STR_LEN("\r\nServer: "));
			buffer_append_string_encoded(b, CONST_BUF_LEN(con->conf.server_tag), ENCODING_HTTP_HEADER);
		}
	}

	//添加结束头域行
	buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));
	con->bytes_header = b->used - 1;
	if (con->conf.log_response_header) {
		log_error_write(srv, __FILE__, __LINE__, "sSb", "Response-Header:", "\n", b);
	}

	return 0;
}












































handler_t http_response_prepare(server *srv, connection *con) {
	handler_t r;

	//该请求已经被处理则直接返回
	if (con->mode == DIRECT &&
	    (con->http_status != 0 && con->http_status != 200)) {
		/* remove a packets in the queue */
		if (con->file_finished == 0) {
			chunkqueue_reset(con->write_queue);
		}

		return HANDLER_FINISHED;
	}

	//该请求未被处理并且请求资料的绝对路径还未组织
	if (con->mode == DIRECT && con->physical.path->used == 0) {
		char *qstr;

		
		//重置连接配置值
		config_cond_cache_reset(srv, con);
		//获取连接的固定全局配置值
		config_setup_connection(srv, con); 
		//记录日志
		if (con->conf.log_condition_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "run condition");
		}
		//获取连接的socket条件配置值
		config_patch_connection(srv, con, COMP_SERVER_SOCKET); 

	
		//记录协议类型
		if (con->conf.is_ssl) {
			buffer_copy_string_len(con->uri.scheme, CONST_STR_LEN("https"));
		} 
		else {
			buffer_copy_string_len(con->uri.scheme, CONST_STR_LEN("http"));
		}

		//记录主机名或者ip：port
		buffer_copy_string_buffer(con->uri.authority, con->request.http_host);
		//转小写
		buffer_to_lower(con->uri.authority);

		//获取连接的各类条件配置值
		config_patch_connection(srv, con, COMP_HTTP_SCHEME);    /* Scheme:      */
		config_patch_connection(srv, con, COMP_HTTP_HOST);      /* Host:        */
		config_patch_connection(srv, con, COMP_HTTP_REMOTE_IP); /* Client-IP */
		config_patch_connection(srv, con, COMP_HTTP_REFERER);   /* Referer:     */
		config_patch_connection(srv, con, COMP_HTTP_USER_AGENT);/* User-Agent:  */
		config_patch_connection(srv, con, COMP_HTTP_COOKIE);    /* Cookie:  */
		config_patch_connection(srv, con, COMP_HTTP_REQUEST_METHOD); /* REQUEST_METHOD */

		//去除uri中的‘＃’号（资源段落定位号），请求资料的路径不需要此符号
		if (NULL != (qstr = strchr(con->request.uri->ptr, '#'))) {
			con->request.uri->used = qstr - con->request.uri->ptr;
			con->request.uri->ptr[con->request.uri->used++] = '\0';
		}

		//去除uri中的‘？’号（查询号），请求资料的路径不需要此符号
		if (NULL != (qstr = strchr(con->request.uri->ptr, '?'))) {
			buffer_copy_string    (con->uri.query, qstr + 1);
			buffer_copy_string_len(con->uri.path_raw, con->request.uri->ptr, qstr - con->request.uri->ptr);
		} 
		else {
			buffer_reset     (con->uri.query);
			buffer_copy_string_buffer(con->uri.path_raw, con->request.uri);
		}


		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- splitting Request-URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Request-URI  : ", con->request.uri);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-scheme   : ", con->uri.scheme);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-authority: ", con->uri.authority);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path     : ", con->uri.path_raw);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-query    : ", con->uri.query);
		}

	
		//保证不超过可保持的最大连接数
		if (con->request_count > con->conf.max_keep_alive_requests) {
			con->keep_alive = 0;
		}


		

		//解码uri；con->uri.path_raw存的是原始uri，而con->uri.path存的是经过等同简化的uri
		if (con->request.http_method == HTTP_METHOD_OPTIONS &&
		    con->uri.path_raw->ptr[0] == '*' && con->uri.path_raw->ptr[1] == '\0') {
			//当客户端请求方法为options时，请求的uri可以为*号，表示请求会应用于服务器的所有资源而不是特定资源
			buffer_copy_string_buffer(con->uri.path, con->uri.path_raw);
		} 
		else {
			buffer_copy_string_buffer(srv->tmp_buf, con->uri.path_raw);
			buffer_urldecode_path(srv->tmp_buf);
			buffer_path_simplify(con->uri.path, srv->tmp_buf);
		}


		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- sanatising URI");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "URI-path     : ", con->uri.path);
		}




		//插件处理函数调用
		switch(r = plugins_call_handle_uri_raw(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "sd", "handle_uri_raw: unknown return value", r);
			break;
		}

		
		//获取连接的HTTPurl和HTTPqs的条件配置值
		config_patch_connection(srv, con, COMP_HTTP_URL); /* HTTPurl */
		config_patch_connection(srv, con, COMP_HTTP_QUERY_STRING); /* HTTPqs */


		//判断是否支持http1.1版本，若不支持则使用http1.0版本
		if (!con->conf.allow_http11) {
			con->request.http_version = HTTP_VERSION_1_0;
		}

		//插件处理函数调用
		switch(r = plugins_call_handle_uri_clean(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}



		//options请求应用于服务器的所有资源时直接处理并返回
		if (con->request.http_method == HTTP_METHOD_OPTIONS &&
		    con->uri.path->ptr[0] == '*' && con->uri.path_raw->ptr[1] == '\0') {
		
			response_header_insert(srv, con, CONST_STR_LEN("Allow"), CONST_STR_LEN("OPTIONS, GET, HEAD, POST"));

			con->http_status = 200;
			con->file_finished = 1;

			return HANDLER_FINISHED;
		}



		/***
		 *
		 * border
		 *
		 * logical filename (URI) becomes a physical filename here
		 *
		 *
		 *
		 */




		/* 1. stat()
		 * ... ISREG() -> ok, go on
		 * ... ISDIR() -> index-file -> redirect
		 *
		 * 2. pathinfo()
		 * ... ISREG()
		 *
		 * 3. -> 404
		 *
		 */

		/*
		 * SEARCH DOCUMENT ROOT
		 */

		/* set a default */
		//记录资源的根路径和简化的路径
		buffer_copy_string_buffer(con->physical.doc_root, con->conf.document_root);
		buffer_copy_string_buffer(con->physical.rel_path, con->uri.path);


#if defined(__WIN32) || defined(__CYGWIN__)
		/* strip dots from the end and spaces
		 *
		 * windows/dos handle those filenames as the same file
		 *
		 * foo == foo. == foo..... == "foo...   " == "foo..  ./"
		 *
		 * This will affect in some cases PATHINFO
		 *
		 * on native windows we could prepend the filename with \\?\ to circumvent
		 * this behaviour. I have no idea how to push this through cygwin
		 *
		 * */
		 //去掉uri末尾的点和空格
		if (con->physical.rel_path->used > 1) {
			buffer *b = con->physical.rel_path;
			size_t i;

			if (b->used > 2 &&
			    b->ptr[b->used-2] == '/' &&
			    (b->ptr[b->used-3] == ' ' ||
			     b->ptr[b->used-3] == '.')) {
				b->ptr[b->used--] = '\0';
			}

			for (i = b->used - 2; b->used > 1; i--) {
				if (b->ptr[i] == ' ' ||
				    b->ptr[i] == '.') {
					b->ptr[b->used--] = '\0';
				} else {
					break;
				}
			}
		}
#endif


		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- before doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}



		/* the docroot plugin should set the doc_root and might also set the physical.path
		 * for us (all vhost-plugins are supposed to set the doc_root)
		 * */
		//插件处理函数调用
		switch(r = plugins_call_handle_docroot(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}

		/* MacOS X and Windows can't distiguish between upper and lower-case
		 *
		 * convert to lower-case
		 */
		 //将资源简化路径转小写
		if (con->conf.force_lowercase_filenames) {
			buffer_to_lower(con->physical.rel_path);
		}

		/* the docroot plugins might set the servername, if they don't we take http-host */
		if (buffer_is_empty(con->server_name)) {
			buffer_copy_string_buffer(con->server_name, con->uri.authority);
		}


		/**
		 * create physical filename
		 * -> physical.path = docroot + rel_path
		 *
		 */
		//将资源的根路径和简化的路径合并成绝对路径
		buffer_copy_string_buffer(con->physical.path, con->physical.doc_root);
		BUFFER_APPEND_SLASH(con->physical.path);
		buffer_copy_string_buffer(con->physical.basedir, con->physical.path);
		if (con->physical.rel_path->used &&
		    con->physical.rel_path->ptr[0] == '/') {
			buffer_append_string_len(con->physical.path, con->physical.rel_path->ptr + 1, con->physical.rel_path->used - 2);
		} else {
			buffer_append_string_buffer(con->physical.path, con->physical.rel_path);
		}



		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after doc_root");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}



		//插件处理函数调用
		switch(r = plugins_call_handle_physical(srv, con)) {
		case HANDLER_GO_ON:
			break;
		case HANDLER_FINISHED:
		case HANDLER_COMEBACK:
		case HANDLER_WAIT_FOR_EVENT:
		case HANDLER_ERROR:
			return r;
		default:
			log_error_write(srv, __FILE__, __LINE__, "");
			break;
		}

		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- logical -> physical");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Doc-Root     :", con->physical.doc_root);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Rel-Path     :", con->physical.rel_path);
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}
	}






	/*
	 *程序执行到此，代表当前请求还没处理掉（如options请求、请求的uri被禁止访问等）
	 *接下来进行检查请求资源文件是否存在进一步处理
	 */

	if (con->mode == DIRECT) {
		char *slash = NULL;
		char *pathinfo = NULL;
		int found = 0;
		stat_cache_entry *sce = NULL;



		//记录日志
		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling physical path");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}

		//请求的资源存在 
		if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {

			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- file found");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
			}
#ifdef HAVE_LSTAT
			//若文件路径含有符号链接且配置文件指定不允许访问符号链接资源
			if ((sce->is_symlink != 0) && !con->conf.follow_symlink) {
				//403:禁止访问
				con->http_status = 403; 

				if (con->conf.log_request_handling) {
					log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied due symlink restriction");
					log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				}

				buffer_reset(con->physical.path);
				return HANDLER_FINISHED;
			};
#endif
			//若当前请求的资源文件时一个目录文件，而请求uri的末尾字符又不是‘／’
			if (S_ISDIR(sce->st.st_mode)) {
				if (con->physical.path->ptr[con->physical.path->used - 2] != '/') {
				
					//设置响应状态码为301（永久性重定向）
					http_response_redirect_to_directory(srv, con);
					return HANDLER_FINISHED;
				}
#ifdef HAVE_LSTAT
			} else if (!S_ISREG(sce->st.st_mode) && !sce->is_symlink) {
#else
			} else if (!S_ISREG(sce->st.st_mode)) {
#endif
				/* any special handling of non-reg files ?*/
			}
		}

		//调用stat_cache_get_entry函数出错
		 else {
			switch (errno) {
			//存储权限有误
			case EACCES:
				con->http_status = 403;

				if (con->conf.log_request_handling) {
					log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied");
					log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				}

				buffer_reset(con->physical.path);
				return HANDLER_FINISHED;
			//路径名的部分组成不存在
			case ENOENT:
				con->http_status = 404;

				if (con->conf.log_request_handling) {
					log_error_write(srv, __FILE__, __LINE__,  "s",  "-- file not found");
					log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				}

				buffer_reset(con->physical.path);
				return HANDLER_FINISHED;
			//路径名的部分不是目录
			case ENOTDIR:
				/* PATH_INFO ! :) */
				break;
			//其他错误
			default:
				/* we have no idea what happend. let's tell the user so. */
				con->http_status = 500;
				buffer_reset(con->physical.path);

				log_error_write(srv, __FILE__, __LINE__, "ssbsb",
						"file not found ... or so: ", strerror(errno),
						con->uri.path,
						"->", con->physical.path);

				return HANDLER_FINISHED;
			}




			//路径名的部分不是目录，可能是多种url模式造成的，所以逐步向前查找实际的页面资源路径
			buffer_copy_string_buffer(srv->tmp_buf, con->physical.path);
			//逐步去掉末尾的查询参数，直到找到资源文件或证实资源文件不存在为止
			do {
				if (slash) {
					buffer_copy_string_len(con->physical.path, srv->tmp_buf->ptr, slash - srv->tmp_buf->ptr);
				} else {
					buffer_copy_string_buffer(con->physical.path, srv->tmp_buf);
				}

				if (HANDLER_ERROR != stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
					found = S_ISREG(sce->st.st_mode);
					break;
				}

				if (pathinfo != NULL) {
					*pathinfo = '\0';
				}
				slash = strrchr(srv->tmp_buf->ptr, '/');

				if (pathinfo != NULL) {
					/* restore '/' */
					*pathinfo = '/';
				}

				if (slash) pathinfo = slash;
			} while ((found == 0) && (slash != NULL) && ((size_t)(slash - srv->tmp_buf->ptr) > (con->physical.basedir->used - 2)));

			//资源文件不存在
			if (found == 0) {
				/* no it really doesn't exists */
				con->http_status = 404;

				if (con->conf.log_file_not_found) {
					log_error_write(srv, __FILE__, __LINE__, "sbsb",
							"file not found:", con->uri.path,
							"->", con->physical.path);
				}

				buffer_reset(con->physical.path);

				return HANDLER_FINISHED;
			}




			//若文件路径含有符号链接且配置文件指定不允许访问符号链接资源
#ifdef HAVE_LSTAT
			if ((sce->is_symlink != 0) && !con->conf.follow_symlink) {
				//403:禁止访问
				con->http_status = 403;

				if (con->conf.log_request_handling) {
					log_error_write(srv, __FILE__, __LINE__,  "s",  "-- access denied due symlink restriction");
					log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				}

				buffer_reset(con->physical.path);
				return HANDLER_FINISHED;
			};
#endif



			//记录实际的页面资源路径pathinfo
			if (pathinfo) {
				buffer_copy_string(con->request.pathinfo, pathinfo);

				con->uri.path->used -= strlen(pathinfo);
				con->uri.path->ptr[con->uri.path->used - 1] = '\0';
			}

			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- after pathinfo check");
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
				log_error_write(srv, __FILE__, __LINE__,  "sb", "URI          :", con->uri.path);
				log_error_write(srv, __FILE__, __LINE__,  "sb", "Pathinfo     :", con->request.pathinfo);
			}
		}






		if (con->conf.log_request_handling) {
			log_error_write(srv, __FILE__, __LINE__,  "s",  "-- handling subrequest");
			log_error_write(srv, __FILE__, __LINE__,  "sb", "Path         :", con->physical.path);
		}



		//插件处理函数调用
		switch(r = plugins_call_handle_subrequest_start(srv, con)) {
		case HANDLER_GO_ON:
			/* request was not handled */
			break;
		case HANDLER_FINISHED:
		default:
			if (con->conf.log_request_handling) {
				log_error_write(srv, __FILE__, __LINE__,  "s",  "-- subrequest finished");
			}

			/* something strange happend */
			return r;
		}


		
		//没有任何插件处理这种情况，设置状态响应码为403（禁止访问）
		if (con->mode == DIRECT && con->http_status == 0) {
			switch (con->request.http_method) {
			case HTTP_METHOD_OPTIONS:
				con->http_status = 200;
				break;
			default:
				con->http_status = 403;
			}

			return HANDLER_FINISHED;
		}

	}


	//插件处理函数调用 
	switch(r = plugins_call_handle_subrequest(srv, con)) {
	case HANDLER_GO_ON:
		/* request was not handled, looks like we are done */
		return HANDLER_FINISHED;
	case HANDLER_FINISHED:
		/* request is finished */
	default:
		/* something strange happend */
		return r;
	}

	/* can't happen */
	return HANDLER_COMEBACK;
}



