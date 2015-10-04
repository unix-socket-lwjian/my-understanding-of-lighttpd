#define _GNU_SOURCE

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include "log.h"
#include "array.h"

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

/* Close fd and _try_ to get a /dev/null for it instead.
 * close() alone may trigger some bugs when a
 * process opens another file and gets fd = STDOUT_FILENO or STDERR_FILENO
 * and later tries to just print on stdout/stderr
 *
 * Returns 0 on success and -1 on failure (fd gets closed in all cases)
 */





















 // 该函数首先关闭fd文件描述符原来所指的打开文件，然后尝试将指向空文件（／dev／null）的文件描述符保存到fd中
int openDevNull(int fd) {
	int tmpfd;
	close(fd);
#if defined(__WIN32)
	tmpfd = open("nul", O_RDWR);
#else
	tmpfd = open("/dev/null", O_RDWR);
#endif
	if (tmpfd != -1 && tmpfd != fd) {
//复制文件描述符到fd
		dup2(tmpfd, fd); 
		close(tmpfd);
	}
	return (tmpfd != -1) ? 0 : -1;
}



























/**
 * 记录日志方式:
 * - 1.输出到标准错误 (默认)
 * - 2.记录到用户指定的日志文件中
 * - 3.记录到操作系统日志内
 */
//该函数用于打开日志系统 
int log_error_open(server *srv) {
	int close_stderr = 1;

#ifdef HAVE_SYSLOG_H      
//打开本程序到系统日志服务进程的一个连接
	openlog("lighttpd", LOG_CONS | LOG_PID, LOG_DAEMON); 
#endif

//默认日志方式，errorlog_mode取值为3个枚举值之一。枚举结构直接定义在server结构体中。base.h文件中。
	srv->errorlog_mode = ERRORLOG_STDERR; 

//如果配置中声明使用系统日志则修改错误日志模式为ERRORLOG_SYSLOG
	if (srv->srvconf.errorlog_use_syslog) { 
		srv->errorlog_mode = ERRORLOG_SYSLOG;
	} 

//如果设置了用户合法路径的日志文件，则使用用户指定的日志文件
	else if (!buffer_is_empty(srv->srvconf.errorlog_file)) { 
		const char *logfile = srv->srvconf.errorlog_file->ptr;
//打开用户指定的日志文件
		if (-1 == (srv->errorlog_fd = open(logfile, O_APPEND | O_WRONLY | O_CREAT | O_LARGEFILE, 0644))) { 
//打开用户指定的日志文件失败
			log_error_write(srv, __FILE__, __LINE__, "SSSS",
					"opening errorlog '", logfile,
					"' failed: ", strerror(errno));
			return -1;
		}
#ifdef FD_CLOEXEC //FD_CLOEXEC用于配置文件的close-on-exec状态标准。close-on-exec为0（默认），则调用exec()后，此文件不被关闭。非零则关闭。
		/* close fd on exec (cgi) */
		fcntl(srv->errorlog_fd, F_SETFD, FD_CLOEXEC); //fcntl用于改变一打开文件性质
#endif
//修改错误日志模式为ERRORLOG_FILE
		srv->errorlog_mode = ERRORLOG_FILE;
	}
//Lighttpd开始运行！
	log_error_write(srv, __FILE__, __LINE__, "s", "server started");

//当程序运行在Valgrind调试状态时，不能关闭标准错误文件
#ifdef HAVE_VALGRIND_VALGRIND_H 

	if (RUNNING_ON_VALGRIND) close_stderr = 0;
#endif

//守护进程是不向终端输出信息的，直接将错误信息输出到 /dev/null。
	if (srv->errorlog_mode == ERRORLOG_STDERR && srv->srvconf.dont_daemonize) { 
		close_stderr = 0;
	}

// 将STDERR_FILENO为标准错误输出重定向到／dev/null
	if (close_stderr) openDevNull(STDERR_FILENO);
	return 0;
}



























/**
 * open the errorlog
 *
 * if the open failed, report to the user and die
 * if no filename is given, use syslog instead
 *
 */


//重新打开用户指定的日志文件，如果打开失败，就使用系统日志
int log_error_cycle(server *srv) {
	/* only cycle if we are not in syslog-mode */

	if (srv->errorlog_mode == ERRORLOG_FILE) {
		const char *logfile = srv->srvconf.errorlog_file->ptr;
		/* already check of opening time */

		int new_fd;

		if (-1 == (new_fd = open(logfile, O_APPEND | O_WRONLY | O_CREAT | O_LARGEFILE, 0644))) {
			/* write to old log */
			log_error_write(srv, __FILE__, __LINE__, "SSSSS",
					"cycling errorlog '", logfile,
					"' failed: ", strerror(errno),
					", falling back to syslog()");

			close(srv->errorlog_fd);
			srv->errorlog_fd = -1;
#ifdef HAVE_SYSLOG_H
			srv->errorlog_mode = ERRORLOG_SYSLOG;
#endif
		} else {
			/* ok, new log is open, close the old one */
			close(srv->errorlog_fd);
			srv->errorlog_fd = new_fd;
		}
	}

	return 0;
}






























//关闭日志系统
int log_error_close(server *srv) {
	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
		close(srv->errorlog_fd);
		break;
	case ERRORLOG_SYSLOG:
#ifdef HAVE_SYSLOG_H
		closelog();
#endif
		break;
	case ERRORLOG_STDERR:
		break;
	}

	return 0;
}




























//将可变参数按指定的格式组成一个字符串（日志信息），然后将其记录起来，即输出到三种方式的其中一种
/*
filename：要记录信息所在的文件
line：信息具体在文件里的行号
fmt：信息格式
const char *fmt, ...：可变参数，但参数是char类型的
*/ 
int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...) {
	va_list ap;


//构建时间
	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
	case ERRORLOG_STDERR: //当错误日志类型为用户定义日志文件或是标准错误输出时，
		/* cache the generated timestamp */ //cache生产的时间戳
		if (srv->cur_ts != srv->last_generated_debug_ts) { //上次创建的时间戳已经变得陈旧，需要重新构建
			buffer_prepare_copy(srv->ts_debug_str, 255);
			strftime(srv->ts_debug_str->ptr, srv->ts_debug_str->size - 1, "%Y-%m-%d %H:%M:%S", localtime(&(srv->cur_ts))); //strftime是时间格式化函数.localtime函数将time_t形式的参数转换成本地时间日期表示方法。
			srv->ts_debug_str->used = strlen(srv->ts_debug_str->ptr) + 1;

			srv->last_generated_debug_ts = srv->cur_ts;  //更新上次创建的时间记录
		}

		buffer_copy_string_buffer(srv->errorlog_buf, srv->ts_debug_str); //buffer结构体之间的复制
		buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(": (")); //CONST_STR_LEN宏定义在buffer.h中 #define CONST_STR_LEN(x) x, x ? sizeof(x) - 1 : 0
		break;
	case ERRORLOG_SYSLOG:
		/* syslog is generating its own timestamps */
		buffer_copy_string_len(srv->errorlog_buf, CONST_STR_LEN("("));
		break;
	}



//构建文件名和行号
	buffer_append_string(srv->errorlog_buf, filename);
	buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN("."));
	buffer_append_long(srv->errorlog_buf, line);
	buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(") "));


//对可变参数进行逐个分析，根据其不同类型进行添加
//va_start(ap, fmt):使得ap指向第一个可变参数
	for(va_start(ap, fmt); *fmt; fmt++) {
		int d;
		char *s;
		buffer *b;
		off_t o;
		switch(*fmt) {
		case 's':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string(srv->errorlog_buf, s); 
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(" "));
			break;
		case 'b':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_buffer(srv->errorlog_buf, b);
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(" "));
			break;
		case 'd':           /* int */
			d = va_arg(ap, int);
			buffer_append_long(srv->errorlog_buf, d); 
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(" "));
			break;
		case 'o':           /* off_t */ //long
			o = va_arg(ap, off_t);
			buffer_append_off_t(srv->errorlog_buf, o);
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(" "));
			break;
		case 'x':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN("0x"));
			buffer_append_long_hex(srv->errorlog_buf, d);
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN(" "));
			break;
		case 'S':           /* string */
			s = va_arg(ap, char *);
			buffer_append_string(srv->errorlog_buf, s);
			break;
		case 'B':           /* buffer */
			b = va_arg(ap, buffer *);
			buffer_append_string_buffer(srv->errorlog_buf, b);
			break;
		case 'D':           /* int */
			d = va_arg(ap, int);
			buffer_append_long(srv->errorlog_buf, d);
			break;
		case 'O':           /* off_t */
			o = va_arg(ap, off_t);
			buffer_append_off_t(srv->errorlog_buf, o);
			break;
		case 'X':           /* int (hex) */
			d = va_arg(ap, int);
			buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN("0x"));
			buffer_append_long_hex(srv->errorlog_buf, d);
			break;
		case '(':
		case ')':
		case '<':
		case '>':
		case ',':
		case ' ':
			buffer_append_string_len(srv->errorlog_buf, fmt, 1);
			break;
		}
	}
	va_end(ap);



// 将日志信息输出到三种方式的其中一种
	switch(srv->errorlog_mode) {
	case ERRORLOG_FILE:
		buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN("\n"));
		write(srv->errorlog_fd, srv->errorlog_buf->ptr, srv->errorlog_buf->used - 1);
		break;
	case ERRORLOG_STDERR:
		buffer_append_string_len(srv->errorlog_buf, CONST_STR_LEN("\n"));
		write(STDERR_FILENO, srv->errorlog_buf->ptr, srv->errorlog_buf->used - 1);
		break;
	case ERRORLOG_SYSLOG:
		syslog(LOG_ERR, "%s", srv->errorlog_buf->ptr);
		break;
	}

	return 0;
}

