#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <locale.h>

#include <stdio.h>

#include "server.h"
#include "buffer.h"
#include "network.h"
#include "log.h"
#include "keyvalue.h"
#include "response.h"
#include "request.h"
#include "chunk.h"
#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "stat_cache.h"
#include "plugin.h"
#include "joblist.h"
#include "network_backends.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_PWD_H
#include <grp.h>
#include <pwd.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef USE_OPENSSL
# include <openssl/err.h> 
#endif

#ifndef __sgi
/* IRIX doesn't like the alarm based time() optimization */
/* #define USE_ALARM */
#endif





















//														分别定义sigaction_handler、signal_handler两个信号处理函数
//signal_handler用于signal函数；sigaction_handler（可接受附带消息）用于sigaction函数
static volatile sig_atomic_t srv_shutdown = 0;
static volatile sig_atomic_t graceful_shutdown = 0;
static volatile sig_atomic_t handle_sig_alarm = 1;
static volatile sig_atomic_t handle_sig_hup = 0;
static volatile sig_atomic_t forwarded_sig_hup = 0;

#if defined(HAVE_SIGACTION) && defined(SA_SIGINFO)
static volatile siginfo_t last_sigterm_info;
static volatile siginfo_t last_sighup_info;
static void sigaction_handler(int sig, siginfo_t *si, void *context) {
	UNUSED(context);

	switch (sig) {
	case SIGTERM:
		srv_shutdown = 1;
		last_sigterm_info = *si;
		break;
	case SIGINT:
		if (graceful_shutdown) {
			srv_shutdown = 1;
		} else {
			graceful_shutdown = 1;
		}
		last_sigterm_info = *si;

		break;
	case SIGALRM: 
		handle_sig_alarm = 1; 
		break;
	case SIGHUP:
		if (!forwarded_sig_hup) {
			handle_sig_hup = 1;
			last_sighup_info = *si;
		} else {
			forwarded_sig_hup = 0;
		}
		break;
	case SIGCHLD:
		break;
	}
}
#elif defined(HAVE_SIGNAL) || defined(HAVE_SIGACTION)
static void signal_handler(int sig) {
	switch (sig) {
	case SIGTERM: srv_shutdown = 1; break;
	case SIGINT:
	     if (graceful_shutdown) srv_shutdown = 1;
	     else graceful_shutdown = 1;

	     break;
	case SIGALRM: handle_sig_alarm = 1; break;
	case SIGHUP:  handle_sig_hup = 1; break;	//??????????????????????????????????
	case SIGCHLD:  break;
	}
}
#endif




































//																				进程守护化函数
//												根据srv->srvconf.dont_daemonize的值判断是否要进行进程守护化（＝＝0则进行，＝＝1则不进行）
#ifdef HAVE_FORK
static void daemonize(void) {
//将下述出现的信号进行忽略,防止在守护进程没有正常运转前，控制终端受到干扰退出或挂起！
//SIGTTOU:后台进程企图从控制终端写
#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
//SIGTTIN:后台进程企图从控制终端读
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
//SIGTSTP:控制终端（tty）上按下停止键
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
//调用fork函数的目的是使子进程不是一个进程组的头进程，这是创建新会话的必要条件
	if (0 != fork()) exit(0);
//调用setsid函数创建一个新会话
	if (-1 == setsid()) exit(0);
//SIGHUP:控制终端进程终止
	signal(SIGHUP, SIG_IGN);
//再次调用fork函数使得新的子进程不是会话的头进程，从而不能自动获得控制终端
	if (0 != fork()) exit(0);
//chdir函数：更改当前目录，成功返回0！
	if (0 != chdir("/")) exit(0);
}
#endif






























//																		server结构体的初始化
static server *server_init(void) {
	int i;

	server *srv = calloc(1, sizeof(*srv)); 
	assert(srv);
#define CLEAN(x) \
	srv->x = buffer_init(); 

	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(errorlog_buf);
	CLEAN(response_range);
	CLEAN(tmp_buf);
//为empty_string申请内存空间，并利用空字符串进行初始化
	srv->empty_string = buffer_init_string(""); 
	CLEAN(cond_check_buf);
	CLEAN(srvconf.errorlog_file);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);

	CLEAN(tmp_chunk_len);
#undef CLEAN

#define CLEAN(x) \
	srv->x = array_init();

	CLEAN(config_context);
	CLEAN(config_touched);
	CLEAN(status);
#undef CLEAN

	for (i = 0; i < FILE_CACHE_MAX; i++) {
//'(time_t)-1'的意思是未能获取日历时间，这种赋值在此也可以认为是初始化的一种方式
		srv->mtime_cache[i].mtime = (time_t)-1; 
		srv->mtime_cache[i].str = buffer_init();
	}
//获取当前的时间
	srv->cur_ts = time(NULL); 
	srv->startup_ts = srv->cur_ts;

	srv->conns = calloc(1, sizeof(*srv->conns));
	assert(srv->conns);

	srv->joblist = calloc(1, sizeof(*srv->joblist));
	assert(srv->joblist);

	srv->fdwaitqueue = calloc(1, sizeof(*srv->fdwaitqueue));
	assert(srv->fdwaitqueue);

	srv->srvconf.modules = array_init();
	srv->srvconf.modules_dir = buffer_init_string(LIBRARY_DIR);
	srv->srvconf.network_backend = buffer_init();
	srv->srvconf.upload_tempdirs = array_init();

	/* use syslog */
	srv->errorlog_fd = -1;
	srv->errorlog_mode = ERRORLOG_STDERR;

	srv->split_vals = array_init();

	return srv;
}





















//																			释放server结构体
static void server_free(server *srv) {
	size_t i;

	for (i = 0; i < FILE_CACHE_MAX; i++) {
		buffer_free(srv->mtime_cache[i].str);
	}

#define CLEAN(x) \
	buffer_free(srv->x);

	CLEAN(response_header);
	CLEAN(parse_full_path);
	CLEAN(ts_debug_str);
	CLEAN(ts_date_str);
	CLEAN(errorlog_buf);
	CLEAN(response_range);
	CLEAN(tmp_buf);
	CLEAN(empty_string);
	CLEAN(cond_check_buf);

	CLEAN(srvconf.errorlog_file);
	CLEAN(srvconf.groupname);
	CLEAN(srvconf.username);
	CLEAN(srvconf.changeroot);
	CLEAN(srvconf.bindhost);
	CLEAN(srvconf.event_handler);
	CLEAN(srvconf.pid_file);
	CLEAN(srvconf.modules_dir);
	CLEAN(srvconf.network_backend);

	CLEAN(tmp_chunk_len);
#undef CLEAN

#if 0
	fdevent_unregister(srv->ev, srv->fd);
#endif
	fdevent_free(srv->ev);

	free(srv->conns);

	if (srv->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			specific_config *s = srv->config_storage[i];

			if (!s) continue;

			buffer_free(s->document_root);
			buffer_free(s->server_name);
			buffer_free(s->server_tag);
			buffer_free(s->ssl_pemfile);
			buffer_free(s->ssl_ca_file);
			buffer_free(s->ssl_cipher_list);
			buffer_free(s->error_handler);
			buffer_free(s->errorfile_prefix);
			array_free(s->mimetypes);
#ifdef USE_OPENSSL
			SSL_CTX_free(s->ssl_ctx);
#endif
			free(s);
		}
		free(srv->config_storage);
		srv->config_storage = NULL;
	}

#define CLEAN(x) \
	array_free(srv->x);

	CLEAN(config_context);
	CLEAN(config_touched);
	CLEAN(status);
	CLEAN(srvconf.upload_tempdirs);
#undef CLEAN

	joblist_free(srv, srv->joblist);
	fdwaitqueue_free(srv, srv->fdwaitqueue);

	if (srv->stat_cache) {
		stat_cache_free(srv->stat_cache);
	}

	array_free(srv->srvconf.modules);
	array_free(srv->split_vals);

#ifdef USE_OPENSSL
	if (srv->ssl_is_init) {
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		ERR_remove_state(0);
		EVP_cleanup();
	}
#endif

	free(srv);
}




























static void show_version (void) {
#ifdef USE_OPENSSL
# define TEXT_SSL " (ssl)"
#else
# define TEXT_SSL
#endif
	char *b = PACKAGE_NAME "-" PACKAGE_VERSION TEXT_SSL \
" - a light and fast webserver\n" \
"Build-Date: " __DATE__ " " __TIME__ "\n";
;
#undef TEXT_SSL
	write(STDOUT_FILENO, b, strlen(b));
}









































static void show_features (void) {
  const char features[] = ""
#ifdef USE_SELECT
      "\t+ select (generic)\n"
#else
      "\t- select (generic)\n"
#endif
#ifdef USE_POLL
      "\t+ poll (Unix)\n"
#else
      "\t- poll (Unix)\n"
#endif
#ifdef USE_LINUX_SIGIO
      "\t+ rt-signals (Linux 2.4+)\n"
#else
      "\t- rt-signals (Linux 2.4+)\n"
#endif
#ifdef USE_LINUX_EPOLL
      "\t+ epoll (Linux 2.6)\n"
#else
      "\t- epoll (Linux 2.6)\n"
#endif
#ifdef USE_SOLARIS_DEVPOLL
      "\t+ /dev/poll (Solaris)\n"
#else
      "\t- /dev/poll (Solaris)\n"
#endif
#ifdef USE_FREEBSD_KQUEUE
      "\t+ kqueue (FreeBSD)\n"
#else
      "\t- kqueue (FreeBSD)\n"
#endif
      "\nNetwork handler:\n\n"
#if defined(USE_LINUX_SENDFILE) || defined(USE_FREEBSD_SENDFILE) || defined(USE_SOLARIS_SENDFILEV) || defined(USE_AIX_SENDFILE)
      "\t+ sendfile\n"
#else
  #ifdef USE_WRITEV
      "\t+ writev\n"
  #else
      "\t+ write\n"
  #endif
  #ifdef USE_MMAP
      "\t+ mmap support\n"
  #else
      "\t- mmap support\n"
  #endif
#endif
      "\nFeatures:\n\n"
#ifdef HAVE_IPV6
      "\t+ IPv6 support\n"
#else
      "\t- IPv6 support\n"
#endif
#if defined HAVE_ZLIB_H && defined HAVE_LIBZ
      "\t+ zlib support\n"
#else
      "\t- zlib support\n"
#endif
#if defined HAVE_BZLIB_H && defined HAVE_LIBBZ2
      "\t+ bzip2 support\n"
#else
      "\t- bzip2 support\n"
#endif
#ifdef HAVE_LIBCRYPT
      "\t+ crypt support\n"
#else
      "\t- crypt support\n"
#endif
#ifdef USE_OPENSSL
      "\t+ SSL Support\n"
#else
      "\t- SSL Support\n"
#endif
#ifdef HAVE_LIBPCRE
      "\t+ PCRE support\n"
#else
      "\t- PCRE support\n"
#endif
#ifdef HAVE_MYSQL
      "\t+ mySQL support\n"
#else
      "\t- mySQL support\n"
#endif
#if defined(HAVE_LDAP_H) && defined(HAVE_LBER_H) && defined(HAVE_LIBLDAP) && defined(HAVE_LIBLBER)
      "\t+ LDAP support\n"
#else
      "\t- LDAP support\n"
#endif
#ifdef HAVE_MEMCACHE_H
      "\t+ memcached support\n"
#else
      "\t- memcached support\n"
#endif
#ifdef HAVE_FAM_H
      "\t+ FAM support\n"
#else
      "\t- FAM support\n"
#endif
#ifdef HAVE_LUA_H
      "\t+ LUA support\n"
#else
      "\t- LUA support\n"
#endif
#ifdef HAVE_LIBXML_H
      "\t+ xml support\n"
#else
      "\t- xml support\n"
#endif
#ifdef HAVE_SQLITE3_H
      "\t+ SQLite support\n"
#else
      "\t- SQLite support\n"
#endif
#ifdef HAVE_GDBM_H
      "\t+ GDBM support\n"
#else
      "\t- GDBM support\n"
#endif
      "\n";
  show_version();
  printf("\nEvent Handlers:\n\n%s", features);
}














































static void show_help (void) {
#ifdef USE_OPENSSL
# define TEXT_SSL " (ssl)"
#else
# define TEXT_SSL
#endif
	char *b = PACKAGE_NAME "-" PACKAGE_VERSION TEXT_SSL " ("__DATE__ " " __TIME__ ")" \
" - a light and fast webserver\n" \
"usage:\n" \
" -f <name>  filename of the config-file\n" \
" -m <name>  module directory (default: "LIBRARY_DIR")\n" \
" -p         print the parsed config-file in internal form, and exit\n" \
" -t         test the config-file, and exit\n" \
" -D         don't go to background (default: go to background)\n" \
" -v         show version\n" \
" -V         show compile-time features\n" \
" -h         show this help\n" \
"\n"
;
#undef TEXT_SSL
#undef TEXT_IPV6
	write(STDOUT_FILENO, b, strlen(b));
}




































// 									****************************************下面全是main函数的执行语句*********************************************

int main (int argc, char **argv) {
	server *srv = NULL;
	int print_config = 0;
	int test_config = 0;
	int i_am_root;
	int o;
	int num_childs = 0;
	int pid_fd = -1, fd;
	size_t i;

#ifdef HAVE_GETRLIMIT
	struct rlimit rlim;
#endif




	/* for nice %b handling in strfime() */
	setlocale(LC_TIME, "C");


//server结构体srv的初始化
	if (NULL == (srv = server_init())) {
		fprintf(stderr, "did this really happen?\n");
		return -1;
	}


// 暂时设端口号为0
	srv->srvconf.port = 0;

//判断是否为管理员
#ifdef HAVE_GETUID
	i_am_root = (getuid() == 0);
#else
	i_am_root = 0;
#endif

//暂时设不进行守护化进程
	srv->srvconf.dont_daemonize = 0;






















//																本段代码主要是根据用户运行Lighttpd程序的选项参数进行不同的操作

/*
getopt()用来分析命令行参数。
参数argc和argv分别代表参数个数和内容，跟main（）函数的命令行参数是一样的。
参数 optstring为选项字符串， 告知 getopt()可以处理哪个选项以及哪个选项需要参数，如果选项字符串里的字母后接着冒号“:”，则表示还有相关的参数，全域变量optarg 即会指向此额外参数。
如果在处理期间遇到了不符合optstring指定的其他选项getopt()将显示一个错误消息，并将全域变量optarg设为“?”字符，如果不希望getopt()打印出错信息，则只要将全域变量opterr设为0即可。
*/
	while(-1 != (o = getopt(argc, argv, "f:m:hvVDpt"))) {  
		switch(o) {
		case 'f':  //指定配置文件路径
			if (config_read(srv, optarg)) {
				server_free(srv);
				return -1;
			}
			break;
//指定插件保存目录
		case 'm': 
			buffer_copy_string(srv->srvconf.modules_dir, optarg);
			break;
//打印配置信息标记			
		case 'p': print_config = 1; break; 
//测试配置信息标记		
		case 't': test_config = 1; break;  
//不进行守护化转换标记		
		case 'D': srv->srvconf.dont_daemonize = 1; break; 
//显示版本信息		
		case 'v': show_version(); return 0;
//显示特征信息		 
		case 'V': show_features(); return 0; 
//显示帮助信息		
		case 'h': show_help(); return 0; 
		default:
			show_help();
			server_free(srv);
			return -1;
		}
	}

























	if (!srv->config_storage) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"No configuration available. Try using -f option.");

		server_free(srv);
		return -1;
	}

	if (print_config) {
		data_unset *dc = srv->config_context->data[0];
		if (dc) {
			dc->print(dc, 0);
			fprintf(stdout, "\n");
		} else {
			/* shouldn't happend */
			fprintf(stderr, "global config not found\n");
		}
	}

	if (test_config) {
		printf("Syntax OK\n");
	}

	if (test_config || print_config) {
		server_free(srv);
		return 0;
	}

	/* close stdin and stdout, as they are not needed */
	openDevNull(STDIN_FILENO);
	openDevNull(STDOUT_FILENO);

	if (0 != config_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"setting default values failed");
		server_free(srv);
		return -1;
	}

	/* UID handling */
#ifdef HAVE_GETUID
	if (!i_am_root && (geteuid() == 0 || getegid() == 0)) {
		/* we are setuid-root */

		log_error_write(srv, __FILE__, __LINE__, "s",
				"Are you nuts ? Don't apply a SUID bit to this binary");

		server_free(srv);
		return -1;
	}
#endif

	/* check document-root */
	if (srv->config_storage[0]->document_root->used <= 1) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"document-root is not set\n");

		server_free(srv);

		return -1;
	}

	if (plugins_load(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"loading plugins finally failed");

		plugins_free(srv);
		server_free(srv);

		return -1;
	}

	/* open pid file BEFORE chroot */
	if (srv->srvconf.pid_file->used) {
		if (-1 == (pid_fd = open(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
			struct stat st;
			if (errno != EEXIST) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
					"opening pid-file failed:", srv->srvconf.pid_file, strerror(errno));
				return -1;
			}

			if (0 != stat(srv->srvconf.pid_file->ptr, &st)) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"stating existing pid-file failed:", srv->srvconf.pid_file, strerror(errno));
			}

			if (!S_ISREG(st.st_mode)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"pid-file exists and isn't regular file:", srv->srvconf.pid_file);
				return -1;
			}

			if (-1 == (pid_fd = open(srv->srvconf.pid_file->ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"opening pid-file failed:", srv->srvconf.pid_file, strerror(errno));
				return -1;
			}
		}
	}

	if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
		/* select limits itself
		 *
		 * as it is a hard limit and will lead to a segfault we add some safety
		 * */
		srv->max_fds = FD_SETSIZE - 200;
	} else {
		srv->max_fds = 4096;
	}



















	if (i_am_root) {
		struct group *grp = NULL;
		struct passwd *pwd = NULL;
		int use_rlimit = 1;

#ifdef HAVE_VALGRIND_VALGRIND_H
		if (RUNNING_ON_VALGRIND) use_rlimit = 0;
#endif

#ifdef HAVE_GETRLIMIT
		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_error_write(srv, __FILE__, __LINE__,
					"ss", "couldn't get 'max filedescriptors'",
					strerror(errno));
			return -1;
		}

		if (use_rlimit && srv->srvconf.max_fds) {
			/* set rlimits */

			rlim.rlim_cur = srv->srvconf.max_fds;
			rlim.rlim_max = srv->srvconf.max_fds;

			if (0 != setrlimit(RLIMIT_NOFILE, &rlim)) {
				log_error_write(srv, __FILE__, __LINE__,
						"ss", "couldn't set 'max filedescriptors'",
						strerror(errno));
				return -1;
			}
		}

		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			srv->max_fds = rlim.rlim_cur < FD_SETSIZE - 200 ? rlim.rlim_cur : FD_SETSIZE - 200;
		} else {
			srv->max_fds = rlim.rlim_cur;
		}

		/* set core file rlimit, if enable_cores is set */
		if (use_rlimit && srv->srvconf.enable_cores && getrlimit(RLIMIT_CORE, &rlim) == 0) {
			rlim.rlim_cur = rlim.rlim_max;
			setrlimit(RLIMIT_CORE, &rlim);
		}
#endif
		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			/* don't raise the limit above FD_SET_SIZE */
			if (srv->max_fds > FD_SETSIZE - 200) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"can't raise max filedescriptors above",  FD_SETSIZE - 200,
						"if event-handler is 'select'. Use 'poll' or something else or reduce server.max-fds.");
				return -1;
			}
		}


#ifdef HAVE_PWD_H
		/* set user and group */
		if (srv->srvconf.username->used) {
			if (NULL == (pwd = getpwnam(srv->srvconf.username->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"can't find username", srv->srvconf.username);
				return -1;
			}

			if (pwd->pw_uid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"I will not set uid to 0\n");
				return -1;
			}
		}

		if (srv->srvconf.groupname->used) {
			if (NULL == (grp = getgrnam(srv->srvconf.groupname->ptr))) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
					"can't find groupname", srv->srvconf.groupname);
				return -1;
			}
			if (grp->gr_gid == 0) {
				log_error_write(srv, __FILE__, __LINE__, "s",
						"I will not set gid to 0\n");
				return -1;
			}
		}
#endif
//获取那些创建监听套接字必须的用户配置信息，并调用network_server_init函数创建监听套接字描述符
		/* we need root-perms for port < 1024 */
		if (0 != network_init(srv)) {
			plugins_free(srv);
			server_free(srv);

			return -1;
		}
#ifdef HAVE_PWD_H
		/* 
		 * Change group before chroot, when we have access
		 * to /etc/group
		 * */
		if (srv->srvconf.groupname->used) {
			setgid(grp->gr_gid);
			setgroups(0, NULL);
			if (srv->srvconf.username->used) {
				initgroups(srv->srvconf.username->ptr, grp->gr_gid);
			}
		}
#endif
#ifdef HAVE_CHROOT
		if (srv->srvconf.changeroot->used) {
			tzset();

			if (-1 == chroot(srv->srvconf.changeroot->ptr)) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "chroot failed: ", strerror(errno));
				return -1;
			}
			if (-1 == chdir("/")) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "chdir failed: ", strerror(errno));
				return -1;
			}
		}
#endif
#ifdef HAVE_PWD_H
		/* drop root privs */
		if (srv->srvconf.username->used) {
			setuid(pwd->pw_uid);
		}
#endif
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_DUMPABLE)
		/**
		 * on IRIX 6.5.30 they have prctl() but no DUMPABLE
		 */
		if (srv->srvconf.enable_cores) {
			prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		}
#endif
	} 


	else {

#ifdef HAVE_GETRLIMIT
		if (0 != getrlimit(RLIMIT_NOFILE, &rlim)) {
			log_error_write(srv, __FILE__, __LINE__,
					"ss", "couldn't get 'max filedescriptors'",
					strerror(errno));
			return -1;
		}

		/**
		 * we are not root can can't increase the fd-limit, but we can reduce it
		 */
		if (srv->srvconf.max_fds && srv->srvconf.max_fds < rlim.rlim_cur) {
			/* set rlimits */

			rlim.rlim_cur = srv->srvconf.max_fds;

			if (0 != setrlimit(RLIMIT_NOFILE, &rlim)) {
				log_error_write(srv, __FILE__, __LINE__,
						"ss", "couldn't set 'max filedescriptors'",
						strerror(errno));
				return -1;
			}
		}

		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			srv->max_fds = rlim.rlim_cur < FD_SETSIZE - 200 ? rlim.rlim_cur : FD_SETSIZE - 200;
		} else {
			srv->max_fds = rlim.rlim_cur;
		}

		/* set core file rlimit, if enable_cores is set */
		if (srv->srvconf.enable_cores && getrlimit(RLIMIT_CORE, &rlim) == 0) {
			rlim.rlim_cur = rlim.rlim_max;
			setrlimit(RLIMIT_CORE, &rlim);
		}

#endif
		if (srv->event_handler == FDEVENT_HANDLER_SELECT) {
			/* don't raise the limit above FD_SET_SIZE */
			if (srv->max_fds > FD_SETSIZE - 200) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"can't raise max filedescriptors above",  FD_SETSIZE - 200,
						"if event-handler is 'select'. Use 'poll' or something else or reduce server.max-fds.");
				return -1;
			}
		}
//获取那些创建监听套接字必须的用户配置信息，并调用network_server_init函数创建监听套接字描述符
		if (0 != network_init(srv)) {
			plugins_free(srv);
			server_free(srv);

			return -1;
		}
	}














	/* set max-conns */
	if (srv->srvconf.max_conns > srv->max_fds) {
		/* we can't have more connections than max-fds */
		srv->max_conns = srv->max_fds;
	} else if (srv->srvconf.max_conns) {
		/* otherwise respect the wishes of the user */
		srv->max_conns = srv->srvconf.max_conns;
	} else {
		/* or use the default */
		srv->max_conns = srv->max_fds;
	}

	if (HANDLER_GO_ON != plugins_call_init(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Initialization of plugins failed. Going down.");

		plugins_free(srv);
		network_close(srv);
		server_free(srv);

		return -1;
	}

#ifdef HAVE_FORK
	/* network is up, let's deamonize ourself */
	if (srv->srvconf.dont_daemonize == 0) daemonize(); //如果srv->srvconf.dont_daemonize为0，则进行进程守护化！
#endif

	srv->gid = getgid();
	srv->uid = getuid();

	/* write pid file */
	if (pid_fd != -1) {
		buffer_copy_long(srv->tmp_buf, getpid());
		buffer_append_string_len(srv->tmp_buf, CONST_STR_LEN("\n"));
		write(pid_fd, srv->tmp_buf->ptr, srv->tmp_buf->used - 1);
		close(pid_fd);
		pid_fd = -1;
	}

	/* Close stderr ASAP in the child process to make sure that nothing
	 * is being written to that fd which may not be valid anymore. */
	if (-1 == log_error_open(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Opening errorlog failed. Going down.");

		plugins_free(srv);
		network_close(srv);
		server_free(srv);
		return -1;
	}

	if (HANDLER_GO_ON != plugins_call_set_defaults(srv)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Configuration of plugins failed. Going down.");

		plugins_free(srv);
		network_close(srv);
		server_free(srv);

		return -1;
	}

	/* dump unused config-keys */
	for (i = 0; i < srv->config_context->used; i++) {
		array *config = ((data_config *)srv->config_context->data[i])->value;
		size_t j;

		for (j = 0; config && j < config->used; j++) {
			data_unset *du = config->data[j];

			/* all var.* is known as user defined variable */
			if (strncmp(du->key->ptr, "var.", sizeof("var.") - 1) == 0) {
				continue;
			}

			if (NULL == array_get_element(srv->config_touched, du->key->ptr)) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"WARNING: unknown config-key:",
						du->key,
						"(ignored)");
			}
		}
	}

	if (srv->config_unsupported) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"Configuration contains unsupported keys. Going down.");
	}

	if (srv->config_deprecated) {
		log_error_write(srv, __FILE__, __LINE__, "s",
				"Configuration contains deprecated keys. Going down.");
	}

	if (srv->config_unsupported || srv->config_deprecated) {
		plugins_free(srv);
		network_close(srv);
		server_free(srv);

		return -1;
	}



































//																				Lighttpd信号处理机制
//父进程对Lighttpd的信号进行处理，以后的子进程延用父进程的信号处理方法
//相比signal函数而言，sigaction函数更有优势，因此程序利用条件编译宏首先判断是否可以使用sigaction函数，否则使用signal函数
//各信号的处理方法都是标志其相关的变量，以便需要处理的进程检查，并处理信号

//定义用于sigaction函数的sigaction结构体act
#ifdef HAVE_SIGACTION
	struct sigaction act;
#endif

//设置定时器的启动时间和产生信号时间
#ifdef USE_ALARM
	struct itimerval interval;
//设置计时器多少秒后启动的时间
	interval.it_interval.tv_sec = 1;
	interval.it_interval.tv_usec = 0;
//设置每隔多少秒产生一个ALARM信号
	interval.it_value.tv_sec = 1;
	interval.it_value.tv_usec = 0;
#endif

//使用sigaction信号设置函数
#ifdef HAVE_SIGACTION
//初始化sigaction结构的act变量
	memset(&act, 0, sizeof(act));
//将SIGPIPE,SIGUSR1信号忽略
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
//defined函数作用：检查某个名称的常量是否存在
//SA_SIGINFO有定义，则使用sa_sigaction方式的sigaction_handler信号处理函数
# if defined(SA_SIGINFO)
//使用sigaction_handler信号处理函数
	act.sa_sigaction = sigaction_handler;
//sa_mask的作用是再调用信号处理函数时屏蔽指定的信号，调用完后恢复指定信号
//初始化清零信号集sa_mask（所有信号在信号处理函数调用时没有被屏蔽）
	sigemptyset(&act.sa_mask);
//将sa_flags标志为SA_SIGINFO说明调用sa_sigaction方式，默认是调用sa_handler方式
	act.sa_flags = SA_SIGINFO;
//SA_SIGINFO没有定义，则使用sa_handler方式的sigaction_handler信号处理函数
# else
//使用signal_handler信号处理函数
	act.sa_handler = signal_handler;
//初始化清零信号集sa_mask（所有信号在信号处理函数调用时没有被屏蔽）
	sigemptyset(&act.sa_mask);
//调用sa_handler方式
	act.sa_flags = 0;
# endif
//分别使用sigaction信号设置函数为下述信号设置sigaction_handler信号处理函数
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

//使用signal信号设置函数
#elif defined(HAVE_SIGNAL)
//将SIGPIPE,SIGUSR1信号忽略
	signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
//分别为下述信号设置signal_handler信号处理函数
	signal(SIGALRM, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP,  signal_handler);
	signal(SIGCHLD,  signal_handler);
	signal(SIGINT,  signal_handler);
#endif

//it_interval秒后启动计时器，并每秒发送一个ALARM信号
#ifdef USE_ALARM
//将信号SIGALRM设置为signal_handler函数处理
	signal(SIGALRM, signal_handler);
//调用setitimer函数启动计时器
	if (setitimer(ITIMER_REAL, &interval, NULL)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "setting timer failed");
		return -1;
	}
//调用getitimer函数获取计时器的值
	getitimer(ITIMER_REAL, &interval);
#endif


































//																由单进程运行的Lighttpd开始创建监控进程（watcher）和一些工作进程(workers)


#ifdef HAVE_FORK
//num_childs的值为可创建的工作进程数目，而初始化srv->srvconf.max_worker默认值为0，即没有监控进程，只有一个工作进程！
	num_childs = srv->srvconf.max_worker;
//若num_childs != 0则创建一个监控进程和num_childs个工作进程
	if (num_childs > 0) {
//child用于标示该进程是监控进程（0）还是工作进程（1）	
//父进程标示为监控进程	
		int child = 0;
//监控进程开始创建工作进程，当遇到srv_shutdown或graceful_shutdown为1时，Lighttpd程序退出！
		while (!child && !srv_shutdown && !graceful_shutdown) {
//若可创建工作进程数（num_childs）大于0，则继续创建工作进程
			if (num_childs > 0) {
//调用fork函数创建工作进程（子进程）
				switch (fork()) {
//创建失败返回－1
				case -1:
					return -1;
//创建成功，工作进程（子进程）执行部分
				case 0:
//子进程标示为工作进程并执行相应的操作
					child = 1;
					break;
				default:
//监控进程将可创建进程数目（num_childs）减1，并回到while循环
					num_childs--;
					break;
				}
			} 
//当全部工作进程创建完后，监控进程调用wait函数阻塞自己，等待工作进程的退出，将可创建进程数目（num_childs）加1，并采集相关工作进程的信息
			else {
				int status;
				if (-1 != wait(&status)) {
					num_childs++;
				} 
				else {
					switch (errno) {
//监控进程在调用wait阻塞时发生中断
					case EINTR:
//handle_sig_hup为1时，产生了SIGHUP信号，web服务器应该将此信号解释为reset；而Lighttpd只是重新打开log日志文件，并将SIGHUP发送给所在组的全部进程
						if (handle_sig_hup) {
							handle_sig_hup = 0;
//重新打开log日志文件
							log_error_cycle(srv);
//forwarded_sig_hup标志用来判断之前是否已经处理过SIGHUP信号，值为0时表示没处理过，值为1时表示处理过；防止信号循环处理
							if (!forwarded_sig_hup) {
								forwarded_sig_hup = 1;
//当kill的第一个参数为0时，将信号传给和目前进程相同进程组的所有进程
								kill(0, SIGHUP);
							}
						}
						break;
					default:
						break;
					}
				}
			}
		}
//监控进程执行Lighttpd退出的相关操作！
		if (!child) {
//监控进程将程序终止信号发送给所在组的全部进程
			if (graceful_shutdown) {
				kill(0, SIGINT);
			} else if (srv_shutdown) {
				kill(0, SIGTERM);
			}
//关闭日志,释放网络连接资源，插件资源，内存资源等
			log_error_close(srv);
			network_close(srv);
			connections_free(srv);
			plugins_free(srv);
			server_free(srv);
			return 0;
		}
	}
#endif




























// 																				下面是工作进程(workers)进行相关操作





//初始化fdevents结构体，进行i/o模式的搭建
	if (NULL == (srv->ev = fdevent_init(srv->max_fds + 1, srv->event_handler))) {
		log_error_write(srv, __FILE__, __LINE__,
				"s", "fdevent_init failed");
		return -1;
	}


















	

//将所有的网络监听描述符（监听socket）注册到事件处理器中 
	if (0 != network_register_fdevents(srv)) {
		plugins_free(srv);
		network_close(srv);
		server_free(srv);

		return -1;
	}












	/* might fail if user is using fam (not gamin) and famd isn't running */
	if (NULL == (srv->stat_cache = stat_cache_init())) {
		log_error_write(srv, __FILE__, __LINE__, "s",
			"stat-cache could not be setup, dieing.");
		return -1;
	}

#ifdef HAVE_FAM_H
	/* setup FAM */
	if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
		if (0 != FAMOpen2(srv->stat_cache->fam, "lighttpd")) {
			log_error_write(srv, __FILE__, __LINE__, "s",
					 "could not open a fam connection, dieing.");
			return -1;
		}
#ifdef HAVE_FAMNOEXISTS
		FAMNoExists(srv->stat_cache->fam);
#endif

		srv->stat_cache->fam_fcce_ndx = -1;
		fdevent_register(srv->ev, FAMCONNECTION_GETFD(srv->stat_cache->fam), stat_cache_handle_fdevent, NULL);
		fdevent_event_add(srv->ev, &(srv->stat_cache->fam_fcce_ndx), FAMCONNECTION_GETFD(srv->stat_cache->fam), FDEVENT_IN);
	}
#endif


	/* get the current number of FDs */
	srv->cur_fds = open("/dev/null", O_RDONLY);
	close(srv->cur_fds);











//设置网络监听描述符的socket选项
	for (i = 0; i < srv->srv_sockets.used; i++) {
		server_socket *srv_socket = srv->srv_sockets.ptr[i];
		if (-1 == fdevent_fcntl_set(srv->ev, srv_socket->fd)) {
			log_error_write(srv, __FILE__, __LINE__, "ss", "fcntl failed:", strerror(errno));
			return -1;
		}
	}












	/* main-loop */
	while (!srv_shutdown) {
		int n;
		size_t ndx;
		time_t min_ts;

		if (handle_sig_hup) {
			handler_t r;

			/* reset notification */
			handle_sig_hup = 0;


			/* cycle logfiles */

			switch(r = plugins_call_handle_sighup(srv)) {
			case HANDLER_GO_ON:
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "sd", "sighup-handler return with an error", r);
				break;
			}

			if (-1 == log_error_cycle(srv)) {
				log_error_write(srv, __FILE__, __LINE__, "s", "cycling errorlog failed, dying");

				return -1;
			} else {
#ifdef HAVE_SIGACTION
				log_error_write(srv, __FILE__, __LINE__, "sdsd", 
					"logfiles cycled UID =",
					last_sighup_info.si_uid,
					"PID =",
					last_sighup_info.si_pid);
#else
				log_error_write(srv, __FILE__, __LINE__, "s", 
					"logfiles cycled");
#endif
			}
		}

		if (handle_sig_alarm) {
			/* a new second */

#ifdef USE_ALARM
			/* reset notification */
			handle_sig_alarm = 0;
#endif

			/* get current time */
			min_ts = time(NULL);

			if (min_ts != srv->cur_ts) {
				int cs = 0;
				connections *conns = srv->conns;
				handler_t r;

				switch(r = plugins_call_handle_trigger(srv)) {
				case HANDLER_GO_ON:
					break;
				case HANDLER_ERROR:
					log_error_write(srv, __FILE__, __LINE__, "s", "one of the triggers failed");
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "d", r);
					break;
				}

				/* trigger waitpid */
				srv->cur_ts = min_ts;

				/* cleanup stat-cache */
				stat_cache_trigger_cleanup(srv);
				/**
				 * check all connections for timeouts
				 *
				 */
				for (ndx = 0; ndx < conns->used; ndx++) {
					int changed = 0;
					connection *con;
					int t_diff;

					con = conns->ptr[ndx];

					if (con->state == CON_STATE_READ ||
					    con->state == CON_STATE_READ_POST) {
						if (con->request_count == 1) {
							if (srv->cur_ts - con->read_idle_ts > con->conf.max_read_idle) {
								/* time - out */
#if 0
								log_error_write(srv, __FILE__, __LINE__, "sd",
										"connection closed - read-timeout:", con->fd);
#endif
								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						} else {
							if (srv->cur_ts - con->read_idle_ts > con->conf.max_keep_alive_idle) {
								/* time - out */
#if 0
								log_error_write(srv, __FILE__, __LINE__, "sd",
										"connection closed - read-timeout:", con->fd);
#endif
								connection_set_state(srv, con, CON_STATE_ERROR);
								changed = 1;
							}
						}
					}

					if ((con->state == CON_STATE_WRITE) &&
					    (con->write_request_ts != 0)) {
#if 0
						if (srv->cur_ts - con->write_request_ts > 60) {
							log_error_write(srv, __FILE__, __LINE__, "sdd",
									"connection closed - pre-write-request-timeout:", con->fd, srv->cur_ts - con->write_request_ts);
						}
#endif

						if (srv->cur_ts - con->write_request_ts > con->conf.max_write_idle) {
							/* time - out */
#if 1
							log_error_write(srv, __FILE__, __LINE__, "sbsosds",
									"NOTE: a request for",
									con->request.uri,
									"timed out after writing",
									con->bytes_written,
									"bytes. We waited",
									(int)con->conf.max_write_idle,
									"seconds. If this a problem increase server.max-write-idle");
#endif
							connection_set_state(srv, con, CON_STATE_ERROR);
							changed = 1;
						}
					}
					/* we don't like div by zero */
					if (0 == (t_diff = srv->cur_ts - con->connection_start)) t_diff = 1;

					if (con->traffic_limit_reached &&
					    (con->conf.kbytes_per_second == 0 ||
					     ((con->bytes_written / t_diff) < con->conf.kbytes_per_second * 1024))) {
						/* enable connection again */
						con->traffic_limit_reached = 0;

						changed = 1;
					}

					if (changed) {
						connection_state_machine(srv, con);
					}
					con->bytes_written_cur_second = 0;
					*(con->conf.global_bytes_per_second_cnt_ptr) = 0;

#if 0
					if (cs == 0) {
						fprintf(stderr, "connection-state: ");
						cs = 1;
					}

					fprintf(stderr, "c[%d,%d]: %s ",
						con->fd,
						con->fcgi.fd,
						connection_get_state(con->state));
#endif
				}

				if (cs == 1) fprintf(stderr, "\n");
			}
		}

		if (srv->sockets_disabled) {
			/* our server sockets are disabled, why ? */

			if ((srv->cur_fds + srv->want_fds < srv->max_fds * 0.8) && /* we have enough unused fds */
			    (srv->conns->used < srv->max_conns * 0.9) &&
			    (0 == graceful_shutdown)) {
				for (i = 0; i < srv->srv_sockets.used; i++) {
					server_socket *srv_socket = srv->srv_sockets.ptr[i];
					fdevent_event_add(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd, FDEVENT_IN);
				}

				log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets enabled again");

				srv->sockets_disabled = 0;
			}
		} else {
			if ((srv->cur_fds + srv->want_fds > srv->max_fds * 0.9) || /* out of fds */
			    (srv->conns->used > srv->max_conns) || /* out of connections */
			    (graceful_shutdown)) { /* graceful_shutdown */

				/* disable server-fds */

				for (i = 0; i < srv->srv_sockets.used; i++) {
					server_socket *srv_socket = srv->srv_sockets.ptr[i];
					fdevent_event_del(srv->ev, &(srv_socket->fde_ndx), srv_socket->fd);

					if (graceful_shutdown) {
						/* we don't want this socket anymore,
						 *
						 * closing it right away will make it possible for
						 * the next lighttpd to take over (graceful restart)
						 *  */

						fdevent_unregister(srv->ev, srv_socket->fd);
						close(srv_socket->fd);
						srv_socket->fd = -1;

						/* network_close() will cleanup after us */

						if (srv->srvconf.pid_file->used &&
						    srv->srvconf.changeroot->used == 0) {
							if (0 != unlink(srv->srvconf.pid_file->ptr)) {
								if (errno != EACCES && errno != EPERM) {
									log_error_write(srv, __FILE__, __LINE__, "sbds",
											"unlink failed for:",
											srv->srvconf.pid_file,
											errno,
											strerror(errno));
								}
							}
						}
					}
				}

				if (graceful_shutdown) {
					log_error_write(srv, __FILE__, __LINE__, "s", "[note] graceful shutdown started");
				} else if (srv->conns->used > srv->max_conns) {
					log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets disabled, connection limit reached");
				} else {
					log_error_write(srv, __FILE__, __LINE__, "s", "[note] sockets disabled, out-of-fds");
				}

				srv->sockets_disabled = 1;
			}
		}

		if (graceful_shutdown && srv->conns->used == 0) {
			/* we are in graceful shutdown phase and all connections are closed
			 * we are ready to terminate without harming anyone */
			srv_shutdown = 1;
		}

		/* we still have some fds to share */
		if (srv->want_fds) {
			/* check the fdwaitqueue for waiting fds */
			int free_fds = srv->max_fds - srv->cur_fds - 16;
			connection *con;

			for (; free_fds > 0 && NULL != (con = fdwaitqueue_unshift(srv, srv->fdwaitqueue)); free_fds--) {
				connection_state_machine(srv, con);

				srv->want_fds--;
			}
		}













// 														工作进程进行调用fdevent_poll进行相对应的i/o模型select阻塞

//n为返回待处理的事件数目
		if ((n = fdevent_poll(srv->ev, 1000)) > 0) {
			/* n is the number of events */
			int revents;
			int fd_ndx;
#if 0
			if (n > 0) {
				log_error_write(srv, __FILE__, __LINE__, "sd",
						"polls:", n);
			}
#endif
			fd_ndx = -1;
//do－while中处理待处理的事件
			do {
				fdevent_handler handler;
				void *context;
				handler_t r;
//获取下一个（第一个fd_ndx＝－1）待处理的事件的索引
				fd_ndx  = fdevent_event_next_fdndx (srv->ev, fd_ndx);
// 获取待处理事件的类型
				revents = fdevent_event_get_revent (srv->ev, fd_ndx);
//获取待处理事件的描述符
				fd      = fdevent_event_get_fd     (srv->ev, fd_ndx);
//获取待处理事件的回调函数
				handler = fdevent_get_handler(srv->ev, fd);
//获取待处理事件的相关的上下文
				context = fdevent_get_context(srv->ev, fd);

				/* connection_handle_fdevent needs a joblist_append */
#if 0
				log_error_write(srv, __FILE__, __LINE__, "sdd",
						"event for", fd, revents);
#endif
/*
	回调函数被调用，参数srv为server结构体变量，存储服务进程的大部分信息，context为server_socket结构体变量，保存该监听套接口的相关信息，revents
	表示发生的事件类型，回调函数handler在I/O复用监控管理事件注册函数network_register_fdevents()被赋值指向函数network_server_handle_fdevent()。
*/
//调用回调函数对待处理事件进行处理
				switch (r = (*handler)(srv, context, revents)) {
				case HANDLER_FINISHED:
				case HANDLER_GO_ON:
				case HANDLER_WAIT_FOR_EVENT:
				case HANDLER_WAIT_FOR_FD:
					break;
				case HANDLER_ERROR:
					/* should never happen */
					SEGFAULT();
					break;
				default:
					log_error_write(srv, __FILE__, __LINE__, "d", r);
					break;
				}
			} while (--n > 0);
		} 

//若调用fdevent_poll进行相对应的i/o模型select阻塞不是被中断，则报错
		else if (n < 0 && errno != EINTR) {
			log_error_write(srv, __FILE__, __LINE__, "ss",
					"fdevent_poll failed:",
					strerror(errno));
		}





		for (ndx = 0; ndx < srv->joblist->used; ndx++) {
			connection *con = srv->joblist->ptr[ndx];
			handler_t r;

			connection_state_machine(srv, con);

			switch(r = plugins_call_handle_joblist(srv, con)) {
			case HANDLER_FINISHED:
			case HANDLER_GO_ON:
				break;
			default:
				log_error_write(srv, __FILE__, __LINE__, "d", r);
				break;
			}

			con->in_joblist = 0;
		}

		srv->joblist->used = 0;
	}//工作进程的主循环结束






	if (srv->srvconf.pid_file->used &&
	    srv->srvconf.changeroot->used == 0 &&
	    0 == graceful_shutdown) {
		if (0 != unlink(srv->srvconf.pid_file->ptr)) {
			if (errno != EACCES && errno != EPERM) {
				log_error_write(srv, __FILE__, __LINE__, "sbds",
						"unlink failed for:",
						srv->srvconf.pid_file,
						errno,
						strerror(errno));
			}
		}
	}


#ifdef HAVE_SIGACTION
	log_error_write(srv, __FILE__, __LINE__, "sdsd", 
			"server stopped by UID =",
			last_sigterm_info.si_uid,
			"PID =",
			last_sigterm_info.si_pid);
#else
	log_error_write(srv, __FILE__, __LINE__, "s", 
			"server stopped");
#endif

	/* clean-up */
	log_error_close(srv);
	network_close(srv);
	connections_free(srv);
	plugins_free(srv);
	server_free(srv);

	return 0;
}
