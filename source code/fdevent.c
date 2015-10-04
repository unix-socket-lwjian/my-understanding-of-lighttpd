#include <sys/types.h>

#include "settings.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include "fdevent.h"
#include "buffer.h"












//初始化fdevents结构体，并返回给用户
fdevents *fdevent_init(size_t maxfds, fdevent_handler_t type) {
	fdevents *ev;
	ev = calloc(1, sizeof(*ev));
	ev->fdarray = calloc(maxfds, sizeof(*ev->fdarray));
	ev->maxfds = maxfds;

// fdevent_xxxx_init对相应的i/o模型的函数指针赋值
	switch(type) {
	case FDEVENT_HANDLER_POLL:
		if (0 != fdevent_poll_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler poll failed\n",
				__FILE__, __LINE__);

			return NULL;
		}
		break;
	case FDEVENT_HANDLER_SELECT:
		if (0 != fdevent_select_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler select failed\n",
				__FILE__, __LINE__);
			return NULL;
		}
		break;
	case FDEVENT_HANDLER_LINUX_RTSIG:
		if (0 != fdevent_linux_rtsig_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler linux-rtsig failed, try to set server.event-handler = \"poll\" or \"select\"\n",
				__FILE__, __LINE__);
			return NULL;
		}
		break;
	case FDEVENT_HANDLER_LINUX_SYSEPOLL:
		if (0 != fdevent_linux_sysepoll_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler linux-sysepoll failed, try to set server.event-handler = \"poll\" or \"select\"\n",
				__FILE__, __LINE__);
			return NULL;
		}
		break;
	case FDEVENT_HANDLER_SOLARIS_DEVPOLL:
		if (0 != fdevent_solaris_devpoll_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler solaris-devpoll failed, try to set server.event-handler = \"poll\" or \"select\"\n",
				__FILE__, __LINE__);
			return NULL;
		}
		break;
	case FDEVENT_HANDLER_FREEBSD_KQUEUE:
		if (0 != fdevent_freebsd_kqueue_init(ev)) {
			fprintf(stderr, "%s.%d: event-handler freebsd-kqueue failed, try to set server.event-handler = \"poll\" or \"select\"\n",
				__FILE__, __LINE__);
			return NULL;
		}
		break;
	default:
		fprintf(stderr, "%s.%d: event-handler is unknown, try to set server.event-handler = \"poll\" or \"select\"\n",
			__FILE__, __LINE__);
		return NULL;
	}

	return ev;
}






















//释放某个fdevents结构体
void fdevent_free(fdevents *ev) {
	size_t i;
	if (!ev) return;

	if (ev->free) ev->free(ev);

	for (i = 0; i < ev->maxfds; i++) {
		if (ev->fdarray[i]) free(ev->fdarray[i]);
	}

	free(ev->fdarray);
	free(ev);
}














//重置某个fdevents
int fdevent_reset(fdevents *ev) {
	if (ev->reset) return ev->reset(ev);

	return 0;
}




//创建并初始化一个描述符节点，并返回
fdnode *fdnode_init() {
	fdnode *fdn;

	fdn = calloc(1, sizeof(*fdn));
	fdn->fd = -1;
	return fdn;
}










//释放某个描述符节点
void fdnode_free(fdnode *fdn) {
	free(fdn);
}











//将某个描述符节点注册到i/o事件处理器中
int fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx) {
	fdnode *fdn;

	fdn = fdnode_init();
	fdn->handler = handler;
	fdn->fd      = fd;
	fdn->ctx     = ctx;

	ev->fdarray[fd] = fdn;

	return 0;
}










//i/o事件处理器中注销某个描述符节点
int fdevent_unregister(fdevents *ev, int fd) {
	fdnode *fdn;
        if (!ev) return 0;
	fdn = ev->fdarray[fd];

	fdnode_free(fdn);

	ev->fdarray[fd] = NULL;

	return 0;
}


























//从fdevents中删除一个fd描述符
int fdevent_event_del(fdevents *ev, int *fde_ndx, int fd) {
	int fde = fde_ndx ? *fde_ndx : -1;

	if (ev->event_del) fde = ev->event_del(ev, fde, fd);

	if (fde_ndx) *fde_ndx = fde;

	return 0;
}



















//向fdevents中添加一个描述符fd，events表示对这描述符关心的事件
int fdevent_event_add(fdevents *ev, int *fde_ndx, int fd, int events) {
	int fde = fde_ndx ? *fde_ndx : -1;

	if (ev->event_add) fde = ev->event_add(ev, fde, fd, events);

	if (fde_ndx) *fde_ndx = fde;

	return 0;
}



















//轮询等待(即内部调用相应i/o模型的select进行阻塞)，超时时间由timeout_ms（单位为微秒）指定
int fdevent_poll(fdevents *ev, int timeout_ms) {
	if (ev->poll == NULL) SEGFAULT();
	return ev->poll(ev, timeout_ms);
}














//根据描述符fd在fdevents中的fdarray中的索引index，获取该描述符目前关心的事件
int fdevent_event_get_revent(fdevents *ev, size_t ndx) {
	if (ev->event_get_revent == NULL) SEGFAULT();

	return ev->event_get_revent(ev, ndx);
}












//根据描述符fd在fdevents中的fdarray中的索引index，获取对应的描述符
int fdevent_event_get_fd(fdevents *ev, size_t ndx) {
	if (ev->event_get_fd == NULL) SEGFAULT();

	return ev->event_get_fd(ev, ndx);
}











//获取某描述符的待处理事件的回调函数
fdevent_handler fdevent_get_handler(fdevents *ev, int fd) {
	if (ev->fdarray[fd] == NULL) SEGFAULT();
	if (ev->fdarray[fd]->fd != fd) SEGFAULT();

	return ev->fdarray[fd]->handler;
}












//获得某描述符的相关上下文
void * fdevent_get_context(fdevents *ev, int fd) {
	if (ev->fdarray[fd] == NULL) SEGFAULT();
	if (ev->fdarray[fd]->fd != fd) SEGFAULT();

	return ev->fdarray[fd]->ctx;
}




















//设置某个描述符socket的套接字选项
int fdevent_fcntl_set(fdevents *ev, int fd) {
#ifdef FD_CLOEXEC
	/* close fd on exec (cgi) */
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	if ((ev) && (ev->fcntl_set)) return ev->fcntl_set(ev, fd);
#ifdef O_NONBLOCK
	return fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);
#else
	return 0;
#endif
}















//获取下一个需要进行处理的描述符fd在fdarray中的索引index
int fdevent_event_next_fdndx(fdevents *ev, int ndx) {
	if (ev->event_next_fdndx) return ev->event_next_fdndx(ev, ndx);

	return -1;
}

