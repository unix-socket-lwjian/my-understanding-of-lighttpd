#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include "stream.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sys-mmap.h"

#ifndef O_BINARY
# define O_BINARY 0
#endif

int stream_open(stream *f, buffer *fn) { //打开文件并map到内存（起始地址和内存长度存储在stream结构体参数f内），出错返回-1；
	struct stat st;
#ifdef HAVE_MMAP
	int fd;
#elif defined __WIN32
	HANDLE *fh, *mh;
	void *p;
#endif

	f->start = NULL;

	if (-1 == stat(fn->ptr, &st)) { //获取指定文件属性
		return -1;
	}

	f->size = st.st_size;

#ifdef HAVE_MMAP
	if (-1 == (fd = open(fn->ptr, O_RDONLY | O_BINARY))) {
		return -1;
	}

	f->start = mmap(0, f->size, PROT_READ, MAP_SHARED, fd, 0); //映射

	close(fd); //关闭文件

	if (MAP_FAILED == f->start) { //映射失败
		return -1;
	}

#elif defined __WIN32 //windows环境
	fh = CreateFile(fn->ptr,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_READONLY,
			NULL);

	if (!fh) return -1;

	mh = CreateFileMapping( fh,
			NULL,
			PAGE_READONLY,
			(sizeof(off_t) > 4) ? f->size >> 32 : 0,
			f->size & 0xffffffff,
			NULL);

	if (!mh) {
/*
		LPVOID lpMsgBuf;
		FormatMessage(
		        FORMAT_MESSAGE_ALLOCATE_BUFFER |
		        FORMAT_MESSAGE_FROM_SYSTEM,
		        NULL,
		        GetLastError(),
		        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		        (LPTSTR) &lpMsgBuf,
		        0, NULL );
*/
		return -1;
	}

	p = MapViewOfFile(mh,
			FILE_MAP_READ,
			0,
			0,
			0);
	CloseHandle(mh);
	CloseHandle(fh);

	f->start = p;
#else
# error no mmap found
#endif

	return 0;
}

int stream_close(stream *f) { //关闭文件内存映射
#ifdef HAVE_MMAP
	if (f->start) munmap(f->start, f->size);
#elif defined(__WIN32)
	if (f->start) UnmapViewOfFile(f->start);
#endif

	f->start = NULL;

	return 0;
}
