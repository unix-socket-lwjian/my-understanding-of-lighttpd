/**
 * the network chunk-API
 *
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "chunk.h"





















//初始化并返回一个chunkqueue结构体cq
chunkqueue *chunkqueue_init(void) {
	chunkqueue *cq;

	cq = calloc(1, sizeof(*cq));

	cq->first = NULL;
	cq->last = NULL;

	cq->unused = NULL;

	return cq;
}


















//初始化并返回一个chunk结构体c
static chunk *chunk_init(void) {
	chunk *c;

	c = calloc(1, sizeof(*c));

	c->mem = buffer_init();
	c->file.name = buffer_init();
	c->file.fd = -1;
//MAP_FAILED＝－1 
	c->file.mmap.start = MAP_FAILED;
	c->next = NULL;

	return c;
}


















//释放一个chunk结构体c 
static void chunk_free(chunk *c) {
	if (!c) return;

	buffer_free(c->mem);
	buffer_free(c->file.name);

	free(c);
}



















//重置用户指定的chunk结构体c
static void chunk_reset(chunk *c) {
	if (!c) return;

	buffer_reset(c->mem);

	if (c->file.is_temp && !buffer_is_empty(c->file.name)) {
		unlink(c->file.name->ptr);
	}

	buffer_reset(c->file.name);

	if (c->file.fd != -1) {
		close(c->file.fd);
		c->file.fd = -1;
	}
	if (MAP_FAILED != c->file.mmap.start) {
//munmap()用来取消参数start所指的映射内存起始地址，参数length则是欲取消的内存大小
		munmap(c->file.mmap.start, c->file.mmap.length);
		c->file.mmap.start = MAP_FAILED;
	}
}

























//释放一个chunkqueue结构体cq
void chunkqueue_free(chunkqueue *cq) {
	chunk *c, *pc;
	if (!cq) return;
//释放正在使用的块列表
	for (c = cq->first; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}
//释放已经使用完的块列表
	for (c = cq->unused; c; ) {
		pc = c;
		c = c->next;
		chunk_free(pc);
	}
	free(cq);
}

























//从用户指定的结构体chunkqueue的cp中获取一个没有正在使用的chunk,如果没有，则新建新的chunk返回给用户
static chunk *chunkqueue_get_unused_chunk(chunkqueue *cq) {
	chunk *c;
//如果没有，则创建一个新的chunk并返回它
	if (!cq->unused) {
		c = chunk_init();
	}
//若有，则提取cp中第一个没有正在使用的chunk，并返回它
	 else {
		c = cq->unused;
		cq->unused = c->next;
		c->next = NULL;
		cq->unused_chunks--;
	}
	return c;
}
























//将用户指定的chunk结构体的c添加到chunkqueue结构体cp的链头
static int chunkqueue_prepend_chunk(chunkqueue *cq, chunk *c) {
	c->next = cq->first;
	cq->first = c;

	if (cq->last == NULL) {
		cq->last = c;
	}

	return 0;
}


























//将用户指定的chunk结构体的c添加到chunkqueue结构体cp的链尾
static int chunkqueue_append_chunk(chunkqueue *cq, chunk *c) {
	if (cq->last) {
		cq->last->next = c;
	}
	cq->last = c;

	if (cq->first == NULL) {
		cq->first = c;
	}

	return 0;
}





















//重置用户指定的chunkqueue结构体cp
void chunkqueue_reset(chunkqueue *cq) {
	chunk *c;
	/* move everything to the unused queue */

	/* mark all read written */
	for (c = cq->first; c; c = c->next) {
		switch(c->type) {
		case MEM_CHUNK:
			c->offset = c->mem->used - 1;
			break;
		case FILE_CHUNK:
			c->offset = c->file.length;
			break;
		default:
			break;
		}
	}
//从链头开始清理使用完的chunk（将块转移到已使用完的块队列中）
	chunkqueue_remove_finished_chunks(cq);
	cq->bytes_in = 0;
	cq->bytes_out = 0;
}
























//根据用户指定的file，创建FILE_CHUNK结构体的c添加到chunkqueue结构体cp的链尾
int chunkqueue_append_file(chunkqueue *cq, buffer *fn, off_t offset, off_t len) {
	chunk *c;

	if (len == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;

	buffer_copy_string_buffer(c->file.name, fn);
	c->file.start = offset;
	c->file.length = len;
	c->offset = 0;

	chunkqueue_append_chunk(cq, c);

	return 0;
}


























//根据用户指定的mem，创建MEM_CHUNK结构体的c添加到chunkqueue结构体cp的链尾，其内容是mem的副本
int chunkqueue_append_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
// 副本
	buffer_copy_string_buffer(c->mem, mem);

	chunkqueue_append_chunk(cq, c);

	return 0;
}
























//根据用户指定的file，创建FILE_CHUNK结构体的c添加到chunkqueue结构体cp的链尾，其内容是mem的引用（weak）
int chunkqueue_append_buffer_weak(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	if (c->mem) buffer_free(c->mem);
//引用 
	c->mem = mem;

	chunkqueue_append_chunk(cq, c);

	return 0;
}



























//根据用户指定的mem，创建MEM_CHUNK结构体的c添加到chunkqueue结构体cp的链头，其内容是mem的副本
int chunkqueue_prepend_buffer(chunkqueue *cq, buffer *mem) {
	chunk *c;

	if (mem->used == 0) return 0;

	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_copy_string_buffer(c->mem, mem);

	chunkqueue_prepend_chunk(cq, c);

	return 0;
}



















//根据用户指定的mem，创建MEM_CHUNK结构体的c添加到chunkqueue结构体cp的链头，其内容是mem的指定长度子字符串
int chunkqueue_append_mem(chunkqueue *cq, const char * mem, size_t len) {
	chunk *c;
	if (len == 0) return 0;
	c = chunkqueue_get_unused_chunk(cq);
	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_copy_string_len(c->mem, mem, len - 1);

	chunkqueue_append_chunk(cq, c);

	return 0;
}














//从用户指定的chunkqueue结构体cq中获取一个没使用的块添加到其cq的链头
buffer * chunkqueue_get_prepend_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_reset(c->mem);

	chunkqueue_prepend_chunk(cq, c);

	return c->mem;
}

















//从用户指定的chunkqueue结构体cq中获取一个没使用的块添加到其cq的链尾
buffer *chunkqueue_get_append_buffer(chunkqueue *cq) {
	chunk *c;

	c = chunkqueue_get_unused_chunk(cq);

	c->type = MEM_CHUNK;
	c->offset = 0;
	buffer_reset(c->mem);

	chunkqueue_append_chunk(cq, c);

	return c->mem;
}












//设置用户指定chunkqueue结构体cq的tempdirs字段
int chunkqueue_set_tempdirs(chunkqueue *cq, array *tempdirs) {
	if (!cq) return -1;

	cq->tempdirs = tempdirs;

	return 0;
}















//创建拥有临时文件的file_chunk结构体c，并添加到cp的链尾，并返回副本c；若创建临时文件失败则file.fd＝－1
chunk *chunkqueue_get_append_tempfile(chunkqueue *cq) {
	chunk *c;
	buffer *template = buffer_init_string("/var/tmp/lighttpd-upload-XXXXXX");

	c = chunkqueue_get_unused_chunk(cq);

	c->type = FILE_CHUNK;
	c->offset = 0;
// 如果cq中已有一些定义目录，那么就按这些定义目录的其中一个里创建临时文件
	if (cq->tempdirs && cq->tempdirs->used) {
		size_t i;

		/* we have several tempdirs, only if all of them fail we jump out */

		for (i = 0; i < cq->tempdirs->used; i++) {
			data_string *ds = (data_string *)cq->tempdirs->data[i];
			buffer_copy_string_buffer(template, ds->value);
//若其目录路径后没加'/'，则加上'/'
			BUFFER_APPEND_SLASH(template);
//在其目录路径后加上ighttpd-upload-XXXXXX字符串（临时文件名）
			buffer_append_string_len(template, CONST_STR_LEN("lighttpd-upload-XXXXXX"));
/*
mkstemp函数在系统中以唯一的文件名创建一个文件并打开，而且只有当前用户才能访问这个临时文件，并进行读、写操作。
mkstemp函数只有一个参数，这个参数是个以“XXXXXX”结尾的非空字符串。
mkstemp函数会用随机产生的字符串替换“XXXXXX”，保证 了文件名的唯一性。 
函数返回一个文件描述符，如果执行失败返回-1。
*/
//按照给定的目录创建试创建临时文件，创建成功后退出创建临时文件循环
			if (-1 != (c->file.fd = mkstemp(template->ptr))) {
// 标示该文件是临时文件
				c->file.is_temp = 1;
				break;
			}
		}
	}
// 若cq中没有指定的目录，则按照/var/tmp/lighttpd-upload-XXXXXX创建临时文件
	 else {
		if (-1 != (c->file.fd = mkstemp(template->ptr))) {
// 标示该文件是临时文件			
			c->file.is_temp = 1;
		}
	}
	buffer_copy_string_buffer(c->file.name, template);
	c->file.length = 0;
	chunkqueue_append_chunk(cq, c);
	buffer_free(template);
	return c;
}


























//获取所有块的总字节长度
off_t chunkqueue_length(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		switch (c->type) {
		case MEM_CHUNK:
			len += c->mem->used ? c->mem->used - 1 : 0;
			break;
		case FILE_CHUNK:
			len += c->file.length;
			break;
		default:
			break;
		}
	}

	return len;
}




























//获取所有chunk块的总共已写字节数
off_t chunkqueue_written(chunkqueue *cq) {
	off_t len = 0;
	chunk *c;

	for (c = cq->first; c; c = c->next) {
		switch (c->type) {
		case MEM_CHUNK:
		case FILE_CHUNK:
			len += c->offset;
			break;
		default:
			break;
		}
	}

	return len;
}



















//判断chunkqueue结构体cq的正在使用块队列是否为空
int chunkqueue_is_empty(chunkqueue *cq) {
	return cq->first ? 0 : 1;
}




















//从用户指定的chunkqueue结构体cq的正在使用块链头开始清理使用完的chunk（将块从正在使用队列转移到已使用完的块队列中）
int chunkqueue_remove_finished_chunks(chunkqueue *cq) {
	chunk *c;

	for (c = cq->first; c; c = cq->first) {
		int is_finished = 0;
//寻找已经使用完的chunk
		switch (c->type) {
		case MEM_CHUNK:
			if (c->mem->used == 0 || (c->offset == (off_t)c->mem->used - 1)) is_finished = 1;
			break;
		case FILE_CHUNK:
			if (c->offset == c->file.length) is_finished = 1;
			break;
		default:
			break;
		}
//当前块没使用完成，后续的块肯定没使用完成（先来先服务）；所以退出操作函数！
		if (!is_finished) break;
//将块从正在使用队列转移到已使用完的块队列中
		chunk_reset(c);
		cq->first = c->next;
		if (c == cq->last) cq->last = NULL;
//保证使用完的块队列只有5个块
		if (cq->unused_chunks > 4) {
			chunk_free(c);
		} else {
//插入到使用完的块队列链头
			c->next = cq->unused;
			cq->unused = c;
			cq->unused_chunks++;
		}
	}

	return 0;
}
