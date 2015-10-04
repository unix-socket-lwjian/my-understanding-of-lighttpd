#ifndef _CHUNK_H_
#define _CHUNK_H_

#include "buffer.h"
#include "array.h"

















//声明结构体chunk，该结构体有两种类型：MEM_CHUNK（内存块）、FILE_CHUNK（文件块），而UNUSED_CHUNK表示该已使用完但没释放chunk
typedef struct chunk {
//定义chunk的类型
	enum { UNUSED_CHUNK, MEM_CHUNK, FILE_CHUNK } type;
//MEM_CHUNK的数据字段
/* either the storage of the mem-chunk or the read-ahead buffer */
	buffer *mem; 
//FILE_CHUNK的数据字段 
	struct {
// 文件的名字
		buffer *name; 
		off_t  start; /* starting offset in the file */
		off_t  length; /* octets（字节） to send from the starting offset */
		int    fd;
//该mmap结构体用于文件的映射内存区域 
		struct {
			char   *start; /* the start pointer of the mmap'ed area */
			size_t length; /* size of the mmap'ed area */
			off_t  offset; /* start is <n> octet away from the start of the file */
		} mmap;
//该文件是否为临时文件
		int is_temp; /* file is temporary and will be deleted if on cleanup */
	} file;
//FILE_CHUNK和MEM_CHUNK的共同数据字段：块的已写字节长度
	off_t  offset; /* octets（字节） sent from this chunk
			  the size of the chunk is either
			  - mem-chunk: mem->used - 1
			  - file-chunk: file.length
			*/
//用于连接其它的chunk结构体
	struct chunk *next;
} chunk;
















//该chunkqueue结构体是用于记录正在使用的chunk和已经使用完的chunk
typedef struct {
//正在使用的chunk
	chunk *first;
	chunk *last;
//已经使用完的chunk，即相当于块池
	chunk *unused;
	size_t unused_chunks;

	array *tempdirs;

	off_t  bytes_in, bytes_out;
} chunkqueue;









chunkqueue *chunkqueue_init(void);
int chunkqueue_set_tempdirs(chunkqueue *c, array *tempdirs);
int chunkqueue_append_file(chunkqueue *c, buffer *fn, off_t offset, off_t len);
int chunkqueue_append_mem(chunkqueue *c, const char *mem, size_t len);
int chunkqueue_append_buffer(chunkqueue *c, buffer *mem);
int chunkqueue_append_buffer_weak(chunkqueue *c, buffer *mem);
int chunkqueue_prepend_buffer(chunkqueue *c, buffer *mem);

buffer * chunkqueue_get_append_buffer(chunkqueue *c);
buffer * chunkqueue_get_prepend_buffer(chunkqueue *c);
chunk * chunkqueue_get_append_tempfile(chunkqueue *cq);

int chunkqueue_remove_finished_chunks(chunkqueue *cq);

off_t chunkqueue_length(chunkqueue *c);
off_t chunkqueue_written(chunkqueue *c);
void chunkqueue_free(chunkqueue *c);
void chunkqueue_reset(chunkqueue *c);

int chunkqueue_is_empty(chunkqueue *c);

#endif
