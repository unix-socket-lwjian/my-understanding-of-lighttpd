#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "network.h"
#include "fdevent.h"
#include "log.h"
#include "stat_cache.h"

#include "sys-socket.h"

#include "network_backends.h"

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif



















//使用write数据写传输方式将cq中响应数据chunk发送到fd套接字中
int network_write_chunkqueue_write(server *srv, connection *con, int fd, chunkqueue *cq) {
	chunk *c;
	size_t chunks_written = 0;

	for(c = cq->first; c; c = c->next) {
		//标志当前chunk是否发送完成
		int chunk_finished = 0;

		switch(c->type) {
		//内存chunk块
		case MEM_CHUNK: {
			char * offset;
			size_t toSend;
			ssize_t r;
			//判断该内存chunk块的数据已经发送完毕
			if (c->mem->used == 0) {
				chunk_finished = 1;
				break;
			}
			//块内待发送数据的起始位置
			offset = c->mem->ptr + c->offset;
			//块内待发送数据的长度
			toSend = c->mem->used - 1 - c->offset;
#ifdef __WIN32
			if ((r = send(fd, offset, toSend, 0)) < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed: ", strerror(errno), fd);

				return -1;
			}
#else
			//利用write函数进行发送
			if ((r = write(fd, offset, toSend)) < 0) {
				log_error_write(srv, __FILE__, __LINE__, "ssd", "write failed: ", strerror(errno), fd);

				return -1;
			}
#endif
			//块内待发送数据的起始位置后移
			c->offset += r;
			//发送数据总量增加
			cq->bytes_out += r;
			//标志该内存chunk块的数据已经发送完毕
			if (c->offset == (off_t)c->mem->used - 1) {
				chunk_finished = 1;
			}

			break;
		}

		//文件chunk块
		case FILE_CHUNK: {
#ifdef USE_MMAP
			char *p = NULL;
#endif
			ssize_t r;
			off_t offset;
			size_t toSend;
			stat_cache_entry *sce = NULL;
			int ifd;
			//判断文件是否存在
			if (HANDLER_ERROR == stat_cache_get_entry(srv, con, c->file.name, &sce)) {
				log_error_write(srv, __FILE__, __LINE__, "sb",
						strerror(errno), c->file.name);
				return -1;
			}
			//文件内待发送数据的起始位置
			offset = c->file.start + c->offset;
			//文件内待发送数据的长度
			toSend = c->file.length - c->offset;

			if (offset > sce->st.st_size) {
				log_error_write(srv, __FILE__, __LINE__, "sb", "file was shrinked:", c->file.name);

				return -1;
			}
			//打开该文件
			if (-1 == (ifd = open(c->file.name->ptr, O_RDONLY))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "open failed: ", strerror(errno));

				return -1;
			}
			//若系统支持mmap函数，则使用mmap后，再调用write发送数据
#if defined USE_MMAP
			if (MAP_FAILED == (p = mmap(0, sce->st.st_size, PROT_READ, MAP_SHARED, ifd, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "mmap failed: ", strerror(errno));

				close(ifd);

				return -1;
			}
			close(ifd);
			//利用write函数进行发送
			if ((r = write(fd, p + offset, toSend)) <= 0) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "write failed: ", strerror(errno));
				munmap(p, sce->st.st_size);
				return -1;
			}
			//取消文件内存映射
			munmap(p, sce->st.st_size);

			//若系统不支持mmap，则直接调用read写到内存，再调用send发送数据
#else
			buffer_prepare_copy(srv->tmp_buf, toSend);

			lseek(ifd, offset, SEEK_SET);
			if (-1 == (toSend = read(ifd, srv->tmp_buf->ptr, toSend))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "read: ", strerror(errno));
				close(ifd);

				return -1;
			}
			close(ifd);

			if (-1 == (r = send(fd, srv->tmp_buf->ptr, toSend, 0))) {
				log_error_write(srv, __FILE__, __LINE__, "ss", "write: ", strerror(errno));

				return -1;
			}
#endif
			//文件内待发送数据的起始位置后移
			c->offset += r;
			//发送数据总量增加
			cq->bytes_out += r;
			//标志该内存chunk块的数据已经发送完毕
			if (c->offset == c->file.length) {
				chunk_finished = 1;
			}

			break;
		}
		default:

			log_error_write(srv, __FILE__, __LINE__, "ds", c, "type not known");

			return -1;
		}


		//该次循环的块内数据还没全部发送
		if (!chunk_finished) {
			/* not finished yet */
			break;
		}
		//完成发送的块数加一，一次循环应该完成一次块的数据发送
		chunks_written++;
	}
	//返回完成发送的块数
	return chunks_written;
}














#if 0
network_write_init(void) {
	p->write = network_write_write_chunkset;
}
#endif
