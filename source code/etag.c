#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined HAVE_STDINT_H
#include <stdint.h>
#elif defined HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "buffer.h"
#include "etag.h"

















//比较一个非空的etag的数据是否与matches相等
int etag_is_equal(buffer *etag, const char *matches) {
	if (etag && !buffer_is_empty(etag) && 0 == strcmp(etag->ptr, matches)) return 1;
	return 0;
}


















//该函数用于根据指定的某个文件的状态信息创建对应的etag（不是最终值）
int etag_create(buffer *etag, struct stat *st,etag_flags_t flags) {
	if (0 == flags) return 0;

	buffer_reset(etag);
// flags是使用与&，所以可以多值组合
	if (flags & ETAG_USE_INODE) {
		buffer_append_off_t(etag, st->st_ino);
		buffer_append_string_len(etag, CONST_STR_LEN("-"));
	}
	
	if (flags & ETAG_USE_SIZE) {
		buffer_append_off_t(etag, st->st_size);
		buffer_append_string_len(etag, CONST_STR_LEN("-"));
	}
	
	if (flags & ETAG_USE_MTIME) {
		buffer_append_long(etag, st->st_mtime);
	}

	return 0;
}














// 获取etag的hash值，并保存在mut中
int etag_mutate(buffer *mut, buffer *etag) {
	size_t i;
	uint32_t h; //uint32_t类型定义在库文件stdint.h中，typedef unsigned int  uint32_t;

	for (h=0, i=0; i < etag->used; ++i) h = (h<<5)^(h>>27)^(etag->ptr[i]);

	buffer_reset(mut);
	buffer_copy_string_len(mut, CONST_STR_LEN("\""));
	buffer_append_long(mut, h);
	buffer_append_string_len(mut, CONST_STR_LEN("\""));

	return 0;
}
