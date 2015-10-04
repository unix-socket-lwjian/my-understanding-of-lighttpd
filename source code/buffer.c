#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include "buffer.h"


static const char hex_chars[] = "0123456789abcdef";















//初始化buffer结构，但是不会为该结构的ptr字段指向的地方分配内存空间
buffer* buffer_init(void) {
	buffer *b;
	b = malloc(sizeof(*b));
	assert(b);
	b->ptr = NULL;
	b->size = 0;
	b->used = 0;
	return b;
}

















//将buffer结构体src的内容复制到buffer结构体b中
int buffer_copy_string_buffer(buffer *b, const buffer *src) { 
	if (!src) return -1;

	if (src->used == 0) {
		b->used = 0;
		return 0;
	}
	return buffer_copy_string_len(b, src->ptr, src->used - 1);
}


















//创建buffer结构的b并将buffer结构体src的内容复制到buffer结构体b中，返回b
buffer *buffer_init_buffer(buffer *src) {
	buffer *b = buffer_init();
	buffer_copy_string_buffer(b, src);
	return b;
}




















//释放用户指定的buffer结构体b
void buffer_free(buffer *b) {
	if (!b) return;

	free(b->ptr);
	free(b);
}

















//重置用户指定的buffer结构体b
void buffer_reset(buffer *b) {
	if (!b) return;
// 当申请的prt指向内存空间超过MAX_REUSE_SIZE（4*1024即4kB）时，该内存空间被释放，否则重用
	if (b->size > BUFFER_MAX_REUSE_SIZE) {
		free(b->ptr);
		b->ptr = NULL;
		b->size = 0;
// 重用prt指向的内存空间
	} else if (b->size) {
		b->ptr[0] = '\0';
	}
	b->used = 0;
}




















// 64字节
#define BUFFER_PIECE_SIZE 64 
//确保用户指定的buffer结构体b的ptr的指向区域至少有size大小的内存空间，并清空之前数据
int buffer_prepare_copy(buffer *b, size_t size) {
	if (!b) return -1;

	if ((0 == b->size) ||
	    (size > b->size)) {
		if (b->size) free(b->ptr);
		b->size = size;
// 为了避免内存碎片，新分配的总空间是BUFFER_PIECE_SIZE倍数
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		b->ptr = malloc(b->size);
		assert(b->ptr);
	}
	b->used = 0;
	return 0;
}


















//确保用户指定的buffer结构体b的ptr的指向区域至少有size大小的 空闲 内存空间
int buffer_prepare_append(buffer *b, size_t size) {
	if (!b) return -1;
	if (0 == b->size) {
		b->size = size;
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		b->ptr = malloc(b->size);
		b->used = 0;
		assert(b->ptr);
	} else if (b->used + size > b->size) {
		b->size += size;
		b->size += BUFFER_PIECE_SIZE - (b->size % BUFFER_PIECE_SIZE);
		b->ptr = realloc(b->ptr, b->size);
		assert(b->ptr);
	}
	return 0;
}






















//把指定字符串s复制到用户指定的buffer结构体b的数据空间，b原有的数据会失去
int buffer_copy_string(buffer *b, const char *s) {
	size_t s_len;

	if (!s || !b) return -1;

	s_len = strlen(s) + 1;
	buffer_prepare_copy(b, s_len); //为buffer结构体变量b,分配s_len长度的内存

	memcpy(b->ptr, s, s_len);
	b->used = s_len;

	return 0;
}





















//把指定字符串s前s_len个字符复制到用户指定的buffer结构体b的数据空间，b原有的数据会失去
int buffer_copy_string_len(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
//使用＃if0 与＃endif对中间区域的代码进行注释，因为编译条件为0，编译器忽略这段代码！
#if 0 
	/* removed optimization as we have to keep the empty string
	 * in some cases for the config handling
	 *
	 * url.access-deny = ( "" )
	 */
	if (s_len == 0) return 0;
#endif
	buffer_prepare_copy(b, s_len + 1);

	memcpy(b->ptr, s, s_len);
	b->ptr[s_len] = '\0';
	b->used = s_len + 1;

	return 0;
}



























//把指定字符串s复制到用户指定的buffer结构体b的数据空间末尾
int buffer_append_string(buffer *b, const char *s) {
	size_t s_len;

	if (!s || !b) return -1;

	s_len = strlen(s);
	buffer_prepare_append(b, s_len + 1);
	if (b->used == 0)
		b->used++;

	memcpy(b->ptr + b->used - 1, s, s_len + 1);
	b->used += s_len;

	return 0;
}



























//把指定字符串s复制到用户指定的buffer结构体b的数据空间末尾，但是该函数有漏洞
int buffer_append_string_rfill(buffer *b, const char *s, size_t maxlen) {
	size_t s_len;

	if (!s || !b) return -1;

	s_len = strlen(s);
//使b的内存空间加maxlen+1的大小
	buffer_prepare_append(b, maxlen + 1); 
	if (b->used == 0)
		b->used++;
//而这里却添加s_len的长度，如果s_len大于maxlen+1，则会造成内存溢出
	memcpy(b->ptr + b->used - 1, s, s_len); 
	if (maxlen > s_len) {
		memset(b->ptr + b->used - 1 + s_len, ' ', maxlen - s_len);
	}
	b->used += maxlen;
	b->ptr[b->used - 1] = '\0';
	return 0;
}



























//把指定字符串s前s_len个字符复制到用户指定的buffer结构体b的数据空间末尾
int buffer_append_string_len(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	if (s_len == 0) return 0;

	buffer_prepare_append(b, s_len + 1);
	if (b->used == 0)
		b->used++;
	memcpy(b->ptr + b->used - 1, s, s_len);
	b->used += s_len;
	b->ptr[b->used - 1] = '\0';
	return 0;
}



























//将buffer结构体的src的数据复制到buffer结构体b的数据末尾
int buffer_append_string_buffer(buffer *b, const buffer *src) {
	if (!src) return -1;
	if (src->used == 0) return 0;

	return buffer_append_string_len(b, src->ptr, src->used - 1);
}


























//把s指向内存空间前s_len个字节复制到用户指定的buffer结构体b的数据空间末尾，因为是不确定数据，所以没有考虑结尾加‘\0’
int buffer_append_memory(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;
	if (s_len == 0) return 0;
	buffer_prepare_append(b, s_len);
	memcpy(b->ptr + b->used, s, s_len);
	b->used += s_len;

	return 0;
}























//把s指向内存空间前s_len个字节复制到用户指定的buffer结构体b的数据空间并且b原有的数据会失去，因为是不确定数据，所以没有考虑结尾加‘\0’
int buffer_copy_memory(buffer *b, const char *s, size_t s_len) {
	if (!s || !b) return -1;

	b->used = 0;

	return buffer_append_memory(b, s, s_len);
}



























//将无符号长整型数value转换成对应的十六进制字符串，并将其复制增添到buffer结构b的数据末尾。
int buffer_append_long_hex(buffer *b, unsigned long value) {
	char *buf;
	int shift = 0;
//该函数执行时，已经将10进制value转换为2进制存入copy变量中	
	unsigned long copy = value; 
//4位2进制等于一位16进制，shift表示几位16进制数
	while (copy) { 
		copy >>= 4; //copy=copy>>4
		shift++;
	}
//至少转换2次，并且转换次数是偶数
	if (shift == 0)
		shift++;
	if (shift & 0x01) 
		shift++;

	buffer_prepare_append(b, shift + 1);
	if (b->used == 0)
		b->used++;
	buf = b->ptr + (b->used - 1);
	b->used += shift;
//shift=shift<<2，即shift扩大四倍，即总共要转多少位（bit）
	shift <<= 2; 
	while (shift > 0) {
//shift=shift-4	，每次转4位
		shift -= 4; 
//static const char hex_chars[] = "0123456789abcdef";前面已经定义过了hex_chars数组，与0x0F是为了保证每次只转换低4位（从高端开始）
		*(buf++) = hex_chars[(value >> shift) & 0x0F]; 
	}
	*buf = '\0';
	return 0;
}


































//将有符号长整型数value转换成对应的十进制字符串，并将其复制到buf指针指向的内存空间。
int LI_ltostr(char *buf, long val) {
	char swap;
	char *end;
	int len = 1;

	if (val < 0) {
		len++;
		*(buf++) = '-';
//将负数转为正数
		val = -val; 
	}
//使end指针和buf指针所指的位置一致
	end = buf; 
	while (val > 9) {
		*(end++) = '0' + (val % 10);
		val = val / 10;
	}
	*(end) = '0' + val;
	*(end + 1) = '\0'; //这里并没有改变end的值
	len += end - buf; //len=len+end-buf;当指针名没有*符号时，所指的是指针位置

	while (buf < end) { //调换，因为内存先显示低位
		swap = *end;
		*end = *buf;
		*buf = swap;

		buf++;
		end--;
	}

	return len;
}

































//将有符号长整型数value转换成对应的十进制字符串，并将其复制到buffer结构体的数据末尾
int buffer_append_long(buffer *b, long val) {
	if (!b) return -1;

	buffer_prepare_append(b, 32);
	if (b->used == 0)
		b->used++;

	b->used += LI_ltostr(b->ptr + (b->used - 1), val);
	return 0;
}













//将有符号长整型数value转换成对应的十进制字符串，并将其复制到buffer结构体的数据，之前数据失去
int buffer_copy_long(buffer *b, long val) {
	if (!b) return -1;
	b->used = 0;
	return buffer_append_long(b, val);
}




























//将off_t类型value转换成对应的十进制字符串，并将其复制到buffer结构体的数据末尾
#if !defined(SIZEOF_LONG) || (SIZEOF_LONG != SIZEOF_OFF_T)
int buffer_append_off_t(buffer *b, off_t val) {
	char swap;
	char *end;
	char *start;
	int len = 1;

	if (!b) return -1;

	buffer_prepare_append(b, 32);
	if (b->used == 0)
		b->used++;

	start = b->ptr + (b->used - 1);
	if (val < 0) {
		len++;
		*(start++) = '-';
		val = -val;
	}

	end = start;
	while (val > 9) {
		*(end++) = '0' + (val % 10);
		val = val / 10;
	}
	*(end) = '0' + val;
	*(end + 1) = '\0';
	len += end - start;

	while (start < end) {
		swap   = *end;
		*end   = *start;
		*start = swap;

		start++;
		end--;
	}

	b->used += len;
	return 0;
}

































//将off_t类型value转换成对应的十进制字符串，并将其复制到buffer结构体的数据，之前数据失去
int buffer_copy_off_t(buffer *b, off_t val) {
	if (!b) return -1;

	b->used = 0;
	return buffer_append_off_t(b, val);
}
#endif /* !defined(SIZEOF_LONG) || (SIZEOF_LONG != SIZEOF_OFF_T) */































//获得指定字符c低4位对应的十六进制字符
char int2hex(char c) {
	return hex_chars[(c & 0x0F)];
}





























//获得将十六进制字符转换成对应的数字，如果是非法的十六进制字符则返回0xFF
char hex2int(unsigned char hex) { //其实现方法，是否有效？需实验证明
	hex = hex - '0';
	if (hex > 9) {
		hex = (hex + '0' - 1) | 0x20;
		hex = hex - 'a' + 11;
	}
	if (hex > 15)
		hex = 0xFF;

	return hex;
}





























/* 					下面的四个函数是对buffer_array进行操作的，而这个结构在Lighttp源文件中使用不多		*/



buffer_array* buffer_array_init(void) {
	buffer_array *b;

	b = malloc(sizeof(*b));

	assert(b);
	b->ptr = NULL;
	b->size = 0;
	b->used = 0;

	return b;
}
























void buffer_array_reset(buffer_array *b) {
	size_t i;

	if (!b) return;

	/* if they are too large, reduce them */
	for (i = 0; i < b->used; i++) {
		buffer_reset(b->ptr[i]);
	}

	b->used = 0;
}























void buffer_array_free(buffer_array *b) {
	size_t i;
	if (!b) return;

	for (i = 0; i < b->size; i++) {
		if (b->ptr[i]) buffer_free(b->ptr[i]);
	}
	free(b->ptr);
	free(b);
}




























buffer *buffer_array_append_get_buffer(buffer_array *b) {
	size_t i;

	if (b->size == 0) {
		b->size = 16;
		b->ptr = malloc(sizeof(*b->ptr) * b->size);
		assert(b->ptr);
		for (i = 0; i < b->size; i++) {
			b->ptr[i] = NULL;
		}
	} else if (b->size == b->used) {
		b->size += 16;
		b->ptr = realloc(b->ptr, sizeof(*b->ptr) * b->size);
		assert(b->ptr);
		for (i = b->used; i < b->size; i++) {
			b->ptr[i] = NULL;
		}
	}

	if (b->ptr[b->used] == NULL) {
		b->ptr[b->used] = buffer_init();
	}

	b->ptr[b->used]->used = 0;

	return b->ptr[b->used++];
}































//在buffer结构体b数据元素中查找匹配needle字符串前len个字符字串，如果匹配成功，则返回在buffer数据元素的起始下标，否则返回NULL
char * buffer_search_string_len(buffer *b, const char *needle, size_t len) {
	size_t i;
	if (len == 0) return NULL;
	if (needle == NULL) return NULL;

	if (b->used < len) return NULL;

	for(i = 0; i < b->used - len; i++) {
		if (0 == memcmp(b->ptr + i, needle, len)) {
			return b->ptr + i;
		}
	}

	return NULL;
}





























// 使用用户指定的字符串作为创建buffer结构体b的数据元素，并返回结构体b
buffer *buffer_init_string(const char *str) {
	buffer *b = buffer_init();

	buffer_copy_string(b, str);

	return b;
}





























//将用户的指定的buffer结构体b的数据内容清空
int buffer_is_empty(buffer *b) {
	if (!b) return 1;
	return (b->used == 0);
}































//判断用户分别指定的两个结构体a、b的数据内容是否相同
int buffer_is_equal(buffer *a, buffer *b) {
	if (a->used != b->used) return 0;
	if (a->used == 0) return 1;

	return (0 == strcmp(a->ptr, b->ptr));
}




























//判断用户指定的buffer结构体a的数据与指定的字符串是否相同
int buffer_is_equal_string(buffer *a, const char *s, size_t b_len) {
	buffer b;

	b.ptr = (char *)s;
	b.used = b_len + 1;

	return buffer_is_equal(a, &b);
}




























//对两个指定长度的字符串进行大小写不敏感的比较
int buffer_caseless_compare(const char *a, size_t a_len, const char *b, size_t b_len) {
	size_t ndx = 0, max_ndx;
	size_t *al, *bl;
	size_t mask = sizeof(*al) - 1;
	al = (size_t *)a; //类型强制转换
	bl = (size_t *)b;
	/* is the alignment correct ? */
	if ( ((size_t)al & mask) == 0 &&
	     ((size_t)bl & mask) == 0 ) { //判断al,bl地址的值是否都为size_t类型所占内存空间字节数的倍数；32位机size_t为4字节，64位机size_t为8字节

		max_ndx = ((a_len < b_len) ? a_len : b_len) & ~mask;  //取啊a、b字符串最小的长度值，并把低位清零放入max_ndx中
															/*
																条件表达式：逻辑表达式？表达式1：表达式2 =>若逻辑表达式值非零，则取表达式1的值为结果，否则取表达式2的值为结果。
															*/
		for (; ndx < max_ndx; ndx += sizeof(*al)) { //ndx=ndx+sizeof(*al)
			if (*al != *bl) break; //进行每次一个size_t类型所占内存字节数长度的数据比较
			al++; bl++;
		}
	}
	a = (char *)al;
	b = (char *)bl;
	max_ndx = ((a_len < b_len) ? a_len : b_len);
	for (; ndx < max_ndx; ndx++) {
		char a1 = *a++, b1 = *b++;

		if (a1 != b1) {
			if ((a1 >= 'A' && a1 <= 'Z') && (b1 >= 'a' && b1 <= 'z'))
				a1 |= 32;
			else if ((a1 >= 'a' && a1 <= 'z') && (b1 >= 'A' && b1 <= 'Z'))
				b1 |= 32;
			if ((a1 - b1) != 0) return (a1 - b1);
		}
	}
	if (a_len == b_len) return 0;
	return (a_len - b_len);
}

































//比较两个buffer结构体的数据元素末尾len长度的子字符串是否相等
int buffer_is_equal_right_len(buffer *b1, buffer *b2, size_t len) {
	/* no, len -> equal */
	if (len == 0) return 1;

	/* len > 0, but empty buffers -> not equal */
	if (b1->used == 0 || b2->used == 0) return 0;

	/* buffers too small -> not equal */
	if (b1->used - 1 < len || b2->used - 1 < len) return 0; //为什么这里要减一？感觉没必要||原版：if (b1->used - 1 < len || b1->used - 1 < len) return 0;

	if (0 == strncmp(b1->ptr + b1->used - 1 - len,
			 b2->ptr + b2->used - 1 - len, len)) {
		return 1;
	}

	return 0;
}

























//将字符串的前in_len长度的子字符串转换成对应的十六进制字符串，并复制到buffer结构体b的数据中，其之前数据会失去
int buffer_copy_string_hex(buffer *b, const char *in, size_t in_len) {
	size_t i;
	if (in_len * 2 < in_len) return -1;

	buffer_prepare_copy(b, in_len * 2 + 1);

	for (i = 0; i < in_len; i++) {
		b->ptr[b->used++] = hex_chars[(in[i] >> 4) & 0x0F];
		b->ptr[b->used++] = hex_chars[in[i] & 0x0F];
	}
	b->ptr[b->used++] = '\0';

	return 0;
}


























//下面是六种编码的标志数组，数组元素值为1的元素的对应下标值大小的ASCll码在字符表中对应的字符需要转码（一些不安全字符），否则其字符可以直接使用
/* everything except: ! ( ) * - . 0-9 A-Z _ a-z */
const char encoded_chars_rel_uri_part[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1,  /*  20 -  2F space " # $ % & ' + , / */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  /*  70 -  7F { | } ~ DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

/* everything except: ! ( ) * - . / 0-9 A-Z _ a-z */
const char encoded_chars_rel_uri[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0,  /*  20 -  2F space " # $ % & ' + , */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,  /*  30 -  3F : ; < = > ? */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F @ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  50 -  5F [ \ ] ^ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F ` */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,  /*  70 -  7F { | } ~ DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

const char encoded_chars_html[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F & */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

const char encoded_chars_minimal_xml[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F & */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  30 -  3F < > */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  /*  70 -  7F DEL */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  80 -  8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  90 -  9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  A0 -  AF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  B0 -  BF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  C0 -  CF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  D0 -  DF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  E0 -  EF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  F0 -  FF */
};

const char encoded_chars_hex[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  00 -  0F control chars */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  10 -  1F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  20 -  2F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  30 -  3F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  40 -  4F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  50 -  5F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  60 -  6F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  70 -  7F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  80 -  8F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  90 -  9F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  A0 -  AF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  B0 -  BF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  C0 -  CF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  D0 -  DF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  E0 -  EF */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /*  F0 -  FF */
};

const char encoded_chars_http_header[] = {
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	*/
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,  /*  00 -  0F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  10 -  1F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  20 -  2F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  30 -  3F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  40 -  4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  50 -  5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  60 -  6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  70 -  7F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  80 -  8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  90 -  9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  A0 -  AF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  B0 -  BF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  C0 -  CF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  D0 -  DF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  E0 -  EF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  F0 -  FF */
};



































//将字符串s的前s_len个字节以指定的encoding编码方式编码后复制到buffer结构体b的数据末尾
int buffer_append_string_encoded(buffer *b, const char *s, size_t s_len, buffer_encoding_t encoding) {
	unsigned char *ds, *d;
	size_t d_len, ndx;
	const char *map = NULL;

	if (!s || !b) return -1;

	if (b->ptr[b->used - 1] != '\0') {
		SEGFAULT();
	}

	if (s_len == 0) return 0;

	switch(encoding) {
	case ENCODING_REL_URI:
		map = encoded_chars_rel_uri;
		break;
	case ENCODING_REL_URI_PART:
		map = encoded_chars_rel_uri_part;
		break;
	case ENCODING_HTML:
		map = encoded_chars_html;
		break;
	case ENCODING_MINIMAL_XML:
		map = encoded_chars_minimal_xml;
		break;
	case ENCODING_HEX:
		map = encoded_chars_hex;
		break;
	case ENCODING_HTTP_HEADER:
		map = encoded_chars_http_header;
		break;
	case ENCODING_UNSET:
		break;
	}

	assert(map != NULL);

	/* count to-be-encoded-characters */
	for (ds = (unsigned char *)s, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) { //计算转码后的长度（大小）d_len
		if (map[*ds]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d_len += 3;
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d_len += 6;
				break;
			case ENCODING_HTTP_HEADER:
			case ENCODING_HEX:
				d_len += 2;
				break;
			case ENCODING_UNSET:
				break;
			}
		} else {
			d_len ++;
		}
	}
	buffer_prepare_append(b, d_len);
	for (ds = (unsigned char *)s, d = (unsigned char *)b->ptr + b->used - 1, d_len = 0, ndx = 0; ndx < s_len; ds++, ndx++) {
		if (map[*ds]) {
			switch(encoding) {
			case ENCODING_REL_URI:
			case ENCODING_REL_URI_PART:
				d[d_len++] = '%';
				d[d_len++] = hex_chars[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars[(*ds) & 0x0F];
				break;
			case ENCODING_HTML:
			case ENCODING_MINIMAL_XML:
				d[d_len++] = '&';
				d[d_len++] = '#';
				d[d_len++] = 'x';
				d[d_len++] = hex_chars[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars[(*ds) & 0x0F];
				d[d_len++] = ';';
				break;
			case ENCODING_HEX:
				d[d_len++] = hex_chars[((*ds) >> 4) & 0x0F];
				d[d_len++] = hex_chars[(*ds) & 0x0F];
				break;
			case ENCODING_HTTP_HEADER:
				d[d_len++] = *ds;
				d[d_len++] = '\t';
				break;
			case ENCODING_UNSET:
				break;
			}
		} else {
			d[d_len++] = *ds;
		}
	}

	/* terminate buffer and calculate new length */
	b->ptr[b->used + d_len - 1] = '\0';

	b->used += d_len;

	return 0;
}






































//对buffer结构体的url包含的数据元素进行解码，对其中的特殊字符解码后原地替换，非打印字符用_替换
// is_query:数据元素中是否有空格字符，1:有、0:没有
static int buffer_urldecode_internal(buffer *url, int is_query) {
	unsigned char high, low;
	const char *src; //src指针所指的内容不可改变，但指针本身可以再赋值
	char *dst;

	if (!url || !url->ptr) return -1;

	src = (const char*) url->ptr;
	dst = (char*) url->ptr;

	while ((*src) != '\0') {
		if (is_query && *src == '+') { //加号解码为空格
			*dst = ' ';
		} else if (*src == '%') { //编码字符需要进行解码
			*dst = '%';

			high = hex2int(*(src + 1));
			if (high != 0xFF) {
				low = hex2int(*(src + 2));
				if (low != 0xFF) {
					high = (high << 4) | low;

					/* map control-characters out */
					if (high < 32 || high == 127) high = '_';

					*dst = high;
					src += 2;
				}
			}
		} else {
			*dst = *src;
		}

		dst++;
		src++;
	}

	*dst = '\0';
	url->used = (dst - url->ptr) + 1;

	return 0;
}




































//对buffer结构体的url包含的数据元素（不包含空格字符）进行解码，对其中的特殊字符解码后原地替换，非打印字符用_替换
int buffer_urldecode_path(buffer *url) {
	return buffer_urldecode_internal(url, 0);
}
























//对buffer结构体的url包含的数据元素（包含空格字符）进行解码，对其中的特殊字符解码后原地替换，非打印字符用_替换
int buffer_urldecode_query(buffer *url) {
	return buffer_urldecode_internal(url, 1);
}




















//将buffer结构体src包含的字符串路径转换成等同的简单形式，保存到buffer结构体dest内
/* Remove "/../", "//", "/./" parts from path.
 *
 * /blah/..         gets  /
 * /blah/../foo     gets  /foo
 * /abc/./xyz       gets  /abc/xyz
 * /abc//xyz        gets  /abc/xyz
 *
 * NOTE: src and dest can point to the same buffer, in which case,
 *       the operation is performed in-place.
 */
int buffer_path_simplify(buffer *dest, buffer *src)
{
	int toklen;
	char c, pre1;
	char *start, *slash, *walk, *out;
	unsigned short pre; //2字节长

	if (src == NULL || src->ptr == NULL || dest == NULL)
		return -1;

	if (src == dest)
		buffer_prepare_append(dest, 1);
	else
		buffer_prepare_copy(dest, src->used + 1);

	walk  = src->ptr;
	start = dest->ptr;
	out   = dest->ptr;
	slash = dest->ptr;


#if defined(__WIN32) || defined(__CYGWIN__)
	/* cygwin is treating \ and / the same, so we have to that too
	 */

	for (walk = src->ptr; *walk; walk++) { //将walk里所有'\\'转换成'/'
		if (*walk == '\\') *walk = '/';
	}
	walk = src->ptr;
#endif

	while (*walk == ' ') { //跳过第一个空格
		walk++;
	}

	pre1 = *(walk++); //将去除第一个空格后的第一个字符放入pre1
	c    = *(walk++); //将去除第一个空格后的第二个字符放入c
	pre  = pre1;
	if (pre1 != '/') { //（即一开始不为'/'符号，便先添加'/'）
		pre = ('/' << 8) | pre1;//保存'/'和pre1的ASCII码存入pre
		*(out++) = '/';
	}
	*(out++) = pre1;

	if (pre1 == '\0') { //如果pre1为'\0'字符，则dest->pre='/','\0',dest->used = (out - start) + 1;该函数执行结束
		dest->used = (out - start) + 1;
		return 0;
	}

	while (1) {
		if (c == '/' || c == '\0') {
			toklen = out - slash; //获取out指针的移动字节数
			if (toklen == 3 && pre == (('.' << 8) | '.')) {
				out = slash;
				if (out > start) {
					out--;
					while (out > start && *out != '/') {
						out--;
					}
				}

				if (c == '\0')
					out++;
			} else if (toklen == 1 || pre == (('/' << 8) | '.')) {
				out = slash;
				if (c == '\0')
					out++;
			}

			slash = out;
		}

		if (c == '\0')
			break;

		pre1 = c;
		pre  = (pre << 8) | pre1;
		c    = *walk;
		*out = pre1;

		out++;
		walk++;
	}

	*out = '\0';
	dest->used = (out - start) + 1;

	return 0;
}

























//判断c是否为数字字符
int light_isdigit(int c) {
	return (c >= '0' && c <= '9');
}
























//判断c是否为十六进制数字字符
int light_isxdigit(int c) {
	if (light_isdigit(c)) return 1;

	c |= 32;
	return (c >= 'a' && c <= 'f');
}



















//判断c是否为字母字符
int light_isalpha(int c) {
	c |= 32;
	return (c >= 'a' && c <= 'z');
}



















//判断c是否为数字字符或字母字符
int light_isalnum(int c) {
	return light_isdigit(c) || light_isalpha(c);
}















//将buffer结构体b的字符串转换成小写
int buffer_to_lower(buffer *b) {
	char *c;

	if (b->used == 0) return 0;

	for (c = b->ptr; *c; c++) {
		if (*c >= 'A' && *c <= 'Z') {
			*c |= 32;
		}
	}

	return 0;
}


















//将buffer结构体b的字符串转换成大写
int buffer_to_upper(buffer *b) {
	char *c;

	if (b->used == 0) return 0;

	for (c = b->ptr; *c; c++) {
		if (*c >= 'a' && *c <= 'z') {
			*c &= ~32;
		}
	}

	return 0;
}
