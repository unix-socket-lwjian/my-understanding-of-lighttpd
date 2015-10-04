#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "bitset.h"
#include "buffer.h"


//该宏用于计算size_t类型共有多少位
#define BITSET_BITS \
	( CHAR_BIT * sizeof(size_t) )
//该宏用于获取某位（从0开始）为1的mask码（mask码为size_t类型）
#define BITSET_MASK(pos) \
	( ((size_t)1) << ((pos) % BITSET_BITS) )
//根据指定的bit位(pos)，查找对应的某个size_t类型的数组元素
#define BITSET_WORD(set, pos) \
	( (set)->bits[(pos) / BITSET_BITS] )
//用于计算用户指定的位数的多少(nbits)计算出要用的size_t的数目
#define BITSET_USED(nbits) \
	( ((nbits) + (BITSET_BITS - 1)) / BITSET_BITS )



//用于对bitset结构进行初始化
bitset *bitset_init(size_t nbits) {
	bitset *set;
//为bitset结构的set变量分配内存空间
	set = malloc(sizeof(*set));
//判断set指针是否为空指针
	assert(set);
//根据用于指定的位数(nbits)为bitset结构的bits字段分配内存空间
	set->bits = calloc(BITSET_USED(nbits), sizeof(*set->bits));
//将用户指定的位数(nbits)赋予bitset结构的nbits字段
	set->nbits = nbits;
//判断bitset结构的bits字段是否为空指针
	assert(set->bits);
//返回bitset结构的set给该函数的调用者
	return set;
}


//使用户指定bitset结构的位元素值为0
void bitset_reset(bitset *set) {
	memset(set->bits, 0, BITSET_USED(set->nbits) * sizeof(*set->bits));
}


//释放bitset结构的内存空间
void bitset_free(bitset *set) {
	free(set->bits);
	free(set);
}


//将bitset结构的指定位元素（从0开始）置0
void bitset_clear_bit(bitset *set, size_t pos) {
	if (pos >= set->nbits) {
	    SEGFAULT();
	}
	BITSET_WORD(set, pos) &= ~BITSET_MASK(pos);
}


//将bitset结构的指定位元素（从0开始）置1
void bitset_set_bit(bitset *set, size_t pos) {
	if (pos >= set->nbits) {
	    SEGFAULT();
	}
	BITSET_WORD(set, pos) |= BITSET_MASK(pos);
}



//测试bitset结构的指定位元素是否为1，是则返回1，不是则返回0
int bitset_test_bit(bitset *set, size_t pos) {
	if (pos >= set->nbits) {
	    SEGFAULT();
	}
	return (BITSET_WORD(set, pos) & BITSET_MASK(pos)) != 0;
}
