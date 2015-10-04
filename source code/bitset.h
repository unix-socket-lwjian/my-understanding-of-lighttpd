#ifndef _BITSET_H_
#define _BITSET_H_

#include <stddef.h>


//bitset结构提供了对位运算的封装
typedef struct {
//bits字段用于指定位数组（一连串size_t类型的存储空间）
	size_t *bits;
//nbits字段用于记录该数组中位元素的数目
	size_t nbits;
} bitset;

//用于对bitset结构进行初始化
bitset *bitset_init(size_t nbits);
//使用户指定bitset结构的位元素值为0
void bitset_reset(bitset *set);
//释放bitset结构的内存空间
void bitset_free(bitset *set);
//将bitset结构的指定位元素（从0开始）置0
void bitset_clear_bit(bitset *set, size_t pos);
//将bitset结构的指定位元素（从0开始）置1
void bitset_set_bit(bitset *set, size_t pos);
//测试bitset结构的指定位元素是否为1，是则返回1，不是则返回0
int bitset_test_bit(bitset *set, size_t pos);

#endif
