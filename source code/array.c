#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <errno.h>
#include <assert.h>

#include "array.h"
#include "buffer.h"




























//新建，初始化并返回一个array数据结构体a
// 使用calloc函数，除了指针赋予NULL，其他为0
array *array_init(void) {
	array *a;
	a = calloc(1, sizeof(*a));
	assert(a);
	a->next_power_of_2 = 1;
	return a;
}






























// 复制用户指定的array结构体src，并返回副本a
array *array_init_array(array *src) {
	size_t i;
	array *a = array_init();

	a->used = src->used;
	a->size = src->size;
	a->next_power_of_2 = src->next_power_of_2;
	a->unique_ndx = src->unique_ndx;
	a->data = malloc(sizeof(*src->data) * src->size);
	for (i = 0; i < src->size; i++) {
		if (src->data[i]) a->data[i] = src->data[i]->copy(src->data[i]);
		else a->data[i] = NULL;
	}
	a->sorted = malloc(sizeof(*src->sorted)   * src->size);
	memcpy(a->sorted, src->sorted, sizeof(*src->sorted)   * src->size);
	return a;
}
























//释放用户指定的array结构体a
void array_free(array *a) {
	size_t i;
	if (!a) return;
// 如果数据不是其他数据的引用，才释放
	if (!a->is_weakref) {
		for (i = 0; i < a->size; i++) {
			if (a->data[i]) a->data[i]->free(a->data[i]);
		}
	}
	if (a->data) free(a->data);
	if (a->sorted) free(a->sorted);
	free(a);
}






















//重置用户指定的arry结构体a
void array_reset(array *a) {
	size_t i;
	if (!a) return;
// 如果数据不是其他数据的引用，才释放
	if (!a->is_weakref) {
		for (i = 0; i < a->used; i++) {
			a->data[i]->reset(a->data[i]); 
		}
	}
	a->used = 0;
}





















//弹出并返回array结构体a的数组最后一个元素
data_unset *array_pop(array *a) {
	data_unset *du;
	assert(a->used != 0);
	a->used --;
	du = a->data[a->used];
	a->data[a->used] = NULL;

	return du;
}



























/*在array结构体a中数组内查找关键字为给定长度key的数据，返回该数据在data数组中的下标;
同时将sorted中存放该下标值的索引下标（数组元素排列顺序）通过rndx传出，即该数据在data的位置，和排列顺序*/
static int array_get_index(array *a, const char *key, size_t keylen, int *rndx) {
	int ndx = -1;
	int i, pos = 0;

	if (key == NULL) return -1;

//利用sorted数组使用二分搜索查找算法，寻找相应的数据；i为每次收缩寻找倍数（每次缩小两倍）
	for (i = pos = a->next_power_of_2 / 2; ; i >>= 1) { 
		int cmp;

		if (pos < 0) {
			pos += i; //pos=pos+i
		} else if (pos >= (int)a->used) {
			pos -= i; //pos=pos-i
		} else { 
//匹配指定长度key的内容
			cmp = buffer_caseless_compare(key, keylen, a->data[a->sorted[pos]]->key->ptr, a->data[a->sorted[pos]]->key->used);
// 找到相应的数据
			if (cmp == 0) {
				ndx = a->sorted[pos];
				break;
//所找数据在前半部分
			} else if (cmp < 0) {
				pos -= i; //pos=pos-i
//所找数据在后半部分 
			} else {
				pos += i; //pos=pos+i
			}
		}
		if (i == 0) break;
	}

	if (rndx) *rndx = pos;

	return ndx;
}




























//在用户指定的array结构体a中获取给定key的数据
data_unset *array_get_element(array *a, const char *key) {
	int ndx;
//strlen 计算字符串的长度，不包含'\0';strlen(key) + 1,即包含'\0'
	if (-1 != (ndx = array_get_index(a, key, strlen(key) + 1, NULL))) {
		return a->data[ndx];
	}
	return NULL;
}





























//在用户指定的array结构体a中获取一个未使用的data元素，并从a中去除
data_unset *array_get_unused_element(array *a, data_type_t t) {
	data_unset *ds = NULL;
//buffer.h中无作用宏
	UNUSED(t); 
	if (a->size == 0) return NULL;
	if (a->used == a->size) return NULL;
	if (a->data[a->used]) {
		ds = a->data[a->used];
		a->data[a->used] = NULL;
	}
	return ds;
}
























//在用户指定的array结构体a的data中插入du，返回NULL;若du的key与a中有匹配，则进行数据替换,返回旧数据
data_unset *array_replace(array *a, data_unset *du) {
	int ndx;
//进行插入数据
	if (-1 == (ndx = array_get_index(a, du->key->ptr, du->key->used, NULL))) {
		array_insert_unique(a, du);
		return NULL;
	} 
//进行替换数据
	else {
		data_unset *old = a->data[ndx];
		a->data[ndx] = du;
		return old;
	}
}























//插入一个用户给定的数据元素到array结构体a中
int array_insert_unique(array *a, data_unset *str) {
//ndx用于记录str在a－>data内的索引
	int ndx = -1;
//记录ndx在a－>sorted内的索引
	int pos = 0;
	size_t j;
// 如果str是需要按顺序排列，则必须按照a的数据顺序生成唯一的关键字
	if (str->key->used == 0 || str->is_index_key) {
		buffer_copy_long(str->key, a->unique_ndx++);
		str->is_index_key = 1;
	}
//通过key判断判断数据是否存在，若存在则调用该str的insert_dup函数进行free(str)
	if (-1 != (ndx = array_get_index(a, str->key->ptr, str->key->used, &pos))) {
		/* found, leave here */
		if (a->data[ndx]->type == str->type) {
			str->insert_dup(a->data[ndx], str);
		} else {
			fprintf(stderr, "a\n");
		}
		return 0;
	}
//若不存在，则进行插入
// 判断array结构体a中数据量大小，若大于INT_MAX,则错误返回
	if (a->used+1 > INT_MAX) {
		return -1;
	}
//若array结构体a的数据内存空间还没有，则进行创建a的数据内存空间
	if (a->size == 0) {
		a->size   = 16;
		a->data   = malloc(sizeof(*a->data)     * a->size);
		a->sorted = malloc(sizeof(*a->sorted)   * a->size);
		assert(a->data);
		assert(a->sorted);
		for (j = a->used; j < a->size; j++) a->data[j] = NULL;
//array结构体a的数据内存空间,但没有空闲的数据空间，则扩展数据空间
	} else if (a->size == a->used) {
		a->size  += 16;
		a->data   = realloc(a->data,   sizeof(*a->data)   * a->size);
		a->sorted = realloc(a->sorted, sizeof(*a->sorted) * a->size);
		assert(a->data);
		assert(a->sorted);
		for (j = a->used; j < a->size; j++) a->data[j] = NULL;
	}

	ndx = (int) a->used;
//数据插入
	a->data[a->used++] = str;

	if (pos != ndx &&
	    ((pos < 0) ||
	     buffer_caseless_compare(str->key->ptr, str->key->used, a->data[a->sorted[pos]]->key->ptr, a->data[a->sorted[pos]]->key->used) > 0)) {
		pos++;
	}

	/* move everything on step to the right */
	if (pos != ndx) {
		memmove(a->sorted + (pos + 1), a->sorted + (pos), (ndx - pos) * sizeof(*a->sorted));
	}

	/* insert */
	a->sorted[pos] = ndx;

	if (a->next_power_of_2 == (size_t)ndx) a->next_power_of_2 <<= 1;

	return 0;
}





























//按需要打印空格
void array_print_indent(int depth) {
	int i;
	for (i = 0; i < depth; i ++) {
		fprintf(stdout, "    ");
	}
}

























//获取用于指定array结构体a的数据元素中key的最大长度
size_t array_get_max_key_length(array *a) {
	size_t maxlen, i;

	maxlen = 0;
	for (i = 0; i < a->used; i ++) {
		data_unset *du = a->data[i];
		size_t len = strlen(du->key->ptr);

		if (len > maxlen) {
			maxlen = len;
		}
	}
	return maxlen;
}


























//打印用户指定的array结构体a的所有数据元素
int array_print(array *a, int depth) {
	size_t i;
	size_t maxlen;
	int oneline = 1;

	if (a->used > 5) {
		oneline = 0;
	}
	for (i = 0; i < a->used && oneline; i++) {
		data_unset *du = a->data[i];
		if (!du->is_index_key) {
			oneline = 0;
			break;
		}
		switch (du->type) {
			case TYPE_INTEGER:
			case TYPE_STRING:
			case TYPE_COUNT:
				break;
			default:
				oneline = 0;
				break;
		}
	}
	if (oneline) {
		fprintf(stdout, "(");
		for (i = 0; i < a->used; i++) {
			data_unset *du = a->data[i];
			if (i != 0) {
				fprintf(stdout, ", ");
			}
			du->print(du, depth + 1);
		}
		fprintf(stdout, ")");
		return 0;
	}

	maxlen = array_get_max_key_length(a);
	fprintf(stdout, "(\n");
	for (i = 0; i < a->used; i++) {
		data_unset *du = a->data[i];
		array_print_indent(depth + 1);
		if (!du->is_index_key) {
			int j;

			if (i && (i % 5) == 0) {
				fprintf(stdout, "# %zd\n", i);
				array_print_indent(depth + 1);
			}
			fprintf(stdout, "\"%s\"", du->key->ptr);
			for (j = maxlen - strlen(du->key->ptr); j > 0; j --) {
				fprintf(stdout, " ");
			}
			fprintf(stdout, " => ");
		}
		du->print(du, depth + 1);
		fprintf(stdout, ",\n");
	}
	if (!(i && (i - 1 % 5) == 0)) {
		array_print_indent(depth + 1);
		fprintf(stdout, "# %zd\n", i);
	}
	array_print_indent(depth);
	fprintf(stdout, ")");

	return 0;
}

























//用于调试上述对array结构体操作的函数
#ifdef DEBUG_ARRAY
int main (int argc, char **argv) {
	array *a;
	data_string *ds;
	data_count *dc;

	UNUSED(argc);
	UNUSED(argv);

	a = array_init();

	ds = data_string_init();
	buffer_copy_string_len(ds->key, CONST_STR_LEN("abc"));
	buffer_copy_string_len(ds->value, CONST_STR_LEN("alfrag"));

	array_insert_unique(a, (data_unset *)ds);

	ds = data_string_init();
	buffer_copy_string_len(ds->key, CONST_STR_LEN("abc"));
	buffer_copy_string_len(ds->value, CONST_STR_LEN("hameplman"));

	array_insert_unique(a, (data_unset *)ds);

	ds = data_string_init();
	buffer_copy_string_len(ds->key, CONST_STR_LEN("123"));
	buffer_copy_string_len(ds->value, CONST_STR_LEN("alfrag"));

	array_insert_unique(a, (data_unset *)ds);

	dc = data_count_init();
	buffer_copy_string_len(dc->key, CONST_STR_LEN("def"));

	array_insert_unique(a, (data_unset *)dc);

	dc = data_count_init();
	buffer_copy_string_len(dc->key, CONST_STR_LEN("def"));

	array_insert_unique(a, (data_unset *)dc);

	array_print(a, 0);

	array_free(a);

	fprintf(stderr, "%d\n",
	       buffer_caseless_compare(CONST_STR_LEN("Content-Type"), CONST_STR_LEN("Content-type")));

	return 0;
}
#endif
