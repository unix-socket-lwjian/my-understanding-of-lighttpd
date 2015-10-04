#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>

#include "log.h"
#include "stat_cache.h"
#include "fdevent.h"
#include "etag.h"

#ifdef HAVE_ATTR_ATTRIBUTES_H
#include <attr/attributes.h>
#endif

#ifdef HAVE_FAM_H
# include <fam.h>
#endif

#include "sys-mmap.h"

/* NetBSD 1.3.x needs it */
#ifndef MAP_FAILED
# define MAP_FAILED -1
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#if 0
/* enables debug code for testing if all nodes in the stat-cache as accessable */
#define DEBUG_STAT_CACHE
#endif

/*
 * stat-cache
 *
 * we cache the stat() calls in our own storage
 * the directories are cached in FAM
 *
 * if we get a change-event from FAM, we increment the version in the FAM->dir mapping
 *
 * if the stat()-cache is queried we check if the version id for the directory is the
 * same and return immediatly.
 *
 *
 * What we need:
 *
 * - for each stat-cache entry we need a fast indirect lookup on the directory name
 * - for each FAMRequest we have to find the version in the directory cache (index as userdata)
 *
 * stat <<-> directory <-> FAMRequest
 *
 * if file is deleted, directory is dirty, file is rechecked ...
 * if directory is deleted, directory mapping is removed
 *
 * */














//定义fam监控模块的结构体
#ifdef HAVE_FAM_H
typedef struct {
// 用于操作该模块挂起，重启，取消等操作的函数的参数
	FAMRequest *req;
	FAMConnection *fc;
//文件所在目录
	buffer *name;
//文件目录版本号
	int version;
} fam_dir_entry;
#endif
















/* the directory name is too long to always compare on it
 * - we need a hash
 * - the hash-key is used as sorting criteria for a tree
 * - a splay-tree is used as we can use the caching effect of it
 */

/* we want to cleanup the stat-cache every few seconds, let's say 10
 *
 * - remove entries which are outdated since 30s
 * - remove entries which are fresh but havn't been used since 60s
 * - if we don't have a stat-cache entry for a directory, release it from the monitor
 */

#ifdef DEBUG_STAT_CACHE
typedef struct {
	int *ptr;

	size_t used;
	size_t size;
} fake_keys;

static fake_keys ctrl;
#endif




























//创建stat_cache结构体，并返回它
stat_cache *stat_cache_init(void) {
	stat_cache *fc = NULL;

	fc = calloc(1, sizeof(*fc));

	fc->dir_name = buffer_init();
	fc->hash_key = buffer_init();
#ifdef HAVE_FAM_H
	fc->fam = calloc(1, sizeof(*fc->fam));
#endif

#ifdef DEBUG_STAT_CACHE
	ctrl.size = 0;
#endif

	return fc;
}




























//创建文件状态缓冲器sce，并返回它
static stat_cache_entry * stat_cache_entry_init(void) {
	stat_cache_entry *sce = NULL;

	sce = calloc(1, sizeof(*sce));

	sce->name = buffer_init();
	sce->etag = buffer_init();
	sce->content_type = buffer_init();

	return sce;
}
























// 释放用户指定的文件状态缓冲器data
static void stat_cache_entry_free(void *data) {
	stat_cache_entry *sce = data;
	if (!sce) return;

	buffer_free(sce->etag);
	buffer_free(sce->name);
	buffer_free(sce->content_type);

	free(sce);
}

























//创建fam监控，并返回它
#ifdef HAVE_FAM_H
static fam_dir_entry * fam_dir_entry_init(void) {
	fam_dir_entry *fam_dir = NULL;

	fam_dir = calloc(1, sizeof(*fam_dir));

	fam_dir->name = buffer_init();

	return fam_dir;
}



























//// 释放用户指定的fam监控data
static void fam_dir_entry_free(void *data) {
	fam_dir_entry *fam_dir = data;

	if (!fam_dir) return;
/*
FAMCancelMonitor(FAMConnection *fc,FAMRequest *fc):
取消对fc指定的文件或文件夹的监视
*/
	FAMCancelMonitor(fam_dir->fc, fam_dir->req);

	buffer_free(fam_dir->name);
	free(fam_dir->req);

	free(fam_dir);
}
#endif




































//stat_cache结构体的释放
void stat_cache_free(stat_cache *sc) {
	while (sc->files) {
		int osize;
		splay_tree *node = sc->files;

		osize = sc->files->size;

		stat_cache_entry_free(node->data);
		sc->files = splaytree_delete(sc->files, node->key);

		assert(osize - 1 == splaytree_size(sc->files));
	}

	buffer_free(sc->dir_name);
	buffer_free(sc->hash_key);

#ifdef HAVE_FAM_H
	while (sc->dirs) {
		int osize;
		splay_tree *node = sc->dirs;

		osize = sc->dirs->size;

		fam_dir_entry_free(node->data);
		sc->dirs = splaytree_delete(sc->dirs, node->key);

		if (osize == 1) {
			assert(NULL == sc->dirs);
		} else {
			assert(osize == (sc->dirs->size + 1));
		}
	}

	if (sc->fam) {
		FAMClose(sc->fam); //该函数关闭到FAM的连接，执行成功返回0，失败返回-1.
		free(sc->fam);
	}
#endif
	free(sc);
}







































// 用于获取指定路径的文件的文件类型，存放在buf中
#ifdef HAVE_XATTR
static int stat_cache_attr_get(buffer *buf, char *name) {
	int attrlen;
	int ret;

	attrlen = 1024;
	buffer_prepare_copy(buf, attrlen);
	attrlen--;
	if(0 == (ret = attr_get(name, "Content-Type", buf->ptr, &attrlen, 0))) {
		buf->used = attrlen + 1;
		buf->ptr[attrlen] = '\0';
	}
	return ret;
}
#endif















// 获取对应在str中字符串的hash值，并返回
/* the famous DJB hash function for strings */
static uint32_t hashme(buffer *str) {
	uint32_t hash = 5381; //为什么是5381？
	const char *s;
	for (s = str->ptr; *s; s++) {
		hash = ((hash << 5) + hash) + *s;
	}

	hash &= ~(1 << 31); /* strip the highest bit */

	return hash;
}



























//该函数用于对外部文件变化事件做相应处理，即在外部被监控文件发生变化时（还有Lighttpd断开和FAM的连接时）被调用！
#ifdef HAVE_FAM_H
handler_t stat_cache_handle_fdevent(void *_srv, void *_fce, int revent) { //handler_t是一个枚举类型结构体，定义在settings.h头文件内。
	size_t i;
	server *srv = _srv;
	stat_cache *sc = srv->stat_cache;
	size_t events;

	UNUSED(_fce);
	/* */

	if ((revent & FDEVENT_IN) && //可读事件发生
	    sc->fam) {

		events = FAMPending(sc->fam);   //获取可读事件数目
		/*
			FAMPending(FAMConnection *fc)函数返回正整数表示有FAM event在队列中，返回0表示没有事件发生，-1表示发生错误。
			该函数调用后马上返回，既不阻塞等待事件发生。
		*/
		for (i = 0; i < events; i++) {
			FAMEvent fe;
			fam_dir_entry *fam_dir;
			splay_tree *node;
			int ndx, j;
			/*
			* FAMEvent结构体
			*typedef struct{
				FAMConnection* fc; //fc是通过函数FAMOpen或FAMOpen2初始化的
				FAMRequest fr;  //fr是通过函数FAMMonitorFile()或FAMMonitorDirectory()初始化的
				char *hostname; //现在已经不使用了，一般不要用它
				char filename[PATH_MAX]; //(发生改变的)被监控文件或文件夹的完整路径或是被监控目录下的文件名
				void* userdata; //可以指向任何数据，因此提供了从事件监控设置函数到事件发生处理函数之间数据传递方法。
				FAMCodes code; //code是枚举结构FAMCodes中的一个取值，表示当前发生的是哪个事件。(FAMChanged、FAMDeleted、FAMCreated、FAMMove等)
			}FAMEvent;
			*
			*/

			FAMNextEvent(sc->fam, &fe);  //FAMNextEvent函数将逐个把事件信息存储到结构体FAMEvent参数fe内隐性传出

			/* handle event */

			switch(fe.code) { //如果文件名所指的是目录（并且事件是FAMDeleted或FAMMoved）则移除相应节点。获得用户数据，该数据从函数stat_cache_get_entry内传递过来。
			case FAMChanged:
			case FAMDeleted:
			case FAMMoved:
				/* if the filename is a directory remove the entry */

				fam_dir = fe.userdata;
				fam_dir->version++; //更新版本号

				/* file/dir is still here */
				if (fe.code == FAMChanged) break; //知识目录文件状态改变事件则跳出，不用进行接下来的节点删除操作。

				/* we have 2 versions, follow and no-follow-symlink */
					/*
						有两种情况（follow and no-follow-symlink），但是并不知道是哪种情况，因此对这种情况的删除操作都要尝试进行,
						结构最多就是某一次尝试失败。
					*/					
				for (j = 0; j < 2; j++) {
					buffer_copy_string(sc->hash_key, fe.filename); //获得发生改变的文件名
					buffer_append_long(sc->hash_key, j);

					ndx = hashme(sc->hash_key);

					sc->dirs = splaytree_splay(sc->dirs, ndx);
					node = sc->dirs;

					if (node && (node->key == ndx)) {
						int osize = splaytree_size(sc->dirs);

						fam_dir_entry_free(node->data);
						sc->dirs = splaytree_delete(sc->dirs, ndx);

						assert(osize - 1 == splaytree_size(sc->dirs));
					}
				}
				break;
			default:
				break;
			}
		}
	}

	if (revent & FDEVENT_HUP) { //挂断事件
		/* fam closed the connection */
		srv->stat_cache->fam_fcce_ndx = -1;

		fdevent_event_del(srv->ev, &(sc->fam_fcce_ndx), FAMCONNECTION_GETFD(sc->fam));
		fdevent_unregister(srv->ev, FAMCONNECTION_GETFD(sc->fam));

		FAMClose(sc->fam);
		free(sc->fam);

		sc->fam = NULL;
	}

	return HANDLER_GO_ON;
}




























static int buffer_copy_dirname(buffer *dst, buffer *file) {
	size_t i;

	if (buffer_is_empty(file)) return -1;

	for (i = file->used - 1; i+1 > 0; i--) {
		if (file->ptr[i] == '/') {
			buffer_copy_string_len(dst, file->ptr, i);
			return 0;
		}
	}

	return -1;
}
#endif
































//查询dname是否为符号链接（link），另外获得的文件信息由lst返回
#ifdef HAVE_LSTAT
static int stat_cache_lstat(server *srv, buffer *dname, struct stat *lst) {
//lstat函数：获取一些文件相关的信息	
	if (lstat(dname->ptr, lst) == 0) {
		return S_ISLNK(lst->st_mode) ? 0 : 1;
	}
	else {
		log_error_write(srv, __FILE__, __LINE__, "sbs",
				"lstat failed for:",
				dname, strerror(errno));
	};
	return -1;
}
#endif


























































//根据用户指定的路径文件名在文件状态缓冲器伸展树中找出该文件的最新状态信息，并通过ret_sce返回
handler_t stat_cache_get_entry(server *srv, connection *con, buffer *name, stat_cache_entry **ret_sce) {
#ifdef HAVE_FAM_H
	fam_dir_entry *fam_dir = NULL;
	int dir_ndx = -1;
	splay_tree *dir_node = NULL;
#endif
	stat_cache_entry *sce = NULL;
	stat_cache *sc;
	struct stat st;
	size_t k;
	int fd;
	struct stat lst;
#ifdef DEBUG_STAT_CACHE
	size_t i;
#endif

	int file_ndx;
	splay_tree *file_node = NULL;

	*ret_sce = NULL;


//文件状态信息缓存器
	sc = srv->stat_cache; 
//文件路径临时存储
	buffer_copy_string_buffer(sc->hash_key, name); 
//follow_symlink取值0或1
	buffer_append_long(sc->hash_key, con->conf.follow_symlink); 
//文件路径字符串计算对应HASH值
	file_ndx = hashme(sc->hash_key); 
//在缓存器中的文件状态信息存储伸展树中查找记录节点	
	sc->files = splaytree_splay(sc->files, file_ndx);

#ifdef DEBUG_STAT_CACHE
	for (i = 0; i < ctrl.used; i++) {
		if (ctrl.ptr[i] == file_ndx) break;
	}
#endif

	if (sc->files && (sc->files->key == file_ndx)) {
#ifdef DEBUG_STAT_CACHE

		assert(i < ctrl.used);
#endif


//找到的记录节点
		file_node = sc->files; 
//该记录节点保存的文件状态等相关信息
		sce = file_node->data; 



		if (buffer_is_equal(name, sce->name)) {
			if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_SIMPLE) { //简单引擎
//判断记录节点保存的信息是否为新的
				if (sce->stat_ts == srv->cur_ts) { 
//隐性传出
					*ret_sce = sce; 
//返回执行成功的代码
					return HANDLER_GO_ON; 
				}
			}
		} 
//在伸展树中没有找到相应的文件状态缓冲器节点
	   else {

			file_node = NULL;
		}
	} else {
#ifdef DEBUG_STAT_CACHE
		if (i != ctrl.used) {
			fprintf(stderr, "%s.%d: %08x was already inserted but not found in cache, %s\n", __FILE__, __LINE__, file_ndx, name->ptr);
		}
		assert(i == ctrl.used);
#endif
	}


//
#ifdef HAVE_FAM_H
	/* dir-check */
	if (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM) {
//查找文件所在的父目录
		if (0 != buffer_copy_dirname(sc->dir_name, name)) { 
			log_error_write(srv, __FILE__, __LINE__, "sb",
				"no '/' found in filename:", name);
			return HANDLER_ERROR;
		}

		buffer_copy_string_buffer(sc->hash_key, sc->dir_name);
		buffer_append_long(sc->hash_key, con->conf.follow_symlink);
//计算父目录的Hash值
		dir_ndx = hashme(sc->hash_key); 

		sc->dirs = splaytree_splay(sc->dirs, dir_ndx);

		if (sc->dirs && (sc->dirs->key == dir_ndx)) {
			dir_node = sc->dirs;
		}
//判断文件记录节点和监控父节点对应节点是否都找到了			
		if (dir_node && file_node) { 
			/* we found a file */

			sce = file_node->data;
			fam_dir = dir_node->data;

			if (fam_dir->version == sce->dir_version) {
				/* the stat()-cache entry is still ok */

				*ret_sce = sce;
				return HANDLER_GO_ON;
			}
		}
	}
#endif


//接下来执行的是文件状态缓冲器没有命中或者文件已被修改过的处理

//通过文件名获取文件信息，并保存在buf所指的结构体stat中。
	if (-1 == stat(name->ptr, &st)) { 
		return HANDLER_ERROR;
	}

// 尝试去读这个文件，看是否可读
	if (S_ISREG(st.st_mode)) {

		if (-1 == (fd = open(name->ptr, O_RDONLY))) {
			return HANDLER_ERROR;
		}
		close(fd);
	}
//如果节点不存在，就新创建一个文件状态信息节点，并将其插入到文件状态缓冲器伸展树的相应位置
	if (NULL == sce) { 
		int osize = 0;

		if (sc->files) {
			osize = sc->files->size;
		}

		sce = stat_cache_entry_init();
		buffer_copy_string_buffer(sce->name, name);

		sc->files = splaytree_insert(sc->files, file_ndx, sce); //插入新记录数
#ifdef DEBUG_STAT_CACHE
		if (ctrl.size == 0) {
			ctrl.size = 16;
			ctrl.used = 0;
			ctrl.ptr = malloc(ctrl.size * sizeof(*ctrl.ptr));
		} else if (ctrl.size == ctrl.used) {
			ctrl.size += 16;
			ctrl.ptr = realloc(ctrl.ptr, ctrl.size * sizeof(*ctrl.ptr));
		}

		ctrl.ptr[ctrl.used++] = file_ndx;

		assert(sc->files);
		assert(sc->files->data == sce);
		assert(osize + 1 == splaytree_size(sc->files));
#endif
	}

	sce->st = st;
	sce->stat_ts = srv->cur_ts;



//文件缓冲器sce的is_symlink赋值
#ifdef HAVE_LSTAT
	sce->is_symlink = 0;

	if (!con->conf.follow_symlink) {
		if (stat_cache_lstat(srv, name, &lst)  == 0) { //找到符号链接文件
#ifdef DEBUG_STAT_CACHE
				log_error_write(srv, __FILE__, __LINE__, "sb",
						"found symlink", name);
#endif
				sce->is_symlink = 1;
		}

		else if ((name->used > 2)) { //假定根文件不能符号链接
			buffer *dname;
			char *s_cur;

			dname = buffer_init();
			buffer_copy_string_buffer(dname, name);

			while ((s_cur = strrchr(dname->ptr,'/'))) { //strrchr(dname->ptr,'/') 找到dname->ptr所指向的字符串里，'/'最后一次出现的位置
				*s_cur = '\0'; //将/转换成'\0'，去掉后面的部分
				dname->used = s_cur - dname->ptr + 1;
				if (dname->ptr == s_cur) { //为根目录
#ifdef DEBUG_STAT_CACHE
					log_error_write(srv, __FILE__, __LINE__, "s", "reached /");
#endif
					break;
				}
#ifdef DEBUG_STAT_CACHE
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"checking if", dname, "is a symlink");
#endif
				if (stat_cache_lstat(srv, dname, &lst)  == 0) { //如果该目录吻符号链接，则设置标志位并跳出，否者继续父目录判断
					sce->is_symlink = 1;
#ifdef DEBUG_STAT_CACHE
					log_error_write(srv, __FILE__, __LINE__, "sb",
							"found symlink", dname);
#endif
					break;
				};
			};
			buffer_free(dname);
		};
	};
#endif




//文件缓冲器sce的文件类型和etag赋值
	if (S_ISREG(st.st_mode)) {
		/* determine mimetype */
		buffer_reset(sce->content_type);

		for (k = 0; k < con->conf.mimetypes->used; k++) {
			data_string *ds = (data_string *)con->conf.mimetypes->data[k];
			buffer *type = ds->key;

			if (type->used == 0) continue;

			/* check if the right side is the same */
			if (type->used > name->used) continue;

			if (0 == strncasecmp(name->ptr + name->used - type->used, type->ptr, type->used - 1)) {
				buffer_copy_string_buffer(sce->content_type, ds->value);
				break;
			}
		}
 		etag_create(sce->etag, &(sce->st), con->etag_flags);
#ifdef HAVE_XATTR
		if (con->conf.use_xattr && buffer_is_empty(sce->content_type)) {
			stat_cache_attr_get(sce->content_type, name->ptr);
		}
#endif
	} else if (S_ISDIR(st.st_mode)) {
 		etag_create(sce->etag, &(sce->st), con->etag_flags);
	}




//判断该目录是否已经FAM注册了，如果没有则注册	
#ifdef HAVE_FAM_H
	if (sc->fam &&
	    (srv->srvconf.stat_cache_engine == STAT_CACHE_ENGINE_FAM)) {
		if (!dir_node) {
			fam_dir = fam_dir_entry_init();
			fam_dir->fc = sc->fam;

			buffer_copy_string_buffer(fam_dir->name, sc->dir_name);

			fam_dir->version = 1;

			fam_dir->req = calloc(1, sizeof(FAMRequest));
//目录的FAM注册
			if (0 != FAMMonitorDirectory(sc->fam, fam_dir->name->ptr,
						     fam_dir->req, fam_dir)) {

				log_error_write(srv, __FILE__, __LINE__, "sbsbs",
						"monitoring dir failed:",
						fam_dir->name, 
						"file:", name,
						FamErrlist[FAMErrno]);

				fam_dir_entry_free(fam_dir);
			} else {
				int osize = 0;

			       	if (sc->dirs) {
					osize = sc->dirs->size;
				}
//将目录插入FAM监控伸展树中
				sc->dirs = splaytree_insert(sc->dirs, dir_ndx, fam_dir);
				assert(sc->dirs);
				assert(sc->dirs->data == fam_dir);
				assert(osize == (sc->dirs->size - 1));
			}
		} else {
			fam_dir = dir_node->data;
		}

		
//文件缓冲器sce的目录版本、目录索引赋值
		if (fam_dir) {
			sce->dir_version = fam_dir->version;
			sce->dir_ndx     = dir_ndx;
		}
	}
#endif

	*ret_sce = sce;

	return HANDLER_GO_ON;
}







































//被下面tat_cache_trigger_cleanup调用
static int stat_cache_tag_old_entries(server *srv, splay_tree *t, int *keys, size_t *ndx) {
	stat_cache_entry *sce;

	if (!t) return 0;
		//遍历：左->右->中，即后序遍历
	stat_cache_tag_old_entries(srv, t->left, keys, ndx);
	stat_cache_tag_old_entries(srv, t->right, keys, ndx);

	sce = t->data;
	
//超时时间定义
	if (srv->cur_ts - sce->stat_ts > 2) {
		keys[(*ndx)++] = t->key; //将待删除节点的索引记录下来
	}

	return 0;
}























//该函数用于删除距上次被访问时间超过2秒的文件状态缓冲器节点
int stat_cache_trigger_cleanup(server *srv) {
	stat_cache *sc;
	size_t max_ndx = 0, i;
	int *keys;

	sc = srv->stat_cache;

	if (!sc->files) return 0;

	keys = calloc(1, sizeof(size_t) * sc->files->size);

	stat_cache_tag_old_entries(srv, sc->files, keys, &max_ndx); //获取待删除节点

	for (i = 0; i < max_ndx; i++) { //进行清除操作
		int ndx = keys[i];
		splay_tree *node;

		sc->files = splaytree_splay(sc->files, ndx);

		node = sc->files;

		if (node && (node->key == ndx)) {
#ifdef DEBUG_STAT_CACHE
			size_t j;
			int osize = splaytree_size(sc->files);
			stat_cache_entry *sce = node->data;
#endif
			stat_cache_entry_free(node->data);
			sc->files = splaytree_delete(sc->files, ndx);

#ifdef DEBUG_STAT_CACHE
			for (j = 0; j < ctrl.used; j++) {
				if (ctrl.ptr[j] == ndx) {
					ctrl.ptr[j] = ctrl.ptr[--ctrl.used];
					break;
				}
			}

			assert(osize - 1 == splaytree_size(sc->files));
#endif
		}
	}

	free(keys);

	return 0;
}
