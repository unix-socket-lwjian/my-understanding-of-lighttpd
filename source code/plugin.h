#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "base.h"
#include "buffer.h"

#define SERVER_FUNC(x) \
		static handler_t x(server *srv, void *p_d)

#define CONNECTION_FUNC(x) \
		static handler_t x(server *srv, connection *con, void *p_d)

#define INIT_FUNC(x) \
		static void *x()

#define FREE_FUNC          SERVER_FUNC
#define TRIGGER_FUNC       SERVER_FUNC
#define SETDEFAULTS_FUNC   SERVER_FUNC
#define SIGHUP_FUNC        SERVER_FUNC

#define SUBREQUEST_FUNC    CONNECTION_FUNC
#define JOBLIST_FUNC       CONNECTION_FUNC
#define PHYSICALPATH_FUNC  CONNECTION_FUNC
#define REQUESTDONE_FUNC   CONNECTION_FUNC
#define URIHANDLER_FUNC    CONNECTION_FUNC

#define PLUGIN_DATA        size_t id







//Lighttpd利用结构体plugin来组织一个插件 
typedef struct {
//插件的版本号
	size_t version;
//插件的名称
	buffer *name; 

//不是每个插件都会全部用到下述的15个函数指针！

//Lighttpd主程序加载插件完成后，调用该函数创建插件的数据结构存储空间plugin_data
	void *(* init)                       ();
//Lighttpd主程序解释完配置文件后调用该函数从配置信息中获取插件相关的配置信息
	handler_t (* set_defaults)           (server *srv, void *p_d);
//Lighttpd主程序在卸载插件过程中调用该函数
	handler_t (* cleanup)                (server *srv, void *p_d);
//Lighttpd主程序执行过程中每隔一秒就调用一次该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）                                                                                   /* is called ... */
	handler_t (* handle_trigger)         (server *srv, void *p_d);                  
//Lighttpd主程序收到sighup信号时调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR） 
	handler_t (* handle_sighup)          (server *srv, void *p_d);                  
//原始的请求信息被设置后调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR） 
	handler_t (* handle_uri_raw)         (server *srv, connection *con, void *p_d);  
//解码后的请求信息被设置后调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_uri_clean)       (server *srv, connection *con, void *p_d);   
//处理完相对路径而需要docroot时调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_docroot)         (server *srv, connection *con, void *p_d);    
//连接请求绝对路径被创建并且没有其他处理函数可调用时调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_physical)        (server *srv, connection *con, void *p_d);  
//连接请求处理完后调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_request_done)    (server *srv, connection *con, void *p_d);    
//请求连接connection关闭时，调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_connection_close)(server *srv, connection *con, void *p_d);    
//请求连接connection状态发生变化时调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_joblist)         (server *srv, connection *con, void *p_d); 
//当绝对路径被设置并且检查之后调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_subrequest_start)(server *srv, connection *con, void *p_d);
//连接请求处理函数http_response_prepare()末尾初调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* handle_subrequest)      (server *srv, connection *con, void *p_d);    /* */
//重置请求连接connection时，调用该函数，功能由插件定义，返回：成功（HANDLER_GO_ON），失败（HANDLER_ERROR）
	handler_t (* connection_reset)       (server *srv, connection *con, void *p_d);    /* */
//记录插件的相关信息，指向plugin_data结构体
	void *data;

	/* dlopen handle */
	void *lib;
} plugin;









int plugins_load(server *srv);
void plugins_free(server *srv);

handler_t plugins_call_handle_uri_raw(server *srv, connection *con);
handler_t plugins_call_handle_uri_clean(server *srv, connection *con);
handler_t plugins_call_handle_subrequest_start(server *srv, connection *con);
handler_t plugins_call_handle_subrequest(server *srv, connection *con);
handler_t plugins_call_handle_request_done(server *srv, connection *con);
handler_t plugins_call_handle_docroot(server *srv, connection *con);
handler_t plugins_call_handle_physical(server *srv, connection *con);
handler_t plugins_call_handle_connection_close(server *srv, connection *con);
handler_t plugins_call_handle_joblist(server *srv, connection *con);
handler_t plugins_call_connection_reset(server *srv, connection *con);

handler_t plugins_call_handle_trigger(server *srv);
handler_t plugins_call_handle_sighup(server *srv);

handler_t plugins_call_init(server *srv);
handler_t plugins_call_set_defaults(server *srv);
handler_t plugins_call_cleanup(server *srv);

int config_insert_values_global(server *srv, array *ca, const config_values_t *cv);
int config_insert_values_internal(server *srv, array *ca, const config_values_t *cv);
int config_setup_connection(server *srv, connection *con);
int config_patch_connection(server *srv, connection *con, comp_key_t comp);
int config_check_cond(server *srv, connection *con, data_config *dc);
int config_append_cond_match_buffer(connection *con, data_config *dc, buffer *buf, int n);

#endif
