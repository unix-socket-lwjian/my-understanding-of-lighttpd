#include <sys/types.h>

#include <string.h>


#include "base.h"
#include "inet_ntop_cache.h"
#include "sys-socket.h"

const char * inet_ntop_cache_get_ip(server *srv, sock_addr *addr) {
#ifdef HAVE_IPV6
	size_t ndx = 0, i;
	/*在缓存中查找IP记录是否已经存在*/
	for (i = 0; i < INET_NTOP_CACHE_MAX; i++) {
		if (srv->inet_ntop_cache[i].ts != 0) {
			if (srv->inet_ntop_cache[i].family == AF_INET6 &&
			    0 == memcmp(srv->inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16)) { //利用函数memcmp()进行比较
				/* IPv6 found in cache */
				break;
			} else if (srv->inet_ntop_cache[i].family == AF_INET &&
				   srv->inet_ntop_cache[i].addr.ipv4.s_addr == addr->ipv4.sin_addr.s_addr) {
				/* IPv4 found in cache */
				break;

			}
		}
	}
	/*记录未找到*/
	if (i == INET_NTOP_CACHE_MAX) {
		/* not found in cache */

		i = ndx;
		inet_ntop(addr->plain.sa_family,
			  addr->plain.sa_family == AF_INET6 ?
			  (const void *) &(addr->ipv6.sin6_addr) :
			  (const void *) &(addr->ipv4.sin_addr),
			  srv->inet_ntop_cache[i].b2, INET6_ADDRSTRLEN); //函数inet_ntop()原型为：const char *inet_ntop(int af,const void *src,char *dst,socklen_t cnt);函数功能为将类型为af的网络地址结构src，转换成主机序的字符串形式，
															//存放在长度为cnt的字符串中。该函数返回指向dst的指针，如果函数调用错误则返回值为NULL.

		srv->inet_ntop_cache[i].ts = srv->cur_ts;
		srv->inet_ntop_cache[i].family = addr->plain.sa_family;

		if (srv->inet_ntop_cache[i].family == AF_INET) {
			srv->inet_ntop_cache[i].addr.ipv4.s_addr = addr->ipv4.sin_addr.s_addr;
		} else if (srv->inet_ntop_cache[i].family == AF_INET6) {
			memcpy(srv->inet_ntop_cache[i].addr.ipv6.s6_addr, addr->ipv6.sin6_addr.s6_addr, 16);
		}
	}

	return srv->inet_ntop_cache[i].b2;
#else
	UNUSED(srv);
	return inet_ntoa(addr->ipv4.sin_addr); //函数inet_ntoa()和inet_ntop()函数功能一致，但是它不是线程安全函数，因此一般推荐使用inet_ntop()函数；
#endif
}
