#ifndef _LOG_H_
#define _LOG_H_

#include "server.h"

/* Close fd and _try_ to get a /dev/null for it instead.
 * Returns 0 on success and -1 on failure (fd gets closed in all cases)
 */
int openDevNull(int fd);

#define WP() log_error_write(srv, __FILE__, __LINE__, ""); //宏__FILE__和宏__LINE__分别用来表示当前文件名和当前行号，用来定位代码

int log_error_open(server *srv);
int log_error_close(server *srv);
int log_error_write(server *srv, const char *filename, unsigned int line, const char *fmt, ...);
int log_error_cycle(server *srv);

#endif
