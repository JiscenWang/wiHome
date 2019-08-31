/*
 * functions.h
 *
 *  Created on: 2019年6月21日
 *      Author: jerome
 */

#ifndef SRC_FUNCTIONS_H_
#define SRC_FUNCTIONS_H_
#include <stdarg.h>             /* For va_list */
#include <sys/types.h>          /* For fork */
#include <unistd.h>             /* For fork */
#include <sys/socket.h>


void save_pid_file(const char *pf);

time_t mainclock_tick();

int safe_sendto(int s, const void *b, size_t blen, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
size_t strlcpy(char *dst, const char *src, size_t dsize);
pid_t safe_fork(void);
void *safe_malloc(size_t size);
int safe_read(int s, void *b, size_t blen);
char *safe_strdup(const char *s);
int safe_asprintf(char **strp, const char *fmt, ...);
void checkGwOnline();

#endif /* SRC_FUNCTIONS_H_ */
