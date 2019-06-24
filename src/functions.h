/*
 * functions.h
 *
 *  Created on: 2019年6月21日
 *      Author: jerome
 */

#ifndef SRC_FUNCTIONS_H_
#define SRC_FUNCTIONS_H_

void save_pid_file(const char *pf);

time_t mainclock_tick();

int safe_sendto(int s, const void *b, size_t blen, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

#endif /* SRC_FUNCTIONS_H_ */
