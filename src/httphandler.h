/*
 * httphandler.h
 *
 *  Created on: 2019年6月23日
 *      Author: jerome
 */

#ifndef SRC_HTTPHANDLER_H_
#define SRC_HTTPHANDLER_H_

#include "httpd.h"

void thread_httpd(void *args);

int rcvHttpConnection(httpd *server, int index);
int initWebserver(httpd **ppserver, struct in_addr svraddr, int port);
int endWebserver(httpd *pserver);

#endif /* SRC_HTTPHANDLER_H_ */
