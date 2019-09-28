/*
 * homeauth.h
 *
 *  Created on: Apr 30, 2019
 *      Author: jerome
 */

#ifndef SRC_JAUTH_H_
#define SRC_JAUTH_H_

#include "httpd.h"

#define MAX_AUTH_LINES		20
#define MAX_AUTH_NAME_LENGTH		64


  typedef struct {
     int port, serverSock, startTime, lastError;
     char *host;
     struct gateway_t *gateway;
     void (*errorFunction304) (), (*errorFunction403) (), (*errorFunction404) ();
  } authsvr;

  typedef struct {
     int clientSock, readBufRemain;
     char readBuf[HTTP_READ_BUF_LEN + 1], *readBufPtr, clientAddr[HTTP_IP_ADDR_LEN];
     int authRequest;
     char clientName[MAX_AUTH_NAME_LENGTH];
     int action;   /*1: connect; 0: disconnect*/
  } authrequest;

  int initAuthserver(httpd **ppserver, struct in_addr svraddr, int port);
  int authConnect(authsvr *server, int index);
  int endAuthserver(httpd *pserver);
#endif /* SRC_JAUTH_H_ */
