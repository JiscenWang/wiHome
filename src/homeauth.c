/*
 * jauth.c
 *
 *  Created on: Apr 30, 2019
 *      Author: jerome
 */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
/*for safely inet_pton(),inet_ntop()*/
#include <arpa/inet.h>

#include "common.h"
#include "debug.h"
#include "homeauth.h"
#include "homeconfig.h"
#include "gatewayapi.h"
#include "functions.h"

void thread_authsvr(void *args);
authrequest *authGetConnection(authsvr *server, struct timeval *timeout);
int authReadRequest(authsvr * server, authrequest * r);
void authEndRequest(authrequest * r);
void authProcessRequest(authsvr * server, authrequest * r);

int authReadLine(request * r, char *destBuf, int len)
{
    char curChar, *dst;
    int count;

	if(r->readBufRemain == 0){
	    bzero(r->readBuf, HTTP_READ_BUF_LEN + 1);
	    r->readBufRemain = read(r->clientSock, r->readBuf, HTTP_READ_BUF_LEN);

	    if (r->readBufRemain < 1)
	        return (0);
	    r->readBuf[r->readBufRemain] = 0;
	    r->readBufPtr = r->readBuf;
	}

    count = 0;
    dst = destBuf;
    while (count < r->readBufRemain) {

    	curChar = *r->readBufPtr++;
    	r->readBufRemain--;

        if (curChar == '\n' || !isascii(curChar)) {
            *dst = 0;
            return (1);
        }
        count++;
        if (curChar == '\r') {

            continue;
        } else {
            *dst++ = curChar;
        }
    }
    *dst = 0;
    return (1);
}

authrequest *
authGetConnection(server, timeout)
authsvr *server;
struct timeval *timeout;
{
    int result;
    struct sockaddr_in addr;
    socklen_t addrLen;
    char *ipaddr;
    authrequest *r;

    result = 0;

    /* Allocate request struct */
    r = (authrequest *) malloc(sizeof(authrequest));
    if (r == NULL) {
        return NULL;
    }
    memset((void *)r, 0, sizeof(authrequest));
    /* Get on with it */
    bzero(&addr, sizeof(addr));
    addrLen = sizeof(addr);
    r->clientSock = accept(server->serverSock, (struct sockaddr *)&addr, &addrLen);

    ipaddr = inet_ntoa(addr.sin_addr);
    if (ipaddr) {
        strncpy(r->clientAddr, ipaddr, HTTP_IP_ADDR_LEN);
        r->clientAddr[HTTP_IP_ADDR_LEN - 1] = 0;
    } else
        *r->clientAddr = 0;
    r->readBufRemain = 0;
    r->readBufPtr = NULL;

    return (r);
}


int
authReadRequest(authsvr * server, authrequest * r)
{
    char buf[HTTP_MAX_LEN];
    char *cp, *cp2;
    int count, inHeaders;

    count = 0;
    while (authReadLine(r, buf, HTTP_MAX_LEN) > 0) {
        count++;
        /*First line for hello handshaking*/
        if (count == 1) {
            cp = cp2 = buf;
            while (isalpha((unsigned char)*cp2))
                cp2++;
            *cp2 = 0;
            if (strcasecmp(cp, "HelloWorld") == 0){
            	r->authRequest = 1;
            }else{
            	r->authRequest = 0;
            }
            continue;
        }

        if (count < MAX_AUTH_LINES) {
            if (*buf == 0) {
                break;
            }

            if (strncasecmp(buf, "My Name: ", 9) == 0) {
                cp = strchr(buf, ':');
                if (cp) {
                    cp += 2;
                    cp = strchr(cp, ' ') + 1;
                    if (cp) {
                    	strncpy(r->clientName, cp, MAX_AUTH_NAME_LENGTH);
                    }
                }
            }
            continue;
        }else{
            break;
        }
    }
    return (0);
}

void
authEndRequest(authrequest * r)
{
    shutdown(r->clientSock, 2);
    close(r->clientSock);
    free(r);
}


int authProcessRequest(authsvr * server, authrequest * r)
{
	struct gateway_t *pgateway;
	struct ippoolm_t *ipm;
	struct ipconnections_t *peerconn = 0;
	struct in_addr clientIP;
	int err = 0;

	if((r->authRequest ==1) && (r->clientAddr != NULL)){
		pgateway = server->gateway;

	    err = inet_pton(AF_INET, r->clientAddr, &clientIP);   /* 将字符串转换为二进制 */
	    if(err > 0){
			debug(LOG_ERR, "inet_pton:ip,%s value is:0x%x\n", r->clientAddr, clientIP.s_addr);
			return -1;
	    }

		if (ippoolGetip(pgateway->ippool, &ipm, &clientIP)) {
			debug(LOG_DEBUG, "Quit auth procedure with unknown client: %s", r->clientAddr);
		    return -1;
		}

		peerconn = (struct ipconnections_t *)ipm->peer;

		if (peerconn == NULL) {
			debug(LOG_ERR, "No dnlink protocol defined for %s", r->clientAddr);
			return 0;
		}

		peerconn->authstate = AUTH_CLIENT;
		peerconn->clientSock = r->clientSock;
		peerconn->lastauthtime = mainclock_tick();
	}
	return 0;
}

void
thread_authsvr(void *args)
{
	void	**params;
	authsvr	*authserver;
	authrequest	*r;
	s_gwOptions *gwOptions = get_gwOptions();

	params = (void **)args;
	authserver = *params;
	r = *(params + 1);
	free(params); /* XXX We must release this ourselves. */

	if (authReadRequest(authserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing auth request from %s", r->clientAddr);
		authProcessRequest(authserver, r);
	}
	else {
		debug(LOG_DEBUG, "No valid auth request received from %s", r->clientAddr);
		debug(LOG_DEBUG, "Closing auth connection with %s", r->clientAddr);
		authEndRequest(r);
	}
//	debug(LOG_DEBUG, "Closing auth connection with %s", r->clientAddr);
//	authEndRequest(r);
}


/*Adapter callback func of mainloop select for hpptd API func of httpdGetConnection*/
int authConnect(authsvr *server, int index){
    pid_t pid;
	authrequest *r;
    void **params;
    int result;
    pthread_t tid;

    r = authGetConnection(server, NULL);
    if(r == NULL){
        debug(LOG_ERR, "Failed to allocate request memory");
        return -1;
    }
    if(r->clientSock < 0){
        debug(LOG_ERR, "Failed to accept a new connection");
        return -1;
    }

    debug(LOG_DEBUG, "Received authen connection from %s, spawning worker thread", r->clientAddr);

	params = safe_malloc(2 * sizeof(void *));
	*params = server;
	*(params + 1) = r;

	result = pthread_create(&tid, NULL, (void *)thread_authsvr, (void *)params);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new authen thread - exiting");
		termination_handler(0);
	}
	pthread_detach(tid);

    return 0;
}


/* Initializes the web server */
int initAuthserver(httpd **ppserver, char *address, int port){
	authsvr *newServer;
    int server_sockfd = 0;
    int opt;
    struct sockaddr_in server_sockaddr;

    /*
     ** Create the handle and setup it's basic config
     */
    newServer = malloc(sizeof(authsvr));
    if (newServer == NULL)
        return -1;
    bzero(newServer, sizeof(authsvr));
    newServer->port = port;

    if (address == HTTP_ANY_ADDR)
        newServer->host = HTTP_ANY_ADDR;
    else
        newServer->host = strdup(address);

    server_sockfd = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    if (server_sockfd < 0) {
        free(newServer);
        debug(LOG_ERR, "%s: Creat Auth socket error", strerror(errno));
        return -1;
    }
    opt = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int)) < 0) {
        close(server_sockfd);
        free(newServer);
        debug(LOG_ERR, "%s: Creat Auth socket error", strerror(errno));
        return -1;
    }
    newServer->serverSock = server_sockfd;

    bzero(&server_sockaddr, sizeof(server_sockaddr));

    /*使用IPv4协议*/
    server_sockaddr.sin_family = AF_INET;

    if (newServer->host == HTTP_ANY_ADDR) {
    	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
    	/*绑定Gateway IP*/
    	server_sockaddr.sin_addr.s_addr = inet_addr(newServer->host);
    }
	/*监听Auth端口*/
    server_sockaddr.sin_port = htons((u_short) newServer->port);

    if (bind(server_sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) < 0) {
        close(server_sockfd);
        free(newServer);
        debug(LOG_ERR, "%s: Bind Auth socket error", strerror(errno));
        return -1;
    }

    /*Jerome TBD, change 20 to a Macro definition*/
    if(listen(server_sockfd, 20) == -1){
        debug(LOG_ERR, "%s: Listen Auth socket error", strerror(errno));
        return -1;
    }

    newServer->startTime = time(NULL);
    *ppserver= newServer;
    return 0;
}

