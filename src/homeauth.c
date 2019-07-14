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
#include <sys/un.h>

#include "common.h"
#include "debug.h"
#include "homeauth.h"
#include "homeconfig.h"

void thread_authsvr(void *args);
authrequest *authGetConnection(authsvr *server, struct timeval *timeout);
int authReadRequest(authsvr * server, authrequest * r);
void authEndRequest(authrequest * r);
void authProcessRequest(authsvr * server, authrequest * r);


/*Adapter callback func of mainloop select for hpptd API func of httpdGetConnection*/
int authConnect(authsvr *server, int index){
    pid_t pid;
	authrequest *r;
    void **params;
    int result;
    pthread_t tid;

//    r = authGetConnection(server, NULL);

    struct sockaddr_in clnt_addr;/*只是声明，并没有赋值*/
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock = accept(server->serverSock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

    if(clnt_sock == -1){
        printf("appect error");
        return -1;
    }

    /**
     * 这一段直接fork一个子进程
     * 子进程处理单独处理完请求之后退出
     */
    if( (pid = fork()) == 0 ){
        close(server->serverSock);/*子进程不需要监听，关闭*/
        close(clnt_sock);/*处理完毕，关闭客户端连接*/
        exit(0);/*自觉退出*/
    }

    close(clnt_sock); /*连接已经交由子进程处理，父进程可以关闭客户端连接了*/

    /*close(server_sockfd);*/
        /*
         * We got a connection
         *
         * We should create another thread
         */
//        debug(LOG_INFO, "Received connection from %s, spawning worker thread", r->clientAddr);
        /* The void**'s are a simulation of the normal C
         * function calling sequence. */
        params = safe_malloc(2 * sizeof(void *));
        *params = server;
        *(params + 1) = r;

        result = pthread_create(&tid, NULL, (void *)thread_authsvr, (void *)params);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid);


    return 0;
}


/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void
thread_authsvr(void *args)
{
	void	**params;
	authsvr	*webserver;
	authrequest	*r;
	s_gwOptions *gwOptions = get_gwOptions();

	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	free(params); /* XXX We must release this ourselves. */

	if (authReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		authProcessRequest(webserver, r);

	}
	else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	}
	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	authEndRequest(r);
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
    /* Reset error */
    server->lastError = 0;
    result = 0;

    /* Allocate request struct */
    r = (authrequest *) malloc(sizeof(authrequest));
    if (r == NULL) {
        server->lastError = -3;
        return (NULL);
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

    return (0);
}

void
authEndRequest(authrequest * r)
{
    shutdown(r->clientSock, 2);
    close(r->clientSock);
    free(r);
}


void
authProcessRequest(authsvr * server, authrequest * r)
{


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

    if (bind(server_sockaddr, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) < 0) {
        close(server_sockaddr);
        free(newServer);
        debug(LOG_ERR, "%s: Bind Auth socket error", strerror(errno));
        return -1;
    }

    if(listen(server_sockfd, 20) == -1){
        debug(LOG_ERR, "%s: Listen Auth socket error", strerror(errno));
        return -1;
    }

    newServer->startTime = time(NULL);
    *ppserver= newServer;
    return 0;
}

