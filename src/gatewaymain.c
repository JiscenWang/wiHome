/*
 * Jerome Build
*/

/*####Jerome, checked ongoing*/

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common.h"
#include "debug.h"
#include "homeconfig.h"
#include "gatewaymain.h"
#include "gatewayapi.h"
#include "ipprocessing.h"
#include "homeconfig.h"
#include "httpd.h"
#include "functions.h"

#include "httphandler.h"
#include "homenet.h"
#include "homeauth.h"
#include "../config.h"

struct gateway_t *homeGateway = NULL;                /* home gateway */

/* The internal web server */
httpd * webServer = NULL;
authsvr * authserver = NULL;

struct timespec mainclock;
/*End, Jerome*/

/** XXX Ugly hack 
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_ping = 0;
static pthread_t tid_stop = 0;

time_t started_time = 0;
struct timespec mainclock;
static int whctl_socket_server;

static int
create_unix_socket(const char *sock_name)
{
    struct sockaddr_un sa_un;
    int sock;

    memset(&sa_un, 0, sizeof(sa_un));

    if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
        /* TODO: Die handler with logging.... */
        debug(LOG_ERR, "WDCTL socket name too long");
        return -1;
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        debug(LOG_DEBUG, "Could not get unix socket: %s", strerror(errno));
        return -1;
    }
    debug(LOG_DEBUG, "Got unix socket %d", sock);

    /* If it exists, delete... Not the cleanest way to deal. */
    unlink(sock_name);

    debug(LOG_DEBUG, "Filling sockaddr_un");
    strcpy(sa_un.sun_path, sock_name);
    sa_un.sun_family = AF_UNIX;

    debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));

    /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
    if (bind(sock, (struct sockaddr *)&sa_un, sizeof(struct sockaddr_un))) {
        debug(LOG_ERR, "Could not bind unix socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 5)) {
        debug(LOG_ERR, "Could not listen on control socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}


static void printUsage(void)
{
    fprintf(stdout, "wiHome [options]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -f            Run in foreground\n");
    fprintf(stdout, "  -d <level>    Debug level\n");
    fprintf(stdout, "  -s            Log to syslog\n");
    fprintf(stdout, "  -h            Print usage\n");
    fprintf(stdout, "\n");
}


/** Uses getopt() to parse the command line and set configuration values
 */
void parseCommandline(int argc, char **argv)
{
    int c;
    int i;

	s_gwOptions *gwOptions = get_gwOptions();
    while (-1 != (c = getopt(argc, argv, "hfd:sv"))) {

        switch (c) {

        case 'h':
        	printUsage();
            exit(1);
            break;

        case 'f':
        	gwOptions->daemon = 0;
            debugconf.log_stderr = 1;
            break;

        case 'd':
            if (optarg) {
                debugconf.debuglevel = atoi(optarg);
            }
            break;

        case 's':
            debugconf.log_syslog = 1;
            break;

        default:
        	printUsage();
            exit(1);
            break;

        }
    }
}


/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */

static void sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

    rc = waitpid(-1, &status, WNOHANG);

    debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
}

/** @internal
 * Registers all the signal handlers
 */
static void initSignals(void)
{
    struct sigaction sa;

    debug(LOG_DEBUG, "Initializing signal handlers");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }
}


void stopWhome(void *arg)
{
    int *fd;
    char *sock_name;
    struct sockaddr_un sa_un;
    int result;
    pthread_t tid;
    socklen_t len;

    debug(LOG_DEBUG, "Starting wifi home control.");

    sock_name = (char *)arg;
    debug(LOG_DEBUG, "Socket name: %s", sock_name);

    debug(LOG_DEBUG, "Creating socket");
    whctl_socket_server = create_unix_socket(sock_name);
    if (-1 == whctl_socket_server) {
        termination_handler(0);
    }

    while (1) {
        len = sizeof(sa_un);
        memset(&sa_un, 0, len);
        fd = (int *)safe_malloc(sizeof(int));
        if ((*fd = accept(whctl_socket_server, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "Accept failed on control socket: %s", strerror(errno));
            free(fd);
        } else {
            debug(LOG_DEBUG, "Accepted connection on whome stop control socket %d (%s)", fd, sa_un.sun_path);
            pid_t pid;

            shutdown(*fd, 2);
            close(*fd);

            pid = getpid();
            kill(pid, SIGINT);
        }
    }
}


/** Main execution loop */
static void loopMain(void)
{
    int result;

	select_ctx sctx;
	memset(&sctx, 0, sizeof(sctx));

    s_gwOptions *gwOptions = get_gwOptions();
	int lastSecond = 0;

    /* Set the time when the gateway started */
    debug(LOG_INFO, "Setting started_time");
    started_time = time(NULL);

	/* save the pid file if needed */
    if (gwOptions && gwOptions->pidfile)
        save_pid_file(gwOptions->pidfile);


    /* Create a tunnel interface */
    if (initGateway(&homeGateway)) {
      debug(LOG_ERR, "Failed to create tun device for gateway");
      exit(1);
    }
    debug(LOG_DEBUG, "Create tun-gateway name of %s with fd %d", gwOptions->tundevname, homeGateway->gwTun.fd);

	/* Create an instance of IP handler*/
	if (initIpHandling(homeGateway)) {
         debug(LOG_ERR, "Failed to create IP handler");
         exit(1);
	}

//    register_fd_cleanup_on_fork(dhcp->rawif[0].fd);

//    if(dhcp->relayfd > 0) register_fd_cleanup_on_fork(dhcp->relayfd);

	/* Create an instance of IP handler*/
	if (initWebserver(&webServer, gwOptions->gw_address, gwOptions->gw_port)) {
       debug(LOG_ERR, "Could not create web server: %s", strerror(errno));
       exit(1);
	}

    debug(LOG_DEBUG, "Reg select tun device %s with fd %d", homeGateway->gwTun.devname, homeGateway->gwTun.fd);
    net_select_reg(&sctx,
                   homeGateway->gwTun.fd,
                   SELECT_READ, (select_callback)gw_tun_rcvPackets,
				   homeGateway, 0);

    /*Jerome TBD for DHCP relay function
    if(dhcp->relayfd){
    	net_select_reg(&sctx, dhcp->relayfd, SELECT_READ,
                           (select_callback)dhcp_relay_decaps, dhcp, 0);
    }*/

	for (int i=0; i < MAX_RAWIF; i++) {
		if(&homeGateway->rawIf[i] == NULL){
			debug(LOG_ERR, "Multi LAN raw if No. %d error %s", i, strerror(errno));
			exit(0);
		}
        debug(LOG_DEBUG, "Reg select rawIf %s with fd %d with idx = %d", homeGateway->rawIf[i].devname, homeGateway->rawIf[i].fd, i);
          net_select_reg(&sctx, homeGateway->rawIf[i].fd, SELECT_READ,
                         (select_callback)gw_raw_rcvPackets, homeGateway, i);
          homeGateway->rawIf[i].sctx = &sctx;
	}


//    register_fd_cleanup_on_fork(webserver->serverSock);

    debug(LOG_DEBUG, "Reg select websvr %s with fd %d", webServer->host, webServer->serverSock);
    /*Jerome: Add J-module*/
    net_select_reg(&sctx, webServer->serverSock,
                   SELECT_READ, (select_callback)rcvHttpConnection,
				   webServer, 0);

	/* Initializes the auth server */
    debug(LOG_NOTICE, "Creating Auth server on %s:%d", gwOptions->gw_address, gwOptions->auth_port);
    if (initAuthserver(&authserver, gwOptions->gw_address, gwOptions->auth_port)) {
        debug(LOG_ERR, "Could not create Auth server: %s", strerror(errno));
        exit(1);
    }

    /*Jerome: Add J-module*/
    net_select_reg(&sctx, authserver->serverSock,
                   SELECT_READ, (select_callback)authConnect,
				   authserver, 0);
    /*End, Jerome*/

    /* Start control thread */
    result = pthread_create(&tid_stop, NULL, (void *)stopWhome, (void *)safe_strdup(gwOptions->whome_sock));
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new whome control thread - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_stop);

    /* Start heartbeat thread */
    /*Jerome, withdraw
    result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_ping);
	End, Jerome*/


    debug(LOG_NOTICE, "Waiting for connections");
    while (1) {
    	/*Jerome, J-Module add*/
		mainclock_tick();
    	if (lastSecond != mainclock.tv_sec) {
			/*
			 *  Every second, more or less
			 */
			if (homeGateway) ip_checkTimeout(homeGateway);

			/*Jerome TBD, J-Module to check periodically if the client has connection with auth server*/
	        //checkconn();
	        lastSecond = mainclock.tv_sec;
		}

		if (net_select_prepare(&sctx))
              debug(LOG_ERR, "%s: select prepare", strerror(errno));

		int status;
		status = net_select(&sctx);

		if (status > 0) {
              net_run_selected(&sctx, status);
		}
    }

    /* never reached */
	debug(LOG_INFO, "Gateway shutting down unexpectedly");
	/* never reached, end without return */
}


/*main() */
int main(int argc, char **argv)
{

	s_gwOptions *gwOptions = get_gwOptions();
	initOptions();

	parseCommandline(argc, argv);

    /* Initialize the config */
	readConfig(gwOptions->configfile);
	valiConfig();

    /* Init the signals to catch chld/quit/etc */
    initSignals();

    if (gwOptions->daemon) {

        debug(LOG_INFO, "Forking into background");

        switch (safe_fork()) {
        case 0:                /* child */
            setsid();
            loopMain();
            break;

        default:               /* parent */
            exit(0);
            break;
        }
    } else {
    	loopMain();
    }

    return (0);                 /* never reached */
}

/** Clean up all the registered fds. Frees the list as it goes.
 * XXX This should only be run by CHILD processes.
 */
void closeFds()
{
	if (homeGateway)
	{
		net_close(&homeGateway->gwTun);
		debug(LOG_INFO, "Closing gateway tun devive %s", homeGateway->gwTun.devname);

		for (int i=0; i < MAX_RAWIF; i++) {

		      if(&homeGateway->rawIf[i] == NULL){
					debug(LOG_ERR, "Multi LAN raw if No. %d error %s", i, strerror(errno));
					exit(0);
		      }
		      dev_set_flags(homeGateway->rawIf[i].devname,
		    		  homeGateway->rawIf[i].devflags);
		      net_close(&homeGateway->rawIf[i]);
		      debug(LOG_INFO, "Closing rawIf %s with idx = %d", homeGateway->rawIf[i].devname, i);
		}
	}

	if(webServer){
		if(webServer->serverSock > 0){
			close(webServer->serverSock);
			webServer->serverSock = 0;
		}
	}

}

/** Exits cleanly after cleaning up the firewall.
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */

void termination_handler(int s)
{
	struct ipconnections_t *conn, *c;
    pthread_t self = pthread_self();

   debug(LOG_INFO, "Cleaning up and exiting");

   if (tid_stop) {
       debug(LOG_INFO, "Explicitly killing the wihome control thread");
       pthread_kill(tid_stop, SIGKILL);
   }

   if (tid_ping) {
       debug(LOG_INFO, "Explicitly killing the ping thread");
       pthread_kill(tid_ping, SIGKILL);
   }

   closeFds();

	if (homeGateway)
	{
		if (homeGateway->hash) free(homeGateway->hash);
		for (conn = homeGateway->firstfreeconn; conn; ) {
		    c = conn;
		    conn = conn->next;
		    free(c);
		}
		for (conn = homeGateway->firstusedconn; conn; ) {
		    c = conn;
		    conn = conn->next;
		    free(c);
		}
	    debug(LOG_INFO, "Free memory allocated for home gateway connections");

	    free(homeGateway->ippool->hash);
	    free(homeGateway->ippool->member);
	    free(homeGateway->ippool);
	    debug(LOG_INFO, "Free memory allocated for DHCP IP pool");

	    free(homeGateway);
	    debug(LOG_INFO, "Free memory allocated for home gateway itself");
	}

	if(webServer){
		endWebserver(webServer);
	}

    debug(LOG_NOTICE, "Exiting...");
    exit(s == 0 ? 1 : 0);
}


