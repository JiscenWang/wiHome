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

#include "common.h"
#include "debug.h"
#include "homeconfig.h"
#include "gatewaymain.h"
#include "gatewayapi.h"
#include "ipprocessing.h"

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
static pthread_t tid_fw_counter = 0;
static pthread_t tid_ping = 0;

time_t started_time = 0;
struct timespec mainclock;



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

/** Main execution loop */
static void loopMain(void)
{
    int result;
    pthread_t tid;
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
//    register_fd_cleanup_on_fork(homeGateway->gw_tun.fd);


	/* Create an instance of IP handler*/
	if (initIpHandling(homeGateway)) {
         debug(LOG_ERR, "Failed to create IP handler");
         exit(1);
	}

//    register_fd_cleanup_on_fork(dhcp->rawif[0].fd);

//    if(dhcp->relayfd > 0) register_fd_cleanup_on_fork(dhcp->relayfd);

#ifdef ENABLE_MULTILAN
  {
    int idx, i;
    for (idx=1; idx < MAX_MOREIF && dhcp->rawif[idx].fd; idx++) {
        register_fd_cleanup_on_fork(dhcp->rawif[idx].fd);
      }
  }
#endif

	/*
	dhcp_set_cb_request(dhcp, cb_dhcp_request);
	dhcp_set_cb_connect(dhcp, cb_dhcp_connect);
	dhcp_set_cb_disconnect(dhcp, cb_dhcp_disconnect);
	dhcp_set_cb_data_ind(dhcp, cb_dhcp_data_ind);

Initialise connections */

	/* Create an instance of IP handler*/
	if (initWebserver(webServer, gwOptions->gw_address, gwOptions->gw_port)) {
       debug(LOG_ERR, "Could not create web server: %s", strerror(errno));
       exit(1);
	}


    net_select_reg(&sctx,
                   homeGateway->gwTun.fd,
                   SELECT_READ, (select_callback)gw_tun_rcvPackets,
				   homeGateway, 0);

    /*Jerome TBD for DHCP relay function
    if(dhcp->relayfd){
    	net_select_reg(&sctx, dhcp->relayfd, SELECT_READ,
                           (select_callback)dhcp_relay_decaps, dhcp, 0);
    }*/

	for (int i=0; i < MAX_RAWIF && homeGateway->rawIf[i].fd > 0; i++) {
          net_select_reg(&sctx, homeGateway->rawIf[i].fd, SELECT_READ,
                         (select_callback)gw_raw_rcvPackets, homeGateway, i);
          homeGateway->rawIf[i].sctx = &sctx;
	}


//    register_fd_cleanup_on_fork(webserver->serverSock);

    /*Jerome: Add J-module*/
    net_select_reg(&sctx, webServer->serverSock,
                   SELECT_READ, (select_callback)rcvHttpConnection,
				   webServer, 0);


	/* Initializes the auth server */
/*
    debug(LOG_NOTICE, "Creating Auth server on %s:%d", config->gw_address, config->auth_port);
    if ((authserver = authsvrCreate(config->gw_address, config->auth_port)) == NULL) {
        debug(LOG_ERR, "Could not create Auth server: %s", strerror(errno));
        exit(1);
    }
    register_fd_cleanup_on_fork(authserver->serverSock);
*/
    /*Jerome: Add J-module*/
    /*
    net_select_reg(&sctx, authserver->serverSock,
                   SELECT_READ, (select_callback)jauthconnect,
				   authserver, 0);
*/
    /*End, Jerome*/

    /* Start clean up thread */
    result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (fw_counter) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_fw_counter);


    /* Start control thread */
    result = pthread_create(&tid, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid);

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
			if (dhcp) dhcp_timeout(dhcp);

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



/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */

void sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

    rc = waitpid(-1, &status, WNOHANG);

    debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
}

/** Exits cleanly after cleaning up the firewall.
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */

void termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "Handler for termination caught signal %d", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
    } else {
        debug(LOG_INFO, "Cleaning up and exiting");
    }


    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads
     * that use that
     */
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "Explicitly killing the fw_counter thread");
        pthread_kill(tid_fw_counter, SIGKILL);
    }
    if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "Explicitly killing the ping thread");
        pthread_kill(tid_ping, SIGKILL);
    }

	if (dhcp)
          dhcp_free(dhcp);

    if (tun)
      tun_free(tun);

	if (ippool)
          ippool_free(ippool);

    debug(LOG_NOTICE, "Exiting...");
    exit(s == 0 ? 1 : 0);
}



/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress?
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);

        debug(LOG_DEBUG, "Running fw_counter()");
    }
}


