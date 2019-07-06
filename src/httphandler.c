/*
 * httphandler.c
 *
 *  Created on: 2019年6月23日
 *      Author: jerome
 */
#include <sys/types.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#include "common.h"
#include "httpd.h"
#include "homeconfig.h"
#include "debug.h"

#include "../config.h"


/** @brief Sends a redirect to the web browser
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}


/** The 302 handler is responsible for redirecting to the portal page*/
static void
http_callback_302(httpd *webserver, request * r, int error_code)
{
	s_gwOptions *gwOptions = get_gwOptions();
    char *url = NULL;
    safe_asprintf(&url, "http://%s", gwOptions->redirhost);
    http_send_redirect(r, url, "Redirect to portal page!");
    free(url);
	return;
}


/** The 404 handler is also responsible for redirecting to the auth server */
static void
http_callback_404(httpd * webserver, request * r, int error_code)
{
	char tmp_url[MAX_BUF], *url, *mac;
	s_gwOptions *gwOptions = get_gwOptions();
    t_auth_serv *auth_server = get_auth_server();

    memset(tmp_url, 0, sizeof(tmp_url));
    /*
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
    url = httpdUrlEncode(tmp_url);


    if (1/*Jerome TBD, !is_online()*/) {
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>Please read the indication to be able to reaching the Internet.</p>"
                      "<p>If you want to have the right to access the Internet. Please install the application on your computer, pad or mobile phone. And then apply the right from the Wifi spot owner.</p>"
                      "<p>After the Wifi spot owner agreed, he/she will let you online.</p>"
                      "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

        send_http_page(r, "Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an indication since the client is not allowed to be online unless he/she install the application",
              r->clientAddr);
    }
    free(url);
}

static void
http_callback_jmodule(httpd *webserver, request * r)
{
    send_http_page(r, "J-Module", "Please use the menu to navigate the features of this J-Module installation.");
}

static void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About J-Module", "This is J-Module version <strong>" VERSION "</strong>");
}


void
send_http_page(request * r, const char *title, const char *message)
{
	s_gwOptions *gwOptions = get_gwOptions();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(gwOptions->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", gwOptions->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", gwOptions->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}


/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
static void
thread_httpd(void *args)
{
	void	**params;
	httpd	*webserver;
	request	*r;
	s_gwOptions *gwOptions = get_gwOptions();

	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	free(params); /* XXX We must release this ourselves. */
	debug(LOG_DEBUG, "thread_httpd created!");

	if (httpdReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		if(strncasecmp(r->request.host, gwOptions->redirhost, sizeof(gwOptions->redirhost)) != 0){
			debug(LOG_DEBUG, "http_callback_302 for %s", r->request.path);
			http_callback_302(webserver, r, 302);
		}
		else{
			debug(LOG_DEBUG, "Calling httpdProcessRequest() for %s", r->request.path);
			httpdProcessRequest(webserver, r);
			debug(LOG_DEBUG, "Returned from httpdProcessRequest() for %s", r->clientAddr);
		}
	}
	else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	}
	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	httpdEndRequest(r);
}


/*Adapter callback func of mainloop select for hpptd API func of httpdGetConnection*/
int rcvHttpConnection(httpd *server, int index){
    request *r;
    void **params;
    int result;
    pthread_t tid;

    r = httpdGetConnection(server, NULL);

    /* We can't convert this to a switch because there might be
     * values that are not -1, 0 or 1. */
	/*Jerome: seems will not happen to be -1*/
    if (server->lastError == -1) {
        /* Interrupted system call */
        if (NULL != r) {
            httpdEndRequest(r);
        }
    } else if (server->lastError < -1) {
        /*
         * FIXME
         * An error occurred - should we abort?
         * reboot the device ?
         */
        debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.");
        termination_handler(0);
    } else if (r != NULL) {
        /*
         * We got a connection
         *
         * We should create another thread
         */
        debug(LOG_INFO, "Received connection from %s, spawning worker thread", r->clientAddr);
        /* The void**'s are a simulation of the normal C
         * function calling sequence. */
        params = safe_malloc(2 * sizeof(void *));
        *params = server;
        *(params + 1) = r;

        result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid);
    } else {
        /* webserver->lastError should be 2 */
        /* XXX We failed an ACL.... No handling because
         * we don't set any... */
    }

    return 0;
}

/* Initializes the web server */
int initWebserver(httpd *server, char *address, int port){

    if ((server = httpdCreate(address, port)) == NULL) {
        return -1;
   }

    debug(LOG_NOTICE, "Created web server on %s:%d with socket %d", address, port, server->serverSock);

    FILE *logfp = fopen("/tmp/access.log", "a" );
    httpdSetAccessLog ( server, logfp );

    /*Jerome TBD define new Html*/
    debug(LOG_DEBUG, "Assigning callbacks to web server");
    httpdAddCContent(server, "/", "jmodule", 0, NULL, http_callback_jmodule);
    httpdAddCContent(server, "/jmodule", "", 0, NULL, http_callback_jmodule);
    httpdAddCContent(server, "/jmodule", "about", 0, NULL, http_callback_about);

    httpdSetFileBase(server,"/home/jerome/files");
    httpdAddFileContent(server, "/jmodule", "download", 0, NULL,"tryit.mp3");

    httpdSetErrorFunction(server, 404, http_callback_404);

    return 0;
}
