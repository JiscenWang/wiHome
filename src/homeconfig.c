/*
 * Jerome Build
*/

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>

#include "common.h"
#include "debug.h"
#include "homeconfig.h"

#include "../config.h"


/** @internal
 * Holds the current configuration of the gateway */
static s_gwOptions gwOptions;

/** @internal
 The different configuration options */
typedef enum {
    oBadOption,
    oDaemon,
    oDebugLevel,
    oExternalInterface,
    oGatewayID,
	oInternalInterface,
    oGatewayAddress,
    oGatewayPort,
    oHTTPDMaxConn,
    oClientTimeout,
    oCheckInterval,
    oSyslogFacility,
    oPopularServers,
    oHtmlMessageFile,
    oLocalAuthPort,
	oInternalIfDev
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
    const char *name;
    OpCodes opcode;
} keywords[] = {{
    "daemon", oDaemon}, {
    "debuglevel", oDebugLevel}, {
    "externalinterface", oExternalInterface}, {
    "gatewayid", oGatewayID}, {
    "internalinterface", oInternalInterface}, {
    "gatewayaddress", oGatewayAddress}, {
    "gatewayport", oGatewayPort}, {
    "httpdmaxconn", oHTTPDMaxConn}, {
    "clienttimeout", oClientTimeout}, {
    "checkinterval", oCheckInterval}, {
    "syslogfacility", oSyslogFacility}, {
    "popularservers", oPopularServers}, {
    "htmlmessagefile", oHtmlMessageFile}, {
    "localauthport", oLocalAuthPort}, {
    "internalinterfacedev", oInternalIfDev},{
    NULL, oBadOption},};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_internal_interface(FILE *, const char *, int *);

static void parse_trusted_mac_list(const char *);
static void parse_popular_servers(const char *);
static void validate_popular_servers(void);
static void add_popular_server(const char *);

static OpCodes option_parse_token(const char *, const char *, int);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_gwOptions *get_gwOptions(void)
{
    return &gwOptions;
}

/** Sets the default config parameters and initialises the configuration system */
/*####Jerome, check ongoing*/
void initOptions(void)
{
	memset(&gwOptions, 0, sizeof(s_gwOptions));
    //config.external_interface = NULL;  /*External IF must be set later in the conf file*/
    //config.internalif = NULL;	/*Internal IF must be set later in the conf file*/

    debug(LOG_DEBUG, "Setting default config parameters of conf file %s and html file",
    		DEFAULT_CONFIGFILE, DEFAULT_HTMLMSGFILE);
    gwOptions.configfile = safe_strdup(DEFAULT_CONFIGFILE);
    gwOptions.htmlmsgfile = safe_strdup(DEFAULT_HTMLMSGFILE);

    //config.gw_interface = NULL;/*without needing initialized to be zero*/
    //config.gw_address = NULL;/*without needing initialized to be zero*/

    gwOptions.tundevname = safe_strdup(DEFAULT_GATEWAYID);
    gwOptions.tundevip.s_addr = inet_addr(WIRELESS_GATEWAY_IP);
    gwOptions.netmask.s_addr = inet_addr("255.255.255.0");

    gwOptions.gw_id = gwOptions.tundevname;
    gwOptions.gw_interface = gwOptions.tundevname;
    gwOptions.gw_address = safe_strdup(WIRELESS_GATEWAY_IP);

    gwOptions.gw_port = DEFAULT_CAPTIVEPORT;

    gwOptions.auth_port = DEFAULT_LOCALAUTHPORT;

    gwOptions.httpdname = gwOptions.gw_id;

    gwOptions.popular_servers = NULL;

    gwOptions.daemon = DEFAULT_DAEMON;

    gwOptions.dhcpdynip = safe_strdup(DHCP_DYN_IP_POOL);
    gwOptions.dns1.s_addr = inet_addr(GW_DEFAULT_DNS1);
    gwOptions.dns2.s_addr = inet_addr(GW_DEFAULT_DNS2);
    gwOptions.dhcpgwport = DEFAULT_DHCP_GW_PORT;

    //gwOptions.dhcpgwip = NULL;  /*Jerome TBD for DHCP relay mode*/
//    gwOptions.max_clients = DHCP_MAX_CLIENTS;


    gwOptions.redirhost = safe_strdup(GW_REDIR_HOST);
    gwOptions.httpdmaxconn = DEFAULT_HTTPDMAXCONN;

    gwOptions.auth_servers = NULL;

    gwOptions.clienttimeout = DEFAULT_CLIENTTIMEOUT;
    gwOptions.checkinterval = DEFAULT_CHECKINTERVAL;

    gwOptions.pidfile = NULL;
    gwOptions.whome_sock = safe_strdup(DEFAULT_WHOME_SOCK);

    debugconf.debuglevel = DEFAULT_DEBUGLEVEL;
    debugconf.log_stderr = 1;
    debugconf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
    debugconf.log_syslog = DEFAULT_LOG_SYSLOG;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes option_parse_token(const char *cp, const char *filename, int linenum)
{
    int i;

    for (i = 0; keywords[i].name; i++)
        if (strcasecmp(cp, keywords[i].name) == 0)
            return keywords[i].opcode;

    debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
    return oBadOption;
}

/**
@param filename Full path of the configuration file to be read 
*/
void readConfig(const char *filename)
{
    FILE *fd;
    char line[MAX_BUF], *s, *p1, *p2, *tmpadr, *rawarg = NULL;
    int linenum = 0, opcode, value;
    size_t len;

    debug(LOG_INFO, "Reading configuration file '%s'", filename);

    if (!(fd = fopen(filename, "r"))) {
        debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filename);
        exit(1);
    }

    while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
        linenum++;
        s = line;

        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';

        if ((p1 = strchr(s, ' '))) {
            p1[0] = '\0';
        } else if ((p1 = strchr(s, '\t'))) {
            p1[0] = '\0';
        }

        if (p1) {
            p1++;

            // Trim leading spaces
            len = strlen(p1);
            while (*p1 && len) {
                if (*p1 == ' ')
                    p1++;
                else
                    break;
                len = strlen(p1);
            }
            rawarg = safe_strdup(p1);
            if ((p2 = strchr(p1, ' '))) {
                p2[0] = '\0';
            } else if ((p2 = strstr(p1, "\r\n"))) {
                p2[0] = '\0';
            } else if ((p2 = strchr(p1, '\n'))) {
                p2[0] = '\0';
            }
        }

        if (p1 && p1[0] != '\0') {
            /* Strip trailing spaces */

            if ((strncmp(s, "#", 1)) != 0) {
                debug(LOG_DEBUG, "Parsing token: %s, " "value: %s", s, p1);
                opcode = option_parse_token(s, filename, linenum);

                switch (opcode) {
                case oDaemon:
                    if (gwOptions.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
                    	gwOptions.daemon = value;
                        if (gwOptions.daemon > 0) {
                            debugconf.log_stderr = 0;
                        } else {
                            debugconf.log_stderr = 1;
                        }
                    }
                    break;
                /*J-Module changes it to be mandatory, sharing this IF between wifidog and J-Module*/
                case oExternalInterface:
                	gwOptions.external_interface = safe_strdup(p1);
                    break;
                case oInternalInterface:
                    /*J-Module changes it to internal interface*/
                    parse_internal_interface(fd, filename, &linenum);
                    break;
                case oGatewayAddress:
                    /*Jerome: J-Module changes it to TUN IP*/
                	gwOptions.tundevip.s_addr = inet_addr(safe_strdup(p1));
                	gwOptions.gw_address = safe_strdup(p1);
                    break;
                case oGatewayPort:
                    sscanf(p1, "%d", &gwOptions.gw_port);
                    break;
                case oGatewayID:
                	gwOptions.gw_id = safe_strdup(p1);
                	gwOptions.tundevname = gwOptions.gw_id;
                    break;
                case oLocalAuthPort:
                    sscanf(p1, "%d", &gwOptions.auth_port);
                    break;

                case oPopularServers:
//                    parse_popular_servers(rawarg);
                    break;

                case oHTTPDMaxConn:
                    sscanf(p1, "%d", &gwOptions.httpdmaxconn);
                    break;

                case oCheckInterval:
                    sscanf(p1, "%d", &gwOptions.checkinterval);
                    break;

                case oClientTimeout:
                    sscanf(p1, "%d", &gwOptions.clienttimeout);
                    break;
                case oSyslogFacility:
                    sscanf(p1, "%d", &debugconf.syslog_facility);
                    break;
                case oHtmlMessageFile:
                	gwOptions.htmlmsgfile = safe_strdup(p1);
                    break;

                case oBadOption:
                    /* FALL THROUGH */
                default:
                    debug(LOG_ERR, "Bad option on line %d " "in %s.", linenum, filename);
                    debug(LOG_ERR, "Exiting...");
                    exit(-1);
                    break;
                }
            }
        }
        if (rawarg) {
            free(rawarg);
            rawarg = NULL;
        }
    }

    fclose(fd);
}


/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
/*####Jerome, checked over*/
void
valiConfig(void)
{
    /*Jerome: J-Module changes wifidog GW IF to J-Module's TUN*/
    config_notnull(gwOptions.gw_interface, "GatewayInterface");
    /*Jerome: J-Module changes ExternalInterface to be mandatory, sharing this IF between wifidog and J-Module*/
    config_notnull(gwOptions.external_interface, "ExternalInterface");
    /*Jerome: J-Module add validation of internal inteface */
    config_notnull(gwOptions.internalif, "InternalInterface");

    /*Jerome: J-Module removes these validations*/
//    validate_popular_servers();

}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	/*####Jerome, checked over*/
    if (strcasecmp(line, "yes") == 0) {
        return 1;
    }
    if (strcasecmp(line, "no") == 0) {
        return 0;
    }
    if (strcmp(line, "1") == 0) {
        return 1;
    }
    if (strcmp(line, "0") == 0) {
        return 0;
    }

    return -1;
}


/** @internal
Parses internal_interface
*/
static void
parse_internal_interface(FILE * file, const char *filename, int *linenum)
{
    char line[MAX_BUF], *p1, *p2;
    int opcode = 0;
    int i;

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* trim all blanks at the end of the line */
        for (p2 = (p2 != NULL ? p2 - 1 : &line[MAX_BUF - 2]); isblank(*p2) && p2 > p1; p2--) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            debug(LOG_DEBUG, "Parsing token: %s, " "value: %s", p1, p2);
            opcode = option_parse_token(p1, filename, *linenum);

            switch (opcode) {
            case oInternalIfDev:
                 for (i =0; i < MAX_RAWIF; i++){
                	 gwOptions.internalif[i] = safe_strdup(p2);
                }
                if (i == MAX_RAWIF) {
                    debug(LOG_DEBUG, "MAX_RAWIF %d internal ports were added!", i);
                } else {
                    debug(LOG_DEBUG, "%d internal ports were added!", i);
                }
                break;

            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s with opcode %d.", *linenum, filename, opcode);
                debug(LOG_ERR, "Exiting...");
                exit(-1);
            }

        }
    }

    if(gwOptions.internalif[0] == NULL){
    	debug(LOG_ERR, "Configuration without Internal Interfaces. Exiting...");
        exit(-1);
    }
}

/**
 * Parse possiblemac to see if it is valid MAC address format */
int
check_mac_format(char *possiblemac)
{
    char hex2[3];
    return
        sscanf(possiblemac,
               "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

/** @internal
 * Add a popular server to the list. It prepends for simplicity.
 * @param server The hostname to add.
 */
static void
add_popular_server(const char *server)
{
    t_popular_server *p = NULL;

    p = (t_popular_server *)safe_malloc(sizeof(t_popular_server));
    p->hostname = safe_strdup(server);

    if (gwOptions.popular_servers == NULL) {
        p->next = NULL;
        gwOptions.popular_servers = p;
    } else {
        p->next = gwOptions.popular_servers;
        gwOptions.popular_servers = p;
    }
}

static void
parse_popular_servers(const char *ptr)
{
    char *ptrcopy = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for popular servers", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((hostname = strsep(&ptrcopy, ","))) {  /* hostname does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*hostname != '\0' && isblank(*hostname)) { 
            hostname++;
        }
        if (*hostname == '\0') {  /* Equivalent to strcmp(hostname, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = hostname;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
        debug(LOG_DEBUG, "Adding Popular Server [%s] to list", hostname);
        add_popular_server(hostname);
    }

    free(ptrcopy);
}

/** @internal
 * Validate that popular servers are populated or log a warning and set a default.
 */
static void
validate_popular_servers(void)
{
    if (gwOptions.popular_servers == NULL) {
        debug(LOG_WARNING, "PopularServers not set in config file, this will become fatal in a future version.");
        add_popular_server("www.google.com");
        add_popular_server("www.yahoo.com");
    }
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
    if (parm == NULL) {
        debug(LOG_ERR, "%s is not set", parmname);
    }
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{

    /* This is as good as atomic */
    return gwOptions.auth_servers;
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv * bad_server)
{
    t_auth_serv *tmp;

    if (gwOptions.auth_servers == bad_server && bad_server->next != NULL) {
        /* Go to the last */
        for (tmp = gwOptions.auth_servers; tmp->next != NULL; tmp = tmp->next) ;
        /* Set bad server as last */
        tmp->next = bad_server;
        /* Remove bad server from start of list */
        gwOptions.auth_servers = bad_server->next;
        /* Set the next pointe to NULL in the last element */
        bad_server->next = NULL;
    }

}
