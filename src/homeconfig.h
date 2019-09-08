/*
 * Jerome Build
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <arpa/inet.h>
#include "homenet.h"

/** sysZERO_CONTINUEfiguration values */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "/etc/wiHome.conf"
#define DEFAULT_HTMLMSGFILE "/etc/wiHome.html"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/wiHome.conf"
#define DEFAULT_HTMLMSGFILE SYSCONFDIR"/wiHome.html"
#endif

#define DEFAULT_WHOME_SOCK "/tmp/whome.sock"

#define DEFAULT_GATEWAYID "WirelessHome"  /* Name for tun device as well*/
#define WIRELESS_GATEWAY_IP              "192.168.168.169" /* IP address of tun and Wireless Gateway, and DHCP svr*/
#define DEFAULT_CAPTIVEPORT 2060
#define DEFAULT_LOCALAUTHPORT 2061

#define GW_REDIR_HOST "redirpage.home.fun"

#define GW_DEFAULT_DNS1			"114.114.114.114"
#define GW_DEFAULT_DNS2			"119.29.29.29"

/** software configuration values */
#define DEFAULT_DAEMON 1

#define DEFAULT_HTTPDMAXCONN 16
#define DEFAULT_HTTPDNAME "wiHome"
#define DEFAULT_CLIENTTIMEOUT 5
#define DEFAULT_CHECKINTERVAL 60

#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON

/** DHCP configuration values */
#define DHCP_MAX_CLIENTS              16 /* Maximum DHCP clients supported */
#define DHCP_HASH_TABLE              64 /* Maximum DHCP hash table size */
#define DHCP_LEASE_TIME              3000 /* DHCP lease time */
#define DHCP_DYN_IP_POOL              "192.168.168.3" /* Start of DHCP dynamic pool */

#define DEFAULT_DHCP_GW_PORT  3462 /* Default Relay Port of DHCP GW */

/** Network configuration values */
#define MACOK_MAX                         16
#define PKT_MAX_LEN                     9000 /* Maximum packet size we receive */

#ifdef ENABLE_MULTILAN
#define MAX_RAWIF 8
#else
#define MAX_RAWIF 1
#endif

/**
 * Trusted MAC Addresses
 */
typedef struct _trusted_mac_t {
    char *mac;
    struct _trusted_mac_t *next;
} t_trusted_mac;

/**
 * Popular Servers
 */
typedef struct _popular_server_t {
    char *hostname;
    struct _popular_server_t *next;
} t_popular_server;



/**
 * Information about the authentication server
 */
typedef struct _auth_serv_t {
    char *authserv_hostname;    /**< @brief Hostname of the central server */
    char *authserv_path;        /**< @brief Path where wifidog resides */
    char *authserv_login_script_path_fragment;  /**< @brief This is the script the user will be sent to for login. */
    char *authserv_portal_script_path_fragment; /**< @brief This is the script the user will be sent to after a successfull login. */
    char *authserv_msg_script_path_fragment;    /**< @brief This is the script the user will be sent to upon error to read a readable message. */
    char *authserv_ping_script_path_fragment;   /**< @brief This is the ping heartbeating script. */
    char *authserv_auth_script_path_fragment;   /**< @brief This is the script that talks the wifidog gateway protocol. */
    int authserv_http_port;     /**< @brief Http port the central server
				     listens on */
    int authserv_ssl_port;      /**< @brief Https port the central server
				     listens on */
    int authserv_use_ssl;       /**< @brief Use SSL or not */
    char *last_ip;      /**< @brief Last ip used by authserver */
    struct _auth_serv_t *next;
} t_auth_serv;


/*Configuration structure*/
typedef struct {
    char *configfile;       /*Name of the config file */
    char *htmlfile;          /*Name of the HTML file*/
    int daemon;                 /*0, use daemon mode */
    char *pidfile;            /*Pid file path of home gateway */

    char *tundevname;  			/*self-defined name of tun dev*/
    struct in_addr tundevip;     /* IP address to listen to */
    struct in_addr netmask;     /* net mask of IP address*/

    int cap_port;                /*Captive port on which webserver will run*/
    char *httpdname;            /**< @brief Name the web server will return when replying to a request */
    char *redirhost;           /**< URL host name of redirect web*/
    int httpdmaxconn;           /**< @brief Used by libhttpd, not sure what it does */

    int auth_port;          /*Jerome add loacl auth port*/

	char *external_interface;   	/*External network interface's name of the gateway*/
	char* internalif[MAX_RAWIF];    /*Internal network interfaces' name of the gateway*/

    struct in_addr dns1;         /* Client DNS address */
    struct in_addr dns2;         /* Client DNS address */

    char *dhcpdynip;     /* IP address of dyn DHCP pool*/

    struct in_addr dhcpgwip;   /* IP address of DHCP gateway*/
    uint16_t dhcpgwport;      /* Relay port of DHCP gateway */

//    int max_clients;               /* Max subscriber/clients */

    /* MAC Authentication */
    uint8_t macok[MACOK_MAX][PKT_ETH_ALEN]; /* Allowed MACs */
    int macoklen;                   /* Number of MAC addresses */
    t_trusted_mac *trustedmaclist; /**< @brief list of trusted macs */

    char *whome_sock;           /**< @brief wdctl path to socket */
    int clienttimeout;          /**< @brief How many CheckIntervals before a client must be re-authenticated */
    int checkinterval;          /**< @brief Frequency the the client timeout check thread will run. */

    t_popular_server *popular_servers; /*list of popular servers */
    int gw_online; /*0, offline; 1, online */
} s_gwOptions;


/** @brief Get the current gateway configuration */
s_gwOptions *get_gwOptions(void);

/** @brief Initialise the conf system */
void initOptions(void);

/** @brief Reads the configuration file */
void readConfile(const char *filename);

/** @brief Check that the configuration is valid */
void valiConfig(void);


#endif                          /* _CONFIG_H_ */
