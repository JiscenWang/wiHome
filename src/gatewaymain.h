/*
*/

#ifndef _GATEWAY_H_
#define _GATEWAY_H_

#include <stdio.h>

#include "httpd.h"

extern time_t started_time;

/** @brief The internal web server */
extern httpd *webserver;


/* ****************************************************
 * Information for gateway tun device
 *****************************************************/

struct gateway_t {
  int addrs;   /* Number of allocated IP addresses */
  int routes;  /* One if we allocated an automatic route */

  struct _net_interface gwTun;
  /* network internal interfaces */
  struct _net_interface rawIf[MAX_RAWIF];

  struct in_addr ourip; /* IP address to listen to */
  int mtu;              /* Maximum transfer unit */

  uint16_t uamport;     /* TCP port to redirect HTTP requests to */

	uint32_t lease;       /* Seconds before reneval */
	int usemac;           /* Use given mac address */

	/* Pool of IP addresses */
	struct ippool_t *ippool;

	/* Connection management */
	ipconnections_t *firstfreeconn; /* First free in linked list */
	ipconnections_t *lastfreeconn;  /* Last free in linked list */
	ipconnections_t *firstusedconn; /* First used in linked list */
	ipconnections_t *lastusedconn;  /* Last used in linked list */

	/* Hash related parameters */
	int hashsize;                 /* Size of hash table */
	int hashlog;                  /* Log2 size of hash table */
	int hashmask;                 /* Bitmask for calculating hash */
	ipconnections_t **hash;    /* Hashsize array of pointer to member */

#define tun(x,i) ((x)->_tuntap)
#define tuntap(x) tun((x),0)

#define tun_close(tun) net_close(&(tun)->_tuntap)

//  void *table;
};


#endif                          /* _GATEWAY_H_ */
