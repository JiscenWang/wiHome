/*
 * ipprocessing.h
 *
 *  Created on: 2019年6月22日
 *      Author: jerome
 */

#ifndef SRC_IPHANDLER_H_
#define SRC_IPHANDLER_H_

/* Option constants */
#define DHCP_OPTION_MAGIC_LEN       4


#define DHCP_OPTION_PAD             0
#define DHCP_OPTION_SUBNET_MASK     1
#define DHCP_OPTION_ROUTER_OPTION   3
#define DHCP_OPTION_DNS             6
#define DHCP_OPTION_HOSTNAME       12
#define DHCP_OPTION_DOMAIN_NAME    15
#define DHCP_OPTION_INTERFACE_MTU  26
#define DHCP_OPTION_STATIC_ROUTES  33
#define DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION 43
#define DHCP_OPTION_REQUESTED_IP   50
#define DHCP_OPTION_LEASE_TIME     51
#define DHCP_OPTION_MESSAGE_TYPE   53
#define DHCP_OPTION_SERVER_ID      54
#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER 60
#define DHCP_OPTION_CLIENT_IDENTIFIER 61
#define DHCP_OPTION_CLIENT_FQDN    81
#define DHCP_OPTION_82    82
#define DHCP_OPTION_CAPTIVE_PORTAL_URI 160

#define DHCP_MAX_LENGTH_HOSTNAME       36

/* DHCP states */
#define DNPROT_NULL       1
#define DNPROT_DHCP_NONE  2
#define DNPROT_DHCP_DONE  3

/* Authentication states */
#define NEW_CLIENT        0
#define DROP_CLIENT        1
#define AUTH_CLIENT        2

#define DHCP_DNAT_MAX       128

/* BOOTP Message Types */
#define DHCP_BOOTREQUEST  1
#define DHCP_BOOTREPLY    2

/* DHCP Message Types */
#define DHCPDISCOVER      1
#define DHCPOFFER         2
#define DHCPREQUEST       3
#define DHCPDECLINE       4
#define DHCPACK           5
#define DHCPNAK           6
#define DHCPRELEASE       7
#define DHCPINFORM        8
#define DHCPFORCERENEW    9

/* UDP Ports */
#define DHCP_BOOTPS 67
#define DHCP_BOOTPC 68
#define DHCP_DNS    53
#define DHCP_MDNS   5353

/* TCP Ports */
#define DHCP_HTTP   80
#define DHCP_HTTPS 443

#define DHCP_OPTION_END           255

#define DHCP_ARP_REQUEST 1
#define DHCP_ARP_REPLY   2

#define DHCP_DNS_HLEN  12



struct ippoolm_t;                /* Forward declaration */

struct ippool_t {
  int dynsize;                   /* Total number of dynamic addresses */

  struct ippoolm_t *member;      /* Listsize array of members */

  int hashsize;                  /* Size of hash table */
  int hashlog;                   /* Log2 size of hash table */
  int hashmask;                  /* Bitmask for calculating hash */
  struct ippoolm_t **hash;       /* Hashsize array of pointer to member */
  struct ippoolm_t *firstdyn;    /* Pointer to first free dynamic member */
  struct ippoolm_t *lastdyn;     /* Pointer to last free dynamic member */
};

struct ippoolm_t {
  struct in_addr addr;           /* IP address of this member */
  char in_use;                   /* 0=available; 1= used */

  struct ippoolm_t *nexthash;    /* Linked list part of hash table */
  struct ippoolm_t *prev, *next; /* Linked list of free dynamic or static */
  void *peer;                    /* Pointer to peer protocol handler */
};


/* ***********************************************************
 * Information storage for each dhcp instance
 *
 * Normally each instance of the application corresponds to
 * one instance of a dhcp instance.
 *
 *************************************************************/
struct dnat_t {
  uint8_t mac[PKT_ETH_ALEN];
  uint32_t dst_ip;
  uint16_t dst_port;
  uint32_t src_ip;
  uint16_t src_port;
};

struct ipconnections_t {
  struct ipconnections_t *nexthash; /* Linked list part of hash table */
  struct ipconnections_t *next;     /* Next in linked list. 0: Last */
  struct ipconnections_t *prev;     /* Previous in linked list. 0: First */

  struct gateway_t *parent;        /* Gateway is Parent of all connections */

  /* Pointers to protocol handlers */
  void *uplink;                  /* Uplink network interface (Internet) */
  void *dnlink;                  /* Downlink network interface (Wireless) */

  uint8_t inuse:1;             /* Free = 0; Inuse = 1 */
  uint8_t noc2c:1;             /* Prevent client to client access using /32 subnets */
  uint8_t is_reserved:1;       /* If this is a static/reserved mapping */
  uint8_t padding:5;

  time_t lasttime;             /* Last time we heard anything from client */

  uint8_t hismac[PKT_ETH_ALEN];/* Peer's MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in_addr hismask;      /* Client Network Mask */
  uint8_t dhcpstate;           /* 0, not allocated; 1, sent dhcp offer; 2, sent dhcp ack*/
  char hostname[DHCP_MAX_LENGTH_HOSTNAME];	/* Host name provided by DHCP discover of the client */

  struct in_addr dns1;         /* Client DNS address */
  struct in_addr dns2;         /* Client DNS address */

//Jerome  char domain[DHCP_DOMAIN_LEN];/* Domain name to use for DNS lookups */
  int authstate;               /* AUTH_CLIENT */
  int clientSock;				/* Client auth socket*/
  time_t lastauthtime;				/*  Last time we heard auth heart beat from client*/

  int nextdnat;                /* Next location to use for DNAT */
  uint32_t dnatdns;            /* Destination NAT for dns mapping */
  struct dnat_t dnat[DHCP_DNAT_MAX]; /* Destination NAT */
  uint16_t mtu;                /* Maximum transfer unit */

  struct in_addr migrateip;    /* Client IP address to migrate to */
  /*time_t last_nak;*/

  int rawIdx; 	 /* Index of LAN raw interfaces */
} ;

struct rawif_in{
	struct gateway_t *parent;
  int idx;
};


int initIpHandling(struct gateway_t *pgateway);

int raw_rcvIp(struct rawif_in *ctx, uint8_t *pack, size_t len);

int ip_newConnection(struct gateway_t *this, struct ipconnections_t **conn,
		 uint8_t *hwaddr);
int ip_allocClientIP(struct ipconnections_t *conn, struct in_addr *addr,
		    uint8_t *dhcp_pkt, size_t dhcp_len);
int getMacHash(struct gateway_t *this, struct ipconnections_t **conn,
		 uint8_t *hwaddr);
void ip_relConnection(struct gateway_t *this, uint8_t *hwaddr, struct ipconnections_t *conn);
int ip_checkTimeout(struct gateway_t *this);
int ip_tunProcess(struct ipconnections_t *conn,
		  struct pkt_buffer *pb, int ethhdr);

#endif /* SRC_IPHANDLER_H_ */
