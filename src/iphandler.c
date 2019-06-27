/*
 * iphandler.c
 *
 *  Created on: 2019年6月22日
 *      Author: jerome
 */

#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "iphandler.h"
#include "homenet.h"
#include "homeconfig.h"
#include "debug.h"

//Jerome: Try this one first
#define HAVE_SFHASH

#ifdef HAVE_SFHASH
uint32_t SuperFastHash(const char * data, int len, uint32_t hash);
#elif HAVE_LOOKUP3
#if LITTLE_ENDIAN
uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
#elif BIG_ENDIAN
uint32_t hashbig(const void *key, size_t length, uint32_t initval);
#endif
#else
#error No hashing function found.
#endif

const unsigned int IPPOOL_STATSIZE = 0x10000;
static int connections = 0;

uint32_t SuperFastHash (const char * data, int len, uint32_t hash) {
  uint32_t tmp;
  int rem;

  if (len <= 0 || data == NULL) return 0;

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for (;len > 0; len--) {
    hash  += get16bits (data);
    tmp    = (get16bits (data+2) << 11) ^ hash;
    hash   = (hash << 16) ^ tmp;
    data  += 2*sizeof (uint16_t);
    hash  += hash >> 11;
  }

  /* Handle end cases */
  switch (rem) {
    case 3: hash += get16bits (data);
      hash ^= hash << 16;
      hash ^= data[sizeof (uint16_t)] << 18;
      hash += hash >> 11;
      break;
    case 2: hash += get16bits (data);
      hash ^= hash << 11;
      hash += hash >> 17;
      break;
    case 1: hash += *data;
      hash ^= hash << 10;
      hash += hash >> 1;
  }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;
}

uint32_t lookup(uint8_t *k,  uint32_t length,  uint32_t initval)
{
#ifdef HAVE_SFHASH
  return SuperFastHash((const char*)k, length, initval);
#elif HAVE_LOOKUP3
#if LITTLE_ENDIAN
  return hashlittle(k, length, initval);
#elif BIG_ENDIAN
  return hashbig(k, length, initval);
#endif
#endif
}

/**
 * dhcp_hash()
 * Generates a 32 bit hash based on a mac address
 **/
uint32_t macHash(uint8_t *hwaddr) {
  return lookup(hwaddr, PKT_ETH_ALEN, 0);
}

/**
 * Adds a connection to the hash table
 **/
int ip_addHash(struct gateway_t *this, ipconnections_t *conn) {
  uint32_t hash;
  ipconnections_t *p;
  ipconnections_t *p_prev = NULL;

  /* Insert into hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;
  if (!p_prev)
    this->hash[hash] = conn;
  else
    p_prev->nexthash = conn;

  return 0; /* Always OK to insert */
}


/**dhcp_hashget()
 * Uses the hash tables to find a connection based on the mac address.
 **/
static int ip_getHash(struct gateway_t *this, ipconnections_t **conn,
		 uint8_t *hwaddr) {
  ipconnections_t *p;
  uint32_t hash;

  /* Find in hash table */
  hash = macHash(hwaddr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if ((!memcmp(p->hismac, hwaddr, PKT_ETH_ALEN)) && (p->inuse)) {
      *conn = p;
      return 0;
    }
  }
  *conn = NULL;
  return -1; /* Address could not be found */
}


static size_t icmpfrag(ipconnections_t *conn,
		uint8_t *pack, size_t plen, uint8_t *orig_pack) {
  /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           unused = 0          |         Next-Hop MTU          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Used when we recived a truncated (from recvfrom() where our buffer
    is smaller than IP packet length) IP packet.
  */

  size_t icmp_req_len = PKT_IP_HLEN + 8;

  size_t icmp_ip_len = PKT_IP_HLEN + sizeof(struct pkt_icmphdr_t) +
      4 + icmp_req_len;

  size_t icmp_full_len = icmp_ip_len + sizeofeth(orig_pack);

  struct pkt_iphdr_t  *orig_pack_iph  = pkt_iphdr(orig_pack);
  struct pkt_ethhdr_t *orig_pack_ethh = pkt_ethhdr(orig_pack);

  if (icmp_full_len > plen) return 0;

  memset(pack, 0, icmp_full_len);
  copy_ethproto(orig_pack, pack);

  {
    struct pkt_ethhdr_t *pack_ethh  = pkt_ethhdr(pack);
    struct pkt_iphdr_t *pack_iph = pkt_iphdr(pack);
    struct pkt_icmphdr_t *pack_icmph;

    /* eth */
    memcpy(pack_ethh->dst, orig_pack_ethh->src, PKT_ETH_ALEN);
    memcpy(pack_ethh->src, orig_pack_ethh->dst, PKT_ETH_ALEN);

    /* ip */
    pack_iph->version_ihl = PKT_IP_VER_HLEN;
    pack_iph->saddr = conn->ourip.s_addr;
    pack_iph->daddr = orig_pack_iph->saddr;
    pack_iph->protocol = PKT_IP_PROTO_ICMP;
    pack_iph->ttl = 0x10;
    pack_iph->tot_len = htons(icmp_ip_len);

    pack_icmph = pkt_icmphdr(pack);
    pack_icmph->type = 3;
    pack_icmph->code = 4;

    /* go beyond icmp header and fill in next hop MTU */
    pack_icmph++;
    pack_icmph->check = htons(conn->mtu);

    memcpy(pack + (icmp_full_len - icmp_req_len),
	   orig_pack + sizeofeth(orig_pack), icmp_req_len);

    chksum(pack_iph);
  }

  return icmp_full_len;
}

/* Get IP address and mask */
static int parse_ip_aton(struct in_addr *addr, struct in_addr *mask, char *pool) {

  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  unsigned int m;
  int masklog;
  int c;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
	     &a1, &a2, &a3, &a4,
	     &m1, &m2, &m3, &m4);

  switch (c) {
    case 4:
      mask->s_addr = htonl(0xffffff00);
      break;
    case 5:
      if (m1 > 32) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Invalid mask */
      }
      mask->s_addr = m1 > 0 ? htonl(0xffffffff << (32 - m1)) : 0;
      break;
    case 8:
      if (m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Wrong mask format */
      }
      m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
      for (masklog = 0; ((1 << masklog) < ((~m)+1)); masklog++);
      if (((~m)+1) != (1 << masklog)) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Wrong mask format (not all ones followed by all zeros)*/
      }
      mask->s_addr = htonl(m);
      break;
    default:
      debug(LOG_ERR, "Invalid mask");
      return -1; /* Invalid mask */
  }

  if (a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256) {
    debug(LOG_ERR, "Wrong IP address format");
    return -1;
  }
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}


/* Create new address pool */
/*Jerome TBD for defining more parameters*/
static int ippool_new(struct ippool_t **this, char *dyn, int start, int end) {
	s_gwOptions *gwOptions = get_gwOptions();

  /* Parse only first instance of pool for now */
  int i;
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr stataddr;
  struct in_addr statmask;
  struct in_addr naddr;
  uint32_t m;
  uint32_t listsize;
  uint32_t dynsize;
  uint32_t statsize;

  char *stat = NULL;
  int allowdyn = 1;
  int allowstat = 0;

  if (!allowdyn) {
    dynsize = 0;
  }
  else {
    if (parse_ip_aton(&addr, &mask, dyn)) {
      debug(LOG_ERR, "Failed to parse dynamic pool");
      return -1;
    }

    /* auto-dhcpstart if not already set */
    if (!start)
      start = ntohl(addr.s_addr & ~(mask.s_addr));

    /* ensure we have the true network space */
    addr.s_addr = addr.s_addr & mask.s_addr;

    m = ntohl(mask.s_addr);
    dynsize = ((~m)+1);

    if ( ((ntohl(addr.s_addr) + start) & m) != (ntohl(addr.s_addr) & m) ) {
      addr.s_addr = htonl(ntohl(addr.s_addr) + start);
      debug(LOG_ERR, "Invalid dhcpstart=%d (%s) (outside of subnet)!",
             start, inet_ntoa(addr));
      return -1;
    }

    if ( ((ntohl(addr.s_addr) + end) & m) != (ntohl(addr.s_addr) & m) ) {
      debug(LOG_ERR, "Invalid dhcpend (outside of subnet)!");
      return -1;
    }

    if (start > 0 && end > 0) {

      if (end < start) {
	debug(LOG_ERR, "Bad arguments dhcpstart=%d and dhcpend=%d", start, end);
	return -1;
      }

      if ((end - start) > dynsize) {
	debug(LOG_ERR, "Too many IPs between dhcpstart=%d and dhcpend=%d",
               start, end);
	return -1;
      }

      dynsize = end - start;

    } else {

      if (start > 0) {

	/*
	 * if only dhcpstart is set, subtract that from count
	 */
	dynsize -= start;

	dynsize--;/* no broadcast */

      } else if (end > 0) {

	/*
	 * if only dhcpend is set, ensure only that many
	 */
	if (dynsize > end)
	  dynsize = end;

	dynsize--;/* no network */

      } else {
	dynsize-=2;/* no network, no broadcast */
      }

      dynsize--;/* no uamlisten */
    }
  }

  if (!allowstat) {
    statsize = 0;
    stataddr.s_addr = 0;
    statmask.s_addr = 0;
  }
  else {
    if (parse_ip_aton(&stataddr, &statmask, stat)) {
      debug(LOG_ERR, "Failed to parse static range");
      return -1;
    }

    /* ensure we have the true network space */
    stataddr.s_addr = stataddr.s_addr & statmask.s_addr;

    m = ntohl(statmask.s_addr);
    statsize = ((~m)+1);

    if (statsize > IPPOOL_STATSIZE)
      statsize = IPPOOL_STATSIZE;
  }

  listsize = dynsize + statsize; /* Allocate space for static IP addresses */

  if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
    debug(LOG_ERR, "Failed to allocate memory for ippool");
    return -1;
  }

  (*this)->allowdyn  = allowdyn;
  (*this)->allowstat = allowstat;
  (*this)->stataddr  = stataddr;
  (*this)->statmask  = statmask;

  (*this)->dynsize   = dynsize;
  (*this)->statsize  = statsize;
  (*this)->listsize  = listsize;

  if (!((*this)->member = calloc(sizeof(struct ippoolm_t), listsize))){
    debug(LOG_ERR, "Failed to allocate memory for members in ippool");
    return -1;
  }

  for ((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  debug(LOG_DEBUG, "Hashlog %d %d %d", (*this)->hashlog, listsize,
         (1 << (*this)->hashlog));

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet*/
  (*this)->hashmask = (*this)->hashsize -1;

  /* Allocate hash table */
  if (!((*this)->hash =
	calloc(sizeof(struct ippoolm_t *), (*this)->hashsize))){
    debug(LOG_ERR, "Failed to allocate memory for hash members in ippool");
    return -1;
  }

  if (start <= 0) /* adjust for skipping network */
    start = 1;

  (*this)->firstdyn = NULL;
  (*this)->lastdyn = NULL;

  for (i = 0; i < dynsize; i++) {

    naddr.s_addr = htonl(ntohl(addr.s_addr) + i + start);
    if (naddr.s_addr == gwOptions->tundevip.s_addr) {
      start++; /* skip the uamlisten address! */
      naddr.s_addr = htonl(ntohl(addr.s_addr) + i + start);
    }

    (*this)->member[i].addr.s_addr = naddr.s_addr;
    (*this)->member[i].in_use = 0;
    (*this)->member[i].is_static = 0;

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->lastdyn;
    if ((*this)->lastdyn) {
      (*this)->lastdyn->next = &((*this)->member[i]);
    }
    else {
      (*this)->firstdyn = &((*this)->member[i]);
    }
    (*this)->lastdyn = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */

    ippool_hashadd(*this, &(*this)->member[i]);
  }

  (*this)->firststat = NULL;
  (*this)->laststat = NULL;
  for (i = dynsize; i < listsize; i++) {
    (*this)->member[i].addr.s_addr = 0;
    (*this)->member[i].in_use = 0;
    (*this)->member[i].is_static = 1;

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->laststat;
    if ((*this)->laststat) {
      (*this)->laststat->next = &((*this)->member[i]);
    }
    else {
      (*this)->firststat = &((*this)->member[i]);
    }
    (*this)->laststat = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */
  }

  /*Jerome TBD for print if necessary*/
//    ippool_print(0, *this);

  return 0;
}


/**
 * Initialises hash tables
 **/
static int ip_initHash(struct gateway_t *this, int listsize) {
  /* Determine hashlog */
  for ((this)->hashlog = 0;
       ((1 << (this)->hashlog) < listsize);
       (this)->hashlog++);

  /* Determine hashsize */
  (this)->hashsize = 1 << (this)->hashlog;
  (this)->hashmask = (this)->hashsize -1;

  /* Allocate hash table */
  if (!((this)->hash =
	calloc(sizeof(ipconnections_t *), (this)->hashsize))) {
    /* Failed to allocate memory for hash members */
    return -1;
  }

  debug(LOG_DEBUG, "hash table size %d (%d)",   this->hashsize, listsize);
  return 0;
}


/**
 * Allocates/link a new connection from the pool.
 **/
static int addConnection(struct gateway_t *this, ipconnections_t **conn) {

	s_gwOptions *gwOptions = get_gwOptions();

  if (!this->firstfreeconn) {

    if (connections == DHCP_MAX_CLIENTS) {
      debug(LOG_ERR, "reached max connections %d!", DHCP_MAX_CLIENTS);
      return -1;
    }

    ++connections;

    if (!(*conn = calloc(1, sizeof(ipconnections_t)))) {
      debug(LOG_ERR, "Out of memory!");
      return -1;
    }

  } else {

    *conn = this->firstfreeconn;

    /* Remove from link of free */
    if (this->firstfreeconn->next) {
      this->firstfreeconn->next->prev = NULL;
      this->firstfreeconn = this->firstfreeconn->next;
    }
    else { /* Took the last one */
      this->firstfreeconn = NULL;
      this->lastfreeconn = NULL;
    }

    /* Initialise structures */
    memset(*conn, 0, sizeof(struct dhcp_conn_t));
  }

  /* Insert into link of used */
  if (this->firstusedconn) {
    this->firstusedconn->prev = *conn;
    (*conn)->next = this->firstusedconn;
  }
  else { /* First insert */
    this->lastusedconn = *conn;
  }

  this->firstusedconn = *conn;

  return 0; /* Success */
}

/**ip_getHash()
 * Allocates a new connection from the pool.
 **/
int ip_newConnection(struct gateway_t *this, ipconnections_t **conn,
		 uint8_t *hwaddr)
{

	s_gwOptions *gwOptions = get_gwOptions();
  debug(LOG_DEBUG, "IP newconn: "MAC_FMT"", MAC_ARG(hwaddr));

  if (addConnection(this, conn) != 0)
    return -1;

  (*conn)->inuse = 1;
  (*conn)->parent = this;
  (*conn)->mtu = this->mtu;

  /* Application specific initialisations */
  memcpy((*conn)->hismac, hwaddr, PKT_ETH_ALEN);

  (*conn)->lasttime = mainclock_tick();

  ip_addHash(this, *conn);

  /*Jerome TBD for MAC allowed list*/
  if ((gwOptions->macoklen) && !maccmp((*conn)->hismac, gwOptions)) {
	  (*conn)->authstate = DHCP_AUTH_PASS;
	  debug(LOG_DEBUG, "cb_dhcp_connect. MAC "MAC_FMT" is allowed.\n", MAC_ARG((*conn)->hismac));
  }else{
	  (*conn)->authstate = DHCP_AUTH_DNAT;
  }

  (*conn)->dns1 = gwOptions->dns1;
  (*conn)->dns2 = gwOptions->dns2;

  return 0; /* Success */
}


/**
 * Send ARP message to peer
 **/
static
int ip_sendARP(ipconnections_t *conn, uint8_t *pack, size_t len) {
  uint8_t packet[1500];
  struct gateway_t *this = conn->parent;
  struct in_addr reqaddr;

  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

  struct pkt_ethhdr_t *packet_ethh;
  struct arp_packet_t *packet_arp;

  /* Get local copy */
  memcpy(&reqaddr.s_addr, pack_arp->tpa, PKT_IP_ALEN);

  /* Check that request is within limits */

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  copy_ethproto(pack, packet);

  packet_ethh = pkt_ethhdr(packet);
  packet_arp = pkt_arppkt(packet);

  /* ARP Payload */
  packet_arp->hrd = htons(DHCP_HTYPE_ETH);
  packet_arp->pro = htons(PKT_ETH_PROTO_IP);
  packet_arp->hln = PKT_ETH_ALEN;
  packet_arp->pln = PKT_IP_ALEN;
  packet_arp->op  = htons(DHCP_ARP_REPLY);

  /* Source address */
  memcpy(packet_arp->spa, &reqaddr.s_addr, PKT_IP_ALEN);
  memcpy(packet_arp->sha, dhcp_nexthop(this), PKT_ETH_ALEN);

  /* Target address */
  memcpy(packet_arp->tha, &conn->hismac, PKT_ETH_ALEN);
  memcpy(packet_arp->tpa, &conn->hisip.s_addr, PKT_IP_ALEN);

  debug(LOG_DEBUG, "ARP: Replying to %s / "MAC_FMT,
           inet_ntoa(conn->hisip),
           MAC_ARG(conn->hismac));

  /* Ethernet header */
  memcpy(packet_ethh->dst, conn->hismac, PKT_ETH_ALEN);
  memcpy(packet_ethh->src, dhcp_nexthop(this), PKT_ETH_ALEN);

  return gw_sendDlData(this, 0, conn->hismac,
		   packet, sizeofarp(packet));
}


/**
 * Allocates a new instance of the library
 **/
int initIpHandling(struct gateway_t *pgateway) {

	s_gwOptions *gwOptions = get_gwOptions();

  /* Allocate ippool for dynamic IP address allocation */
	if (ippool_new(&pgateway->ippool, gwOptions->dhcpdynip, 0, 0)) {
       debug(LOG_ERR, "Failed to allocate IP pool!");
       return -1;
     }

  if (ip_initHash(pgateway, DHCP_HASH_TABLE))
    return -1; /* Failed to allocate hash tables */

  /* Initialise various variables */
  pgateway->lease = DHCP_LEASE_TIME;
//  phandler->numconn = DHCP_MAX_CLIENTS;

  /* Initialise call back functions
  dhcp->cb_data_ind = NULL;
  dhcp->cb_request = NULL;
  dhcp->cb_disconnect = NULL;
  dhcp->cb_connect = NULL;
*/
  return 0;
}


/* Find an IP address in the pool */
int ippoolGetip(struct ippool_t *this,
		 struct ippoolm_t **member,
		 struct in_addr *addr) {
  struct ippoolm_t *p;
  uint32_t hash;

  /* Find in hash table */
  hash = ippool_hash4(addr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if ((p->addr.s_addr == addr->s_addr) && (p->in_use)) {
      if (member) *member = p;
      return 0;
    }
  }

  if (member) *member = NULL;
  return -1;
}

/*dhcp_receive_arp*/
int ip_rcvArp(struct rawif_in *ctx, uint8_t *pack, size_t len) {

  struct in_addr reqaddr;
  struct in_addr taraddr;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

	s_gwOptions *gwOptions = get_gwOptions();
	struct gateway_t *this = ctx->parent;
  ipconnections_t *conn = 0;

  if (len < sizeofeth(pack) + sizeof(struct arp_packet_t)) {
    debug(LOG_ERR, "ARP too short %d < %d", (int) len,
           (int) (sizeofeth(pack) + sizeof(struct arp_packet_t)));
    return 0;
  }

  if (ntohs(pack_arp->hrd) != 1 ||       /* Ethernet Hardware */
      pack_arp->hln != PKT_ETH_ALEN ||   /* MAC Address Size */
      pack_arp->pln != PKT_IP_ALEN) {    /* IP Address Size */
	  	  debug(LOG_ERR, "ARP reject hrd=%d hln=%d pln=%d",
           ntohs(pack_arp->hrd), pack_arp->hln, pack_arp->pln);
    return 0;
  }

  /* Check that this is ARP request */
  if (pack_arp->op != htons(DHCP_ARP_REQUEST)) {
    debug(LOG_DEBUG, "ARP OP %d: Received other ARP than request!", ntohl(pack_arp->op));
    return 0;
  }

  /* Check that MAC address is our MAC or Broadcast */
  /*Jerome TBD for mulit LAN ARP*/
  if ((memcmp(pack_ethh->dst, this->rawIf[0], PKT_ETH_ALEN)) &&
      (memcmp(pack_ethh->dst, broadcastmac, PKT_ETH_ALEN))) {
    debug(LOG_DEBUG, "ARP: Received ARP request for other destination!");
    return 0;
  }

  /* get sender IP address */
  memcpy(&reqaddr.s_addr, &pack_arp->spa, PKT_IP_ALEN);

  /* get target IP address */
  memcpy(&taraddr.s_addr, &pack_arp->tpa, PKT_IP_ALEN);

  /* Check to see if we know MAC address. */
  if (ip_getHash(this, &conn, pack_arp->sha)) {
    debug(LOG_DEBUG, "ARP: Address not found with IP: %s", inet_ntoa(reqaddr));

    /*Insert new connection of ARP for reused IP allocated during last connection*/
    if (ip_newConnection(this, &conn, pack_arp->sha)) {
      debug(LOG_WARNING, "ARP: out of connections for allocating new access");
      return 0;
    }
  }

  debug(LOG_DEBUG, "ARP: "MAC_FMT" asking about target IP: %s",
           MAC_ARG(conn->hismac),
           inet_ntoa(taraddr));

/*Jerome: respond to ARP without authatation
  if (conn->authstate == DHCP_AUTH_DROP) {
    return 0;
  }
End, Jerome*/

  /* if no sender ip, then client is checking their own ip*/
  /* XXX: lookup in ippool to see if we really do know who has this */
  /* XXX: it should also ack if *we* are that ip */
  /*Jerome, RARP procedure without real response
  if (!reqaddr.s_addr) {

    debug(LOG_DEBUG, "ARP: Ignoring self-discovery: %s",
             inet_ntoa(taraddr));

     	this->cb_request(conn, &taraddr, 0, 0);

    return 0;
  }
  End, Jerome, don't know why to do it*/

  if (!memcmp(&reqaddr.s_addr, &taraddr.s_addr, 4)) {
    debug(LOG_DEBUG, "ARP: Ignoring gratuitous arp with IP: %s",
             inet_ntoa(taraddr));
    return 0;
  }

  /* Is ARP request for clients own address: Ignore */
  if (!memcmp(&conn->hisip.s_addr, &taraddr.s_addr, 4)) {
    debug(LOG_DEBUG, "ARP: hisip equals target ip: %s",
             inet_ntoa(conn->hisip));
    return 0;
  }

/*Jerome: no authstating process in ARP
  if (conn->authstate == DHCP_AUTH_NONE)
    this->cb_request(conn, &reqaddr, 0, 0);
End, Jerome*/

  /* Quit. Only reply if he was allocated an address,
     unless it was a request for the gateway dhcplisten. */
  /*JeModuel changed
  if (memcmp(&config->dhcplisten.s_addr, &taraddr.s_addr, 4) &&
      !conn->hisip.s_addr) {

    debug(LOG_DEBUG, "ARP: request did not come from known client");
    return 0;
  }
*/
  /* if ourip differs from target ip */
  /* Only reply if he asked for his router address */
  /*JeModuel changed
    if (memcmp(&conn->ourip.s_addr, &taraddr.s_addr, 4) &&
    		memcmp(&config->tundevip.s_addr, &taraddr.s_addr, 4)) {

       debug(LOG_DEBUG, "ARP: Did not ask for router address: %s",
               inet_ntoa(conn->ourip));
	   debug(LOG_DEBUG, "ARP: Asked for target: %s",
               inet_ntoa(taraddr));
       return 0;
    }
*/
  if (!conn->hisip.s_addr) {
    debug(LOG_DEBUG, "ARP: request did not come from known client asking for target: %s",
    		inet_ntoa(taraddr));
    return 0;
  }
  if (memcmp(&gwOptions->tundevip.s_addr, &taraddr.s_addr, 4)) {

     debug(LOG_DEBUG, "ARP: Did not ask for gateway address: %s, but ask for target: %s",
    		 inet_ntoa(gwOptions->tundevip), inet_ntoa(taraddr));
     return 0;
  }

  conn->lasttime = mainclock_tick();
  ip_sendARP(conn, pack, len);
  return 0;
}


/**
 *  dhcp_receive_ip()
 *  Received a packet from the dhcpif
 */
int ip_rcvIp(struct rawif_in *ctx, uint8_t *pack, size_t len) {
  struct gateway_t *this = ctx->parent;
  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *pack_tcph = 0;
  struct pkt_udphdr_t *pack_udph = 0;

  ipconnections_t *conn = 0;
  struct in_addr ourip;
  struct in_addr srcaddr, dstaddr;

  char do_checksum = 0;
  char allowed = 0;
  char has_ip = 0;
  char is_dhcp = 0;

  int authstate = 0;

  s_gwOptions *gwOptions = get_gwOptions();

  uint16_t iph_tot_len;
  uint16_t eth_tot_len;

  if (len < PKT_IP_HLEN + PKT_ETH_HLEN + 4) {
    debug(LOG_ERR, "IP: too short");
    return 0;
  }

  if ((pack_iph->version_ihl & 0xf0) != 0x40) {
    debug(LOG_DEBUG, "IP: dropping non-IPv4");
    return 0;
  }

  srcaddr.s_addr = pack_iph->saddr;
  dstaddr.s_addr = pack_iph->daddr;
  debug(LOG_DEBUG, "Gateway received packet from IP %s", inet_ntoa(srcaddr));
  debug(LOG_DEBUG, "Gateway received packet to IP %s", inet_ntoa(dstaddr));

  /*
   *  Check to see if we know MAC address
   */
  if (!ip_getHash(this, &conn, pack_ethh->src)) {

    debug(LOG_DEBUG, "IP: MAC Address "MAC_FMT" found", MAC_ARG(pack_ethh->src));
    //found of MAC doesnot mean there is IP
    //    ourip.s_addr = conn->ourip.s_addr;

  } else {

    struct in_addr reqaddr;

    memcpy(&reqaddr.s_addr, &pack_iph->saddr, PKT_IP_ALEN);

    debug(LOG_DEBUG, "IP: MAC address "MAC_FMT" not found with IP (%s), add new connection",
    		MAC_ARG(pack_ethh->src),
			inet_ntoa(reqaddr));

    /* Allocate new connection */
    if (ip_newConnection(this, &conn, pack_ethh->src)) {
      debug(LOG_DEBUG, "dropping packet; out of connections");
      return 0; /* Out of connections */
    }
  }

  /* Jerome TBD? Return if we do not know peer */
  if (!conn) {
    debug(LOG_ERR, "dropping packet; no peer");
    return 0;
  }

  /*
   * Sanity check on IP total length
   */
  iph_tot_len = ntohs(pack_iph->tot_len);
  eth_tot_len = iph_tot_len + sizeofeth(pack);

  if (eth_tot_len > (uint16_t) len) {
    debug(LOG_ERR, "dropping ip packet; ip-len=%d + eth-hdr=%d > read-len=%d",
             iph_tot_len,
             sizeofeth(pack), (int)len);

    if (pack_iph->opt_off_high & 64) { /* Don't Defrag Option */
      uint8_t icmp_pack[1500];

      debug(LOG_ERR, "Sending fragmentation ICMP");
      gw_sendDlData(this, ctx->idx, pack_ethh->src, icmp_pack,
		icmpfrag(conn, icmp_pack, sizeof(icmp_pack), pack));
    }

    return 0;
  }

  /* Validate IP header length */
  if ((pack_iph->version_ihl & 0xf) < 5 ||
      (pack_iph->version_ihl & 0xf) * 4 > iph_tot_len) {
    debug(LOG_ERR, "dropping invalid-IPv4");
    return 0;
  }

  /*
   * Do not drop all fragments, only if they have DF bit.
   * Note: this is as in SVN before R462 / git e4a934 (2012-03-01 15:46:22).
   */

  if (iph_tot_len > conn->mtu && (pack_iph->opt_off_high & 64)) {
    uint8_t icmp_pack[1500];
    debug(LOG_ERR, "ICMP frag forbidden for IP packet with length %d > %d",
             iph_tot_len, conn->mtu);
    gw_sendDlData(this, ctx->idx, pack_ethh->src, icmp_pack,
	      icmpfrag(conn, icmp_pack, sizeof(icmp_pack), pack));
    return 0;
  }

  /*
   *  Chop off any trailer length
   */
  if (len > (size_t) eth_tot_len) {
    //log_dbg("chopping off trailer length %d", len - eth_tot_len);
    len = eth_tot_len;
  }

  /*
   * Sanity check on UDP total length
   * Note: we cannot check fragments.
   */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP) {
    pack_udph = pkt_udphdr(pack);
    uint16_t udph_len = ntohs(pack_udph->len);
    if (udph_len < PKT_UDP_HLEN || iph_tot_len < PKT_IP_HLEN + PKT_UDP_HLEN ||
        (iph_tot_len != udph_len + PKT_IP_HLEN && iphdr_more_frag(pack_iph) == 0 && iphdr_offset(pack_iph) == 0)) {
    	debug(LOG_ERR, "dropping udp packet; ip-len=%d != udp-len=%d + ip-hdr=20",
               (int) iph_tot_len,
               (int) udph_len);
    	return 0;
    }
  }

  if (pack_iph->protocol == PKT_IP_PROTO_TCP) {
    pack_tcph = pkt_tcphdr(pack);
    if (iph_tot_len < PKT_IP_HLEN + PKT_TCP_HLEN) {
      debug(LOG_ERR, "dropping tcp packet; ip-len=%d",
               (int) iph_tot_len);
      return 0;
    }
  }

  /*
   *  Check that the destination MAC address is our MAC or Broadcast
   */
  if ((memcmp(pack_ethh->dst, dhcp_nexthop(this), PKT_ETH_ALEN)) &&
      (memcmp(pack_ethh->dst, bmac, PKT_ETH_ALEN))) {

	  debug(LOG_DEBUG, "Not for our MAC or broadcast: "MAC_FMT"",
               MAC_ARG(pack_ethh->dst));

      return 0;
  }

  ourip.s_addr = this->ourip.s_addr;

  /*
   *  DHCP (BOOTPS) packets for broadcast or us specifically
   */
  is_dhcp = (((pack_iph->daddr == 0) ||
	      (pack_iph->daddr == 0xffffffff) ||
	      (pack_iph->daddr == ourip.s_addr)) &&
	     (pack_udph && (pack_udph->dst == htons(DHCP_BOOTPS))));

  if (is_dhcp) {
    debug(LOG_DEBUG, "IP: new dhcp/bootps request being processed for "MAC_FMT"",
               MAC_ARG(pack_ethh->src));
    (void) dhcp_getreq(ctx, pack, len);
    return 0;
  }

  has_ip = conn->hisip.s_addr != 0;
  if (!has_ip){
    debug(LOG_DEBUG, "no hisip; packet-drop");
    return 0;
  }

  authstate = conn->authstate;

  /*Jerome: 判断是否本DHCP分配过地址，没有的话先接受client使用的IP*/
  if ((!conn->hisip.s_addr) &&
      (((pack_iph->daddr != 0) &&
           (pack_iph->daddr != 0xffffffff)))) {
	  struct in_addr addr;
	  addr.s_addr = pack_iph->saddr;
    if (this->cb_request)
      if (this->cb_request(conn, &addr, 0, 0)) {
        debug(LOG_DEBUG, "dropping packet; ip not known: %s",   inet_ntoa(addr));
	return 0; // Ignore request if IP address was not allocated
      }
  }
  /*End. Jerome*/

  /*Jerome Changes procedure. Ignore request if IP address was not allocated by this DHCP*/
  struct ippoolm_t *ipm = 0;
  if(conn->peer){
	  struct _t_client *client = conn->peer;
	  if(client->uplink){
		    /*
		     *  IP Address is already known and allocated.
		     */
		    ipm = (struct ippoolm_t*) client->uplink;
	  }
  }
  if(!ipm){
	  debug(LOG_ERR, "IP: failed to allocated IP!");
	    return -1;
  }
  /*End. Jereome */

  conn->lasttime = mainclock_now();

  if (pack_iph->saddr != conn->hisip.s_addr) {
	debug(LOG_ERR, "Received packet with spoofed source!");
    /*dhcp_sendRENEW(conn, pack, len);*/
    return 0;
  }

  switch (pack_iph->protocol) {

    case PKT_IP_PROTO_UDP:

      if ((pack_iph->daddr & config->netmask.s_addr) ==
          (0xffffffff & ~config->netmask.s_addr)) {

        debug(LOG_DEBUG, "Broadcasted UDP to port %d",   ntohs(pack_udph->dst));

        return 0;
      }

      break; /* UDP */

    case PKT_IP_PROTO_TCP:

      /* Was it a request for the auto-logout service? */
      /*Jerome: no uamlogout
      if ((pack_iph->daddr == _options.uamlogout.s_addr) &&
          (pack_tcph->dst == htons(DHCP_HTTP))) {
        if (!appconn)
          appconn = dhcp_get_appconn_pkt(conn, pack_iph, 0);
        if (appconn) {
          if (appconn->s_state.authenticated) {
            terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);
            debug(LOG_DEBUG, "Dropping session due to request for auto-logout ip");
            appconn->uamexit = 1;
          }
        }
      }End, Jerome*/

      break; /* TCP */
  }

  /* Jerome: uamlias are not used
  if (_options.uamalias.s_addr &&
      pack_iph->daddr == _options.uamalias.s_addr &&
      pack_tcph) {

    do_checksum = 1;
    dhcp_uam_nat(conn, pack_ethh, pack_iph, pack_tcph, &this->uamlisten,
		 this->uamport);
  }
	End, Jerome*/

  /* Was it a DNS request? */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->dst == htons(DHCP_DNS)) {

	  debug(LOG_DEBUG, "A DNS request!");

	    if (!dhcp_dns(conn, pack, &len)) {
	      debug(LOG_DEBUG, "A DNS is handled in dhcp_dns()!");
	      return 0; /* Drop DNS if dhcp_dns returns 0*/
	    }

	    allowed = 1; /* Is allowed DNS */

  }

  debug(LOG_DEBUG, "DHCP received packet with authstate %d", authstate);
  switch (authstate) {

    case DHCP_AUTH_PASS:

      /* Check for post-auth proxy, otherwise pass packets unmodified */
      /*Jerome: no post DNAT for proxy*/
      //dhcp_postauthDNAT(conn, pack, len, 0, &do_checksum);
      break;

      /* Destination NAT if request to unknown web server */
    case DHCP_AUTH_DNAT:

      if (dhcp_doDNAT(conn, pack, len, 1, &do_checksum) && !allowed) {
        debug(LOG_DEBUG, "dropping packet; not nat'ed");
        return 0;
      }
      break;

      /*Jerome, no splash state
    case DHCP_AUTH_SPLASH:
      dhcp_doDNAT(conn, pack, len, 0, &do_checksum);
      break;
end, Jerome*/

    case DHCP_AUTH_DROP:
      debug(LOG_DEBUG, "dropping packet; auth-drop");

      return 0;

    default:
      debug(LOG_DEBUG, "dropping packet; unhandled auth state %d",   authstate);

      return 0;
  }

  /*done:*/


  if (do_checksum)
    chksum(pack_iph);

  if (this->cb_data_ind) {
	  srcaddr.s_addr = pack_iph->saddr;
	  dstaddr.s_addr = pack_iph->daddr;
	  debug(LOG_DEBUG, "DHCP sending packet from IP %s", inet_ntoa(srcaddr));
	  debug(LOG_DEBUG, "DHCP sending packet to IP %s of length %d", inet_ntoa(dstaddr), len);

    this->cb_data_ind(conn, pack, len);
  } else {
    debug(LOG_DEBUG, "Call cb_date_ind fail; packet-drop");
  }

  return 0;
}

