/*
 * ipprocessing.c
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

#include "common.h"
#include "gatewayapi.h"
#include "ipprocessing.h"
#include "dhcphandler.h"
#include "dnshandler.h"
#include "arphandler.h"

#include "homenet.h"
#include "homeconfig.h"
#include "debug.h"
#include "functions.h"

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


#undef get16bits
#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)    \
                      +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

const unsigned int IPPOOL_STATSIZE = 0x10000;
static int connections = 0;
extern struct timespec mainclock;

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

uint32_t ippool_hash4(struct in_addr *addr) {
  return lookup((unsigned char *)&addr->s_addr, sizeof(addr->s_addr), 0);
}

/**
 * dhcp_hash()
 * Generates a 32 bit hash based on a mac address
 **/
uint32_t macHash(uint8_t *hwaddr) {
  return lookup(hwaddr, PKT_ETH_ALEN, 0);
}


/**
 * dhcp_hashdel()
 * Removes a connection from the hash table
 **/
int delMacHash(struct gateway_t *this, struct ipconnections_t *conn) {
  uint32_t hash;
  struct ipconnections_t *p = NULL;
  struct ipconnections_t *p_prev = NULL;

  if (conn == (struct ipconnections_t *)0) {
    debug(LOG_ERR, "%s: Bad input param conn(%p)",  conn);
    return -1;
  }

  /* Find in hash table */
  hash = macHash(conn->hismac) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if (p == conn) {
      break;
    }
    p_prev = p;
  }

  if (p != conn) {
    debug(LOG_ERR, "trying to remove connection not in hash table");
    return -1;
  }

  if (!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

/**dhcp_hashadd()
 * Adds a connection to the hash table by MAC address
 **/
int addMacHash(struct gateway_t *this, struct ipconnections_t *conn) {
  uint32_t hash;
  struct ipconnections_t *p;
  struct ipconnections_t *p_prev = NULL;

  /* Insert into hash table */
  hash = macHash(conn->hismac) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;
  if (!p_prev)
    this->hash[hash] = conn;
  else
    p_prev->nexthash = conn;

  return 0; /* Always OK to insert */
}


/**dhcp_hashinit()
 * Initialises hash tables
 **/
static int initMacHash(struct gateway_t *this, int listsize) {
  /* Determine hashlog */
  for ((this)->hashlog = 0;
       ((1 << (this)->hashlog) < listsize);
       (this)->hashlog++);

  /* Determine hashsize */
  (this)->hashsize = 1 << (this)->hashlog;
  (this)->hashmask = (this)->hashsize -1;

  /* Allocate hash table */
  if (!((this)->hash =
	calloc(sizeof(struct ipconnections_t *), (this)->hashsize))) {
    /* Failed to allocate memory for hash members */
    return -1;
  }

  debug(LOG_DEBUG, "hash table size %d (%d)",   this->hashsize, listsize);
  return 0;
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


int ip_addHash(struct ippool_t *this, struct ippoolm_t *member) {
  uint32_t hash;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Insert into hash table */
  hash = ippool_hash4(&member->addr) & this->hashmask;

  for (p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;

  if (!p_prev)
    this->hash[hash] = member;
  else
    p_prev->nexthash = member;

  return 0; /* Always OK to insert */
}

int ip_freeIp(struct ippool_t *this, struct ippoolm_t *member) {

/*Jerome TBD for print if necessary*/
	//ippool_print(0, this);
  if (!member->in_use) {
    debug(LOG_ERR, "Address not in use");
    return -1; /* Not in use: Should not happen */
  }

    member->prev = this->lastdyn;

    if (this->lastdyn) {
      this->lastdyn->next = member;
    }
    else {
      this->firstdyn = member;
    }

    this->lastdyn = member;

    member->in_use = 0;
    member->peer = NULL;

  /*Jerome TBD for print if necessary*/
//   ippool_print(0, this);
  return 0;
}

/**
 * ippool_newip
 * Get an IP address. If addr = 0.0.0.0 get a dynamic IP address. Otherwise
 * check to see if the given address is available. If available allocate it there, otherwise allocate a new one*/
int ip_newIp(struct ippool_t *this,
		 struct ippoolm_t **member, struct in_addr *addr) {
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p2 = NULL;
  uint32_t hash;

  debug(LOG_DEBUG, "Requesting new ip of client with IP: %s", inet_ntoa(*addr));

  /*Jerome TBD for print if necessary*/
//    ippool_print(0, this);

  /* If IP address given try to find it in address pool */
  if ((addr) && (addr->s_addr)) { /* IP address given */
    /* Find in hash table */
    hash = ippool_hash4(addr) & this->hashmask;
    for (p = this->hash[hash]; p; p = p->nexthash) {
      if (p->addr.s_addr == addr->s_addr) {
    	  p2 = p;
    	  break;
      }
    }
    /* If IP was already allocated we can not use it */
    if ((p2) && (p2->in_use)) {
      p2 = NULL;
      return WH_FAIL;
    }
  }

  /* If not found yet then allocate an IP position*/
  if (!p2) {
    if (!this->firstdyn) {
      debug(LOG_ERR, "No more dynamic addresses available");
      return WH_FAIL;
    }
    else {
      p2 = this->firstdyn;
    }
  }

  if (p2) { /* Was allocated from address pool */

    /* Remove from linked list of free dynamic addresses */
    if (p2->prev)
      p2->prev->next = p2->next;
    else
      this->firstdyn = p2->next;

    if (p2->next)
      p2->next->prev = p2->prev;
    else
      this->lastdyn = p2->prev;

    p2->next = NULL;
    p2->prev = NULL;
    p2->in_use = 1;

    *member = p2;
    /*Jerome TBD for print if necessery*/
    //    ippool_print(0, this);
    return WH_SUCC; /* Success */
  }
  return WH_FAIL;
}


/* Create new address pool */
/*Jerome TBD for defining more parameters*/
static int ip_newPool(struct ippool_t **this, char *dyn, int start, int end) {
	s_gwOptions *gwOptions = get_gwOptions();

  /* Parse only first instance of pool for now */
  int i;
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr stataddr;
  struct in_addr statmask;
  struct in_addr naddr;
  uint32_t m;

  uint32_t dynsize;

    if (parse_ip_aton(&addr, &mask, dyn)) {
      debug(LOG_ERR, "Failed to parse dynamic pool");
      return -1;
    }

    /* auto-dhcp start if not already set */
    if (!start)
      start = ntohl(addr.s_addr & ~(mask.s_addr));

    /* ensure we have the true network space */
    addr.s_addr = addr.s_addr & mask.s_addr;

    m = ntohl(mask.s_addr);
    dynsize = ((~m)+1);

    if ( ((ntohl(addr.s_addr) + start) & m) != (ntohl(addr.s_addr) & m) ) {
      addr.s_addr = htonl(ntohl(addr.s_addr) + start);
      debug(LOG_ERR, "Invalid dhcp start=%d (%s) (outside of subnet)!",
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
    	  /* if only dhcpstart is set, subtract that from count	 */
    	  dynsize -= start;
    	  dynsize--;/* no broadcast */

      } else if (end > 0) {
    	  /*if only dhcpend is set, ensure only that many	 */
    	  if (dynsize > end)
    		  dynsize = end;

    	  dynsize--;/* no network */
      } else {
    	  dynsize-=2;/* no network, no broadcast */
      }

      dynsize--;/* no tun devive IP */
    }

  if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
    debug(LOG_ERR, "Failed to allocate memory for ippool");
    return -1;
  }

  (*this)->dynsize   = dynsize;

  if (!((*this)->member = calloc(sizeof(struct ippoolm_t), dynsize))){
    debug(LOG_ERR, "Failed to allocate memory for members in ippool");
    return -1;
  }

  for ((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < dynsize);
       (*this)->hashlog++);

  debug(LOG_DEBUG, "Hashlog %d %d %d", (*this)->hashlog, dynsize,
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
      start++; /* skip the tun device IP address! */
      naddr.s_addr = htonl(ntohl(addr.s_addr) + i + start);
    }

    (*this)->member[i].addr.s_addr = naddr.s_addr;
    (*this)->member[i].in_use = 0;

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

    ip_addHash(*this, &(*this)->member[i]);
  }

  /*Jerome TBD for print if necessary*/
//    ippool_print(0, *this);

  return 0;
}


static size_t icmpfrag(struct gateway_t *this,
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
    pack_iph->saddr = this->ourip.s_addr;
    pack_iph->daddr = orig_pack_iph->saddr;
    pack_iph->protocol = PKT_IP_PROTO_ICMP;
    pack_iph->ttl = 0x10;
    pack_iph->tot_len = htons(icmp_ip_len);

    pack_icmph = pkt_icmphdr(pack);
    pack_icmph->type = 3;
    pack_icmph->code = 4;

    /* go beyond icmp header and fill in next hop MTU */
    pack_icmph++;
    pack_icmph->check = htons(this->mtu);

    memcpy(pack + (icmp_full_len - icmp_req_len),
	   orig_pack + sizeofeth(orig_pack), icmp_req_len);

    chksum(pack_iph);
  }

  return icmp_full_len;
}


/* Compare a MAC address to the addresses given in the macallowed option */
int static maccmp(unsigned char *mac, s_gwOptions *option) {
  int i;

  for (i=0; i < option->macoklen; i++)
    if (!memcmp(mac, option->macok[i], PKT_ETH_ALEN))
      return 0;

  return -1;
}


static
int setEthhdr(uint8_t *packet, uint8_t *hismac,
                uint8_t *nexthop, uint16_t prot) {

    struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(packet);
    copy_mac6(pack_ethh->dst, hismac);
    copy_mac6(pack_ethh->src, nexthop);
    pack_ethh->prot = htons(prot);

  return 0;
}


/**
 * Allocates/link a new connection from the pool.
 **/
static int addConnection(struct gateway_t *this, struct ipconnections_t **conn) {

	s_gwOptions *gwOptions = get_gwOptions();

  if (!this->firstfreeconn) {

    if (connections == DHCP_MAX_CLIENTS) {
      debug(LOG_ERR, "reached max connections %d!", DHCP_MAX_CLIENTS);
      return -1;
    }

    ++connections;

    if (!(*conn = calloc(1, sizeof(struct ipconnections_t)))) {
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
    memset(*conn, 0, sizeof(struct ipconnections_t));
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

static
int undoDnat(struct ipconnections_t *conn,
		   struct pkt_ethhdr_t *ethh,
		   struct pkt_iphdr_t  *iph,
		   struct pkt_tcphdr_t *tcph) {
  int n;
  for (n=0; n < DHCP_DNAT_MAX; n++) {

    if (iph->daddr == conn->dnat[n].src_ip &&
	tcph->dst == conn->dnat[n].src_port) {

      iph->saddr = conn->dnat[n].dst_ip;
      tcph->src = conn->dnat[n].dst_port;

      chksum(iph);

      return 0;
    }
  }
  return 0;
}
/**
 * dhcp_undoDNAT()
 * Change source address back to original server
 **/
static
int checkHttpUndoDNAT(struct ipconnections_t *conn,
		  uint8_t *pack, size_t *plen,
		  char do_reset, char *do_checksum) {
  struct gateway_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *tcph = pkt_tcphdr(pack);

  /* Allow localhost through network... */
  if (iph->saddr == INADDR_LOOPBACK)
    return 0;

  if (iph->protocol == PKT_IP_PROTO_ICMP) {
    /* Was it an ICMP reply from us? */
    if (iph->saddr == conn->ourip.s_addr) {

      return 0;
    }
  }

  /* Was it a reply from redir server? */
  if ( (iph->saddr == this->ourip.s_addr) &&
       (iph->protocol == PKT_IP_PROTO_TCP) &&
       (tcph->src == htons(this->uamport))) {

    *do_checksum = 1;
    return undoDnat(conn, ethh, iph, tcph);
  }

  return -1; /* Something else */
}


/**
 * dhcp_uam_nat()
 * Change destination address to authentication server.
 **/
static
int doDnat(struct ipconnections_t *conn,
		 struct pkt_ethhdr_t *ethh,
		 struct pkt_iphdr_t  *iph,
		 struct pkt_tcphdr_t *tcph,
		 struct in_addr *addr,
		 uint16_t port) {
  int n;
  int pos = -1;

  debug(LOG_DEBUG, "Http connection DNAT to %s : %d",   inet_ntoa(*addr), port);

  for (n=0; n < DHCP_DNAT_MAX; n++) {
    if (conn->dnat[n].src_ip == iph->saddr &&
	conn->dnat[n].src_port == tcph->src) {
      pos = n;
      debug(LOG_DEBUG, "DNAT pos %d",  pos);
      break;
    }
  }

  if (pos == -1) {
    pos = conn->nextdnat;
    conn->dnat[pos].src_ip = iph->saddr;
    conn->dnat[pos].src_port = tcph->src;
    conn->nextdnat = (conn->nextdnat + 1) % DHCP_DNAT_MAX;
  }

  conn->dnat[pos].dst_ip = iph->daddr;
  conn->dnat[pos].dst_port = tcph->dst;

  iph->daddr = addr->s_addr;
  tcph->dst = htons(port);

  chksum(iph);
  return 0;
}

/**
 * dhcp_doDNAT()
 * Change destination address to authentication server.
 **/
int checkHttpDnat(struct ipconnections_t *conn, uint8_t *pack,
		size_t len, char do_reset,
		char *do_checksum) {
  struct gateway_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *tcph = pkt_tcphdr(pack);

  /* Allow localhost through network... */
  if (iph->daddr == INADDR_LOOPBACK)
    return 0;

  /* Was it an ICMP request for us? */
  if (iph->protocol == PKT_IP_PROTO_ICMP) {
    if (iph->daddr == conn->ourip.s_addr) {
      return 0;
    }
  }

  /* If destination was in local net, no need DNAT*/
  if ((iph->daddr != this->ourip.s_addr) &&
		  ((iph->daddr & this->netmask.s_addr) == (this->ourip.s_addr & this->netmask.s_addr))) {
    return 0;
  }

  if (iph->protocol == PKT_IP_PROTO_TCP) {
    if (tcph->dst == htons(DHCP_HTTP)) {
      /* Changing dest IP and dest port to local gateway web server*/
      *do_checksum = 1;
      debug(LOG_DEBUG, "Catched Http connection to %s port %d",   inet_ntoa((struct in_addr)(iph->daddr)), tcph->dst);
      return doDnat(conn, ethh, iph, tcph,
			  &this->ourip, this->uamport);
    }
  }

  return -1; /* Something else */
}


/**
 * Allocates a new instance of the library
 **/
int initIpHandling(struct gateway_t *pgateway) {

	s_gwOptions *gwOptions = get_gwOptions();

  /* Allocate ippool for dynamic IP address allocation */
	if (ip_newPool(&pgateway->ippool, gwOptions->dhcpdynip, 0, 0)) {
       debug(LOG_ERR, "Failed to allocate IP pool!");
       return -1;
     }

  if (initMacHash(pgateway, DHCP_HASH_TABLE))
    return -1; /* Failed to allocate hash tables */

  /* Initialise various variables */
  pgateway->lease = DHCP_LEASE_TIME;
//  phandler->numconn = DHCP_MAX_CLIENTS;

  /* Initialise call back functions
  dhcp->cb_data_ind = NULL;
*/
  return 0;
}


/**
 *  dhcp_receive_ip()
 *  Received a packet from the dhcpif
 */
int raw_rcvIp(struct rawif_in *ctx, uint8_t *pack, size_t len) {
  struct gateway_t *this = ctx->parent;
	int rawifindex = ctx->idx;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *pack_tcph = 0;
  struct pkt_udphdr_t *pack_udph = 0;

  struct ipconnections_t *conn = 0;
  struct in_addr srcaddr, dstaddr;

  char do_checksum = 0;
  char allowed = 0;
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
   *  Check that the destination MAC address is our MAC or Broadcast
   */
  if ((memcmp(pack_ethh->dst, this->rawIf[rawifindex].hwaddr, PKT_ETH_ALEN)) &&
      (memcmp(pack_ethh->dst, broadcastmac, PKT_ETH_ALEN))) {
		 debug(LOG_DEBUG, "Not for our MAC, or broadcast: "MAC_FMT"",
	               MAC_ARG(pack_ethh->dst));
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
      gw_sendDlData(this, rawifindex, pack_ethh->src, icmp_pack,
		icmpfrag(this, icmp_pack, sizeof(icmp_pack), pack));
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

  if (iph_tot_len > this->mtu && (pack_iph->opt_off_high & 64)) {
    uint8_t icmp_pack[1500];
    debug(LOG_ERR, "ICMP frag forbidden for IP packet with length %d > %d",
             iph_tot_len, this->mtu);
    gw_sendDlData(this, rawifindex, pack_ethh->src, icmp_pack,
	      icmpfrag(this, icmp_pack, sizeof(icmp_pack), pack));
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
   *  Check to see if we know MAC address
   */
  if (!getMacHash(this, &conn, pack_ethh->src)) {
    debug(LOG_DEBUG, "IP handler: MAC Address "MAC_FMT" found with IP %s",
    		MAC_ARG(pack_ethh->src), inet_ntoa(conn->hisip));
  } else {
	  /*First connection with home gateway, with(statically set) or without(dynamically) IP address*/
	  struct in_addr reqaddr;
	  memcpy(&reqaddr.s_addr, &pack_iph->saddr, PKT_IP_ALEN);

	  /* Allocate new connection without recording IP address*/
	  if (ip_newConnection(this, &conn, pack_ethh->src)) {
		  debug(LOG_DEBUG, "dropping packet; fail of adding connections");
		  return 0; /* Out of connections */
	  }
	  conn->rawIdx = rawifindex;

	  if(reqaddr.s_addr != 0){
		  debug(LOG_DEBUG, "IP: MAC address "MAC_FMT" not found with statically set IP (%s), add new connection",
	    		MAC_ARG(pack_ethh->src),
				inet_ntoa(reqaddr));
	  }else{
		  debug(LOG_DEBUG, "IP: MAC address "MAC_FMT" not found without IP, add new connection",
	    		MAC_ARG(pack_ethh->src));
	  }

	  /*Recording IP of new connection which could be 0.0.0.0*/
	  conn->hisip.s_addr = reqaddr.s_addr;
  }

  if (!conn) {
    debug(LOG_ERR, "Dropping packet without record in home gateway");
    return 0;
  }

  /*New Connection will be recorded during BOOTPS unless it is statically set IP*/
  /* DHCP (BOOTPS) packets */
  is_dhcp = (((pack_iph->daddr == 0) ||
	      (pack_iph->daddr == 0xffffffff) ||
	      (pack_iph->daddr == this->ourip.s_addr)) &&
	     (pack_udph && (pack_udph->dst == htons(DHCP_BOOTPS))));

  if (is_dhcp) {
    debug(LOG_DEBUG, "IP handler: new dhcp/bootps request being processed for "MAC_FMT"",
               MAC_ARG(pack_ethh->src));
    dhcpHandler(ctx, pack, len);
    return 0;
  }
  /*Ended for DHCP (BOOTPS) packets */

  /*After DHCP IP allocation or static set IP, the connection must have an IP address now*/
  if(conn->hisip.s_addr == 0){
    debug(LOG_DEBUG, "Connection without his IP address, dropping packet");
    return -1;
  }

  /*Jerome Changes procedure. Ignore request if IP address was not allocated by this DHCP*/
  struct ippoolm_t *ipm = 0;
  if(conn->uplink){
	  /* IP Address is already known and allocated */
	  ipm = (struct ippoolm_t*) conn->uplink;
  }else{
	  /*Jerome: 判断是否本DHCP分配过地址，没有的话接受client使用的IP*/
	  if ((conn->dhcpstate == 0) && (((pack_iph->daddr != 0) &&
	           (pack_iph->daddr != 0xffffffff)))) {
		  struct in_addr addr;
		  addr.s_addr = pack_iph->saddr;

		  /*client IP是否本网段，不是DHCP能分配的地址,丢掉*/
		  if((pack_iph->saddr & gwOptions->netmask.s_addr)
				  != (gwOptions->tundevip.s_addr& gwOptions->netmask.s_addr)){

			  debug(LOG_DEBUG, "Dropping packet; Client has static IP %s not in our net", inet_ntoa(addr));
			  return 0;
		  }else{
			  /*本网段client IP记录到IP pool分配表*/
			  if (ip_allocClientIP(conn, &addr, 0, 0)) {
				 debug(LOG_DEBUG, "Dropping packet; Client's ip %s cannot be allocated", inet_ntoa(addr));
				 return 0;
			  }
	      }
	  }
	  /*End. Jerome*/
  }

  if(!ipm){
	  /*Jerome: should not reach here*/
	  debug(LOG_ERR, "IP: failed to allocated IP!");
	    return -1;
  }
  /*End. Jereome */

  if (pack_iph->saddr != conn->hisip.s_addr) {
	debug(LOG_ERR, "Received packet with spoofed source!");
    return 0;
  }

  if (pack_iph->protocol == PKT_IP_PROTO_UDP) {
      if ((pack_iph->daddr & gwOptions->netmask.s_addr) ==
          (0xffffffff & ~gwOptions->netmask.s_addr)) {
        debug(LOG_DEBUG, "Broadcasted UDP to port %d", ntohs(pack_udph->dst));
        return 0;
      }
  }

  /* DNS handling part begin*/
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->dst == htons(DHCP_DNS)) {
	  debug(LOG_DEBUG, "A DNS request!");
	  if (dnsHandler(conn, pack, &len) == WH_GOON) {
		  allowed = 1; /* Is allowed DNS */
	  }else{
		  /* Drop DNS if dhcp_dns returns 0*/
	     debug(LOG_DEBUG, "A DNS is handled in dnsHandler()!");
	     return 0;
	  }
  }
  /* End of DNS handling part*/

  if(((pack_iph->daddr & gwOptions->netmask.s_addr)
		  == (gwOptions->tundevip.s_addr& gwOptions->netmask.s_addr))
		  & (pack_iph->daddr != gwOptions->tundevip.s_addr)){
	  /*Local data transfer is routing to peer IP*/
	  gw_routeData(conn->parent, dstaddr, pack, len);
	  return 0;
  }

  conn->lasttime = mainclock_tick();
  authstate = conn->authstate;

  debug(LOG_DEBUG, "DHCP received packet with authentic state %d", authstate);
  switch (authstate) {
    case AUTH_CLIENT:
      /* Packet go through with this state of the client*/
      break;

    case NEW_CLIENT:
        /* Http request will be DNAT, others are dropped, unless it is allowed DNS or LAN packets*/
      if (!allowed){
    	  if(checkHttpDnat(conn, pack, len, 1, &do_checksum)){
    	       debug(LOG_DEBUG, "dropping packet; not nat'ed");
    	       return 0;
    	  }
      }
      break;

    case DROP_CLIENT:
      debug(LOG_DEBUG, "dropping packet; auth-drop");
      return 0;

    default:
      debug(LOG_DEBUG, "dropping packet; unhandled auth state %d",   authstate);
      return 0;
  }

  if (do_checksum)
    chksum(pack_iph);

  debug(LOG_DEBUG, "cb_dhcp_data_ind. Packet is sending via Tun. DHCP authstate: %d",
    conn->authstate);

  srcaddr.s_addr = pack_iph->saddr;
  dstaddr.s_addr = pack_iph->daddr;
  debug(LOG_DEBUG, "DHCP sending packet from IP %s", inet_ntoa(srcaddr));
  debug(LOG_DEBUG, "DHCP sending packet to IP %s of length %d", inet_ntoa(dstaddr), len);

  gw_sendUlData(conn, pack, len);
  return 0;
}


/**dhcp_newconn()
 * Allocates a new connection to the gateway records.
 **/
int ip_newConnection(struct gateway_t *this, struct ipconnections_t **conn,
		 uint8_t *hwaddr)
{

	s_gwOptions *gwOptions = get_gwOptions();
	debug(LOG_DEBUG, "IP newconn: "MAC_FMT"", MAC_ARG(hwaddr));

	if (addConnection(this, conn) != 0)
		return -1;

	(*conn)->inuse = 1;
	(*conn)->parent = this;
	(*conn)->mtu = this->mtu;

	/* First connection record with MAC address only */
	memcpy((*conn)->hismac, hwaddr, PKT_ETH_ALEN);

	(*conn)->lasttime = mainclock_tick();
	(*conn)->dhcpstate = 0;

	/*Insert to hash table of connections by MAC address*/
	addMacHash(this, *conn);

	/*Jerome TBD for MAC allowed list*/
	if ((gwOptions->macoklen) && !maccmp((*conn)->hismac, gwOptions)) {
		(*conn)->authstate = AUTH_CLIENT;
		debug(LOG_DEBUG, "cb_dhcp_connect. MAC "MAC_FMT" is allowed.\n", MAC_ARG((*conn)->hismac));
	}else{
		(*conn)->authstate = NEW_CLIENT;
	}

	(*conn)->dns1 = gwOptions->dns1;
	(*conn)->dns2 = gwOptions->dns2;

	return 0; /* Success */
}


/* DHCP allocate new IP address */
int ip_allocClientIP(struct ipconnections_t *conn, struct in_addr *addr,
		    uint8_t *dhcp_pkt, size_t dhcp_len) {
  s_gwOptions *gwOptions = get_gwOptions();
  struct gateway_t *pgateway = conn->parent;
  struct ippoolm_t *ipm = 0;

  debug(LOG_DEBUG, "DHCP request for MAC "MAC_FMT" with IP address %s",
		 MAC_ARG(conn->hismac),
         addr ? inet_ntoa(*addr) : "n/a");

  struct in_addr reqip;
  reqip.s_addr = addr ? addr->s_addr : 0;

  if (conn->uplink) {
    /*  IP Address is already known and allocated.*/
    ipm = (struct ippoolm_t*) conn->uplink;
  }
  else {
	/* Allocate IP address */
	if (ip_newIp(pgateway->ippool, &ipm, &reqip) == WH_FAIL) {
		debug(LOG_ERR, "Failed to allocate either static or dynamic IP address");
		return WH_FAIL;
	}

	debug(LOG_DEBUG, "Successfully allocate client MAC="MAC_FMT" assigned IP %s" ,
			MAC_ARG(conn->hismac), inet_ntoa(ipm->addr));

	conn->uplink = ipm;
  }

   if (ipm) {
	  conn->hisip.s_addr = ipm->addr.s_addr;
	  conn->hismask.s_addr = gwOptions->netmask.s_addr;
	  conn->ourip.s_addr = gwOptions->tundevip.s_addr;
	  ipm->peer = conn;
   }else{
	   return WH_FAIL;
   }

  if (conn->authstate != AUTH_CLIENT)
	  conn->authstate = NEW_CLIENT;

  return WH_SUCC;
}



/**dhcp_hashget()
 * Uses the hash tables to find a connection based on the mac address.
 **/
int getMacHash(struct gateway_t *this, struct ipconnections_t **conn,
		 uint8_t *hwaddr) {
  struct ipconnections_t *p;
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


/** dhcp_release_mac & dhcp_freeconn
.Delete a client's instance from the gateway
 **/
void ip_relConnection(struct gateway_t *this, uint8_t *hwaddr, struct ipconnections_t *conn) {
	if(!conn){
		 if (getMacHash(this, &conn, hwaddr)) {
			 return;
		 }
	}

	debug(LOG_INFO, "DHCP Released MAC="MAC_FMT" IP=%s",
	         MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));

	  if (conn->uplink) {
	    struct ippoolm_t *member = (struct ippoolm_t *) conn->uplink;

	    if (member->in_use && (!conn || !conn->is_reserved)) {
	      if (ip_freeIp(this->ippool, member)) {
	    	  debug(LOG_ERR, "Free ip(%s) from pool failed!",
	               inet_ntoa(member->addr));
	      }
	    }
	  }

	  debug(LOG_DEBUG, "DHCP freeconn: "MAC_FMT,
	           MAC_ARG(conn->hismac));

	  /* First remove from hash table */
	  delMacHash(this, conn);

	  /* Remove from link of used */
	  if ((conn->next) && (conn->prev)) {
	    conn->next->prev = conn->prev;
	    conn->prev->next = conn->next;
	  }
	  else if (conn->next) { /* && prev == 0 */
	    conn->next->prev = NULL;
	    this->firstusedconn = conn->next;
	  }
	  else if (conn->prev) { /* && next == 0 */
	    conn->prev->next = NULL;
	    this->lastusedconn = conn->prev;
	  }
	  else { /* if ((next == 0) && (prev == 0)) */
	    this->firstusedconn = NULL;
	    this->lastusedconn = NULL;
	  }

	  /* Initialise structures */
	  memset(conn, 0, sizeof(*conn));

	  /* Insert into link of free */
	  if (this->firstfreeconn) {
	    this->firstfreeconn->prev = conn;
	  }
	  else { /* First insert */
	    this->lastfreeconn = conn;
	  }

	  conn->next = this->firstfreeconn;
	  this->firstfreeconn = conn;
}


/**
 * dhcp_timeout()
 * Need to call this function at regular intervals to clean up old connections.
 **/
int ip_checkTimeout(struct gateway_t *this)
{
	  struct ipconnections_t *conn = this->firstusedconn;

	  while (conn) {
	//    debug(LOG_DEBUG, "dhcp_checkconn: %d %d", mainclock_diff(conn->lasttime), (int) this->lease);

	    struct ipconnections_t *check_conn = conn;
	    conn = conn->next;
	    if ((int)(mainclock.tv_sec - check_conn->lasttime) > (int)this->lease ) {
	      debug(LOG_DEBUG, "DHCP timeout: Removing connection");
	      ip_relConnection(this, check_conn->hismac, check_conn);
	    }
	  }

	  return 0;
}


/**
 * Call this function to send an IP packet to the peer.
 **/
int ip_tunProcess(struct ipconnections_t *conn,
		  struct pkt_buffer *pb, int ethhdr) {

  struct gateway_t *pgateway = conn->parent;

  uint8_t *packet = pkt_buffer_head(pb);
  size_t length = pkt_buffer_length(pb);


  char do_checksum = 0;
  char allowed = 0;

  int authstate = 0;

    size_t hdrlen = sizeofeth2(tag);
    if (pb->offset < hdrlen) {
      debug(LOG_ERR, "bad buffer off=%d hdr=%d",
             (int) pb->offset, (int) hdrlen);
      return 0;
    }
    pkt_buffer_grow(pb, hdrlen);
    packet = pkt_buffer_head(pb);
    length = pkt_buffer_length(pb);
	debug(LOG_DEBUG, "adding %zd to IP frame length %zd",   hdrlen, length);

  if (!pgateway) {
    debug(LOG_WARNING, "DHCP connection no longer valid");
    return 0;
  }

  authstate = conn->authstate;

  setEthhdr(packet, conn->hismac, pgateway->rawIf[0].hwaddr, PKT_ETH_PROTO_IP);

  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(packet);
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(packet);

  /* Was it a DNS response? */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->src == htons(DHCP_DNS)) {
  	debug(LOG_DEBUG, "A DNS response");
  	allowed = 1; /* Is allowed DNS */

  }

  switch (authstate) {

    case AUTH_CLIENT:
      break;

    case NEW_CLIENT:
      /* undo destination NAT */
      if (checkHttpUndoDNAT(conn, packet, &length, 1, &do_checksum) && !allowed) {
    	debug(LOG_DEBUG, "checkHttpUndoDNAT() returns true");
        return 0;
      }
      break;

    case DROP_CLIENT:
		debug(LOG_DEBUG, "drop");
    	return 0;

    default:
		debug(LOG_DEBUG, "Unhandled authstate %d",   authstate);
    	return 0;
  }

  if (do_checksum)
      chksum(pkt_iphdr(packet));

  return gw_sendDlData(pgateway, conn->rawIdx, conn->hismac, packet, length);
}

