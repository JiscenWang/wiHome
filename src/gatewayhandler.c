/*
 * gatewayhandler.c
 *
 *  Created on: 2019年6月21日
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
#include "debug.h"
#include "homeconfig.h"
#include "homenet.h"

#include "httpd.h"
#include "gatewayhandler.h"
#include "gatewaymain.h"
#include "iphandler.h"


/**
 *  dhcp_sendGARP()
 * Send Gratuitous ARP message to network
 **/
/*idx < 0 send data to all raw interfaces*/
static int gw_sendDlGARP(struct gateway_t *pgateway, int idx) {
  uint8_t packet[1500];

  struct pkt_ethhdr_t *packet_ethh;
  struct arp_packet_t *packet_arp;

  memset(packet, 0, sizeof(packet));

  packet_ethh = pkt_ethhdr(packet);
  packet_arp = pkt_arppkt(packet);

  /* ARP Payload */
  packet_arp->hrd = htons(DHCP_HTYPE_ETH);
  packet_arp->pro = htons(PKT_ETH_PROTO_IP);
  packet_arp->hln = PKT_ETH_ALEN;
  packet_arp->pln = PKT_IP_ALEN;
  packet_arp->op  = htons(DHCP_ARP_REPLY);

  /* Source address */
  memcpy(packet_arp->sha, &pgateway->rawIf[0], PKT_ETH_ALEN);
  memcpy(packet_arp->spa, &pgateway->ourip.s_addr, PKT_IP_ALEN);

  /* Target address */
  memcpy(packet_arp->tha, broadcastmac, PKT_ETH_ALEN);
  memcpy(packet_arp->tpa, &pgateway->ourip.s_addr, PKT_IP_ALEN);

  debug(LOG_DEBUG, "DHCP %s GARP with "MAC_FMT": Replying to broadcast",
		  inet_ntoa(pgateway->ourip), MAC_ARG(pgateway->rawIf[0].hwaddr));

  /* Ethernet header */
  memcpy(packet_ethh->dst, broadcastmac, PKT_ETH_ALEN);
  memcpy(packet_ethh->src, &pgateway->rawIf[0], PKT_ETH_ALEN);
  packet_ethh->prot = htons(PKT_ETH_PROTO_ARP);

  return gw_sendDlData(pgateway, idx, broadcastmac, packet, sizeofarp(packet));
}


/**
 * Open a tun device for home gateway
 **/
static int gw_openTun(struct _net_interface *netif) {
  struct ifreq ifr;
  s_gwOptions *gwOptions = get_gwOptions();

  memset(netif, 0, sizeof(*netif));

  /* Open the actual tun device */
  if ((netif->fd = open("/dev/net/tun", O_RDWR)) < 0) {
    debug(LOG_ERR, "%s: open() failed", strerror(errno));
    return -1;
  }

  ndelay_on(netif->fd);
  coe(netif->fd);

  /* Set device flags. For some weird reason this is also the method
     used to obtain the network interface name */

  memset(&ifr, 0, sizeof(ifr));

  /* Tun device, no packet info */
  ifr.ifr_flags = (IFF_TUN) | IFF_NO_PI;

  if (gwOptions->tundevname && *gwOptions->tundevname &&
		  strcmp(gwOptions->tundevname, "tap") && strcmp(gwOptions->tundevname, "tun"))
	  strlcpy(ifr.ifr_name, gwOptions->tundevname, IFNAMSIZ);

  if (ioctl(netif->fd, TUNSETIFF, (void *) &ifr) < 0) {
    debug(LOG_ERR, "%s: ioctl() failed", strerror(errno));
    close(netif->fd);
    return -1;
  }

  strlcpy(netif->devname, ifr.ifr_name, IFNAMSIZ);

  ioctl(netif->fd, TUNSETNOCSUM, 1); /* Disable checksums */

  return 0;
}


/**
Setup raw sockets from internal interfaces for home gateway
 **/
static int gw_openRawsocket(struct gateway_t *pgateway, char *interface, struct in_addr *listen) {
	s_gwOptions *gwOptions = get_gwOptions();

  if (net_init(&pgateway->rawIf[0], interface, ETH_P_ALL, 1) < 0) {
	debug(LOG_ERR, "%s: raw socket init failed", strerror(errno));
    return -1;
  }
  debug(LOG_DEBUG, "Set gateway raw socket fd %d of dev %s", pgateway->rawIf[0].fd, pgateway->rawIf.devname);

#ifdef ENABLE_MULTILAN
  {
    int idx, i;
    for (i=1, idx=1; i < MAX_MOREIF && gwOptions->internalif[i]; i++, idx++) {
      if (net_init(&pgateway->rawIf[idx], gwOptions->internalif[i],
		   0, 1) < 0) {
    	  debug(LOG_ERR, "could not setup interface %s", gwOptions->internalif[i]);
      } else {
    	  debug(LOG_DEBUG, "Configured interface %s fd=%d",
    			  gwOptions->internalif[i],
				  pgateway->rawIf[idx].fd);
      }
    }
  }
#endif


  /* Initialise various variables */
  pgateway->ourip.s_addr = listen->s_addr;
  debug(LOG_DEBUG, "Set gateway listening IP %s", inet_ntoa(pgateway->ourip));

  pgateway->uamport = gwOptions->gw_port;
  pgateway->mtu = pgateway->rawIf[0].mtu;

  /* Initialise call back functions
  dhcp->cb_data_ind = NULL;
  dhcp->cb_request = NULL;
  dhcp->cb_disconnect = NULL;
  dhcp->cb_connect = NULL;
*/
  gw_sendDlGARP(pgateway, -1);
  return 0;
}


static int gw_callNetSend(struct _net_interface *netif, unsigned char *hismac,
		  uint8_t *packet, size_t length) {

  if (hismac) {
    netif->dest.sll_halen = PKT_ETH_ALEN;
    memcpy(netif->dest.sll_addr, hismac, PKT_ETH_ALEN);
  } else {
    netif->dest.sll_halen = 0;
    memset(netif->dest.sll_addr, 0, sizeof(netif->dest.sll_addr));
  }

  return net_write_eth(netif, packet, length, &netif->dest);
}

/**
 * Call this function to send an IP packet to the peer.
 **/
int tun_sndDataProcess(ipconnections_t *conn,
		  struct pkt_buffer *pb, int ethhdr) {

  struct gateway_t *pgateway = conn->parent;

  uint8_t *packet = pkt_buffer_head(pb);
  size_t length = pkt_buffer_length(pb);


  char do_checksum = 0;
  char allowed = 0;

  int authstate = 0;

  if (ethhdr) {
    /*
     * Ethernet frame
     */
    size_t hdrplus = sizeofeth2(tag) - sizeofeth(packet);
    if (hdrplus > 0) {
      if (pb->offset < hdrplus) {
	debug(LOG_ERR, "bad buffer off=%d hdrplus=%d",
               (int) pb->offset, (int) hdrplus);
	return 0;
      }
      pkt_buffer_grow(pb, hdrplus);
      packet = pkt_buffer_head(pb);
      length = pkt_buffer_length(pb);
    }
  } else {
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
  }

  if (!pgateway) {
    debug(LOG_WARNING, "DHCP connection no longer valid");
    return 0;
  }

  authstate = conn->authstate;

  dhcp_ethhdr(conn, packet, conn->hismac, pgateway->rawIf[0].hwaddr, PKT_ETH_PROTO_IP);

  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(packet);
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(packet);

  /* Was it a DNS response? */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->src == htons(DHCP_DNS)) {
  	debug(LOG_DEBUG, "A DNS response");
  	allowed = 1; /* Is allowed DNS */

  }

  switch (authstate) {

    case DHCP_AUTH_PASS:
//      dhcp_postauthDNAT(conn, packet, length, 1, &do_checksum);
      break;

    case DHCP_AUTH_DNAT:
    case DHCP_AUTH_NONE:
      /* undo destination NAT */
      if (dhcp_undoDNAT(conn, packet, &length, 1, &do_checksum) && !allowed) {
    	debug(LOG_DEBUG, "dhcp_undoDNAT() returns true");
        return 0;
      }
      break;

    case DHCP_AUTH_DROP:
		debug(LOG_DEBUG, "drop");
    	return 0;
    default:
		debug(LOG_DEBUG, "unhandled authstate %d",   authstate);
    	return 0;
  }

  if (do_checksum)
      chksum(pkt_iphdr(packet));

  return gw_sendDlData(pgateway, 0, conn->hismac, packet, length);
}

/*
 * Called from the tun callback function, processing either an IP packet.
 */
static int tun_rcvDataProcess(struct gateway_t *pgateway, struct pkt_buffer *pb) {
  struct in_addr dst;
  struct ippoolm_t *ipm;
  ipconnections_t *connection = 0;

  struct pkt_udphdr_t *udph = 0;
  struct pkt_ipphdr_t *ipph;

  uint8_t *pack = pkt_buffer_head(pb);
  size_t len = pkt_buffer_length(pb);

  int ethhdr = (pgateway->gwTun.flags & NET_ETHHDR) != 0;
  size_t ip_len = len;

  ipph = (struct pkt_ipphdr_t *)pack;

  size_t hlen = (ipph->version_ihl & 0x0f) << 2;
  if (ntohs(ipph->tot_len) > ip_len || hlen > ip_len) {
	  debug(LOG_DEBUG, "invalid IP packet %d / %zu",
             ntohs(ipph->tot_len),
             len);
    return 0;
  }

  /*
   *  Filter out unsupported / unhandled protocols,
   *  and check some basic length sanity.
   */
  switch(ipph->protocol) {
    case PKT_IP_PROTO_GRE:
    case PKT_IP_PROTO_TCP:
    case PKT_IP_PROTO_ICMP:
    case PKT_IP_PROTO_ESP:
    case PKT_IP_PROTO_AH:
      break;
    case PKT_IP_PROTO_UDP:
      {
        /*
         * Only the first IP fragment has the UDP header.
         */
        if (iphdr_offset((struct pkt_iphdr_t*)ipph) == 0) {
          udph = (struct pkt_udphdr_t *)(((void *)ipph) + hlen);
        }
        if (udph && !iphdr_more_frag((struct pkt_iphdr_t*)ipph) && (ntohs(udph->len) > ip_len)) {

        	debug(LOG_DEBUG, "invalid UDP packet %d / %d / %zu",
                   ntohs(ipph->tot_len),
                   udph ? ntohs(udph->len) : -1, ip_len);
          return 0;
        }
      }
      break;
    default:
       	debug(LOG_DEBUG, "dropping unhandled packet: %x",   ipph->protocol);
       return 0;
  }

  dst.s_addr = ipph->daddr;

  debug(LOG_DEBUG, "TUN sending packet to : %s", inet_ntoa(dst));

  if (ippoolGetip(pgateway->ippool, &ipm, &dst)) {
    /*
     *  Jerome TBD: If within statip range, allow the packet through (?)
     */
		debug(LOG_DEBUG, "dropping packet with unknown destination: %s",   inet_ntoa(dst));
    return 0;
  }

  connection = (ipconnections_t *)ipm->peer;

  if (connection == NULL) {
    debug(LOG_ERR, "No dnlink protocol defined for %s", inet_ntoa(dst));
    return 0;
  }

  /*Jerome: J-Module modified. Not judged by client's authstate, but by DHCP conn's

  switch (conn->authstate) {
    case DHCP_AUTH_NONE:
    case DHCP_AUTH_DROP:
    case DHCP_AUTH_DNAT:
		debug(LOG_DEBUG, "Dropping...");
      break;

    case DHCP_AUTH_PASS:
      tun_sndDataProcess((struct dhcp_conn_t *)client->dnlink, pb, ethhdr);
      break;

    default:
      debug(LOG_ERR, "Unknown downlink protocol: %d", conn->authstate);
      break;
  }
End Jerome*/
  tun_sndDataProcess(connection, pb, ethhdr);
  return 0;

}


/*Callback entry of select() for tun-gateway when receiving packets */
static int cb_tun_rcvPackets(struct gateway_t *pgateway, struct pkt_buffer *pb) {

  struct pkt_iphdr_t *iph;
  int ethsize = 0;

  size_t length = pkt_buffer_length(pb);
  uint8_t *packet = pkt_buffer_head(pb);

  s_gwOptions *gwOptions = get_gwOptions();

  struct in_addr addr;


  if (length < PKT_IP_HLEN){
		debug(LOG_DEBUG, "tun_decaps invalid length < PKT_IP_HLEN");
	    return -1;
  }

  iph = (struct pkt_iphdr_t *)packet;

  addr.s_addr = iph->saddr;
  debug(LOG_DEBUG, "tun_decaps gets packet(len=%zd) from IP %s", length, inet_ntoa(addr));
  addr.s_addr = iph->daddr;
  debug(LOG_DEBUG, "tun_decaps gets packet sending to IP %s", inet_ntoa(addr));

    if (iph->version_ihl != PKT_IP_VER_HLEN) {
      debug(LOG_DEBUG, "dropping non-IPv4");
      return -1;
    }

    if ((int)ntohs(iph->tot_len) + ethsize > length) {
      debug(LOG_DEBUG, "dropping ip packet; ip-len=%d + eth-hdr=%d > read-len=%d",
               (int)ntohs(iph->tot_len),
               ethsize, (int)length);
      return -1;
    }


  return tun_rcvDataProcess(pgateway, pb);
}

static int cb_raw_rcvPackets(void *pctx, struct pkt_buffer *pb) {
  struct rawif_in *ctx = (struct rawif_in *)pctx;
  uint16_t prot = 0;

  uint8_t *packet = pkt_buffer_head(pb);
  size_t length = pkt_buffer_length(pb);

  int min_length = sizeof(struct pkt_ethhdr_t);

  if (length < min_length) {
    debug(LOG_ERR, "Gateway from raw IF: bad packet length %zu", length);
    return 0;
  }

  struct pkt_ethhdr_t *ethh = pkt_ethhdr(packet);
  prot = ntohs(ethh->prot);

  debug(LOG_DEBUG, "Gateway from raw: src="MAC_FMT" "
           "dst="MAC_FMT" prot=%.4x %d len=%zd",
           MAC_ARG(ethh->src),
           MAC_ARG(ethh->dst),
           prot, (int)prot, length);

  if (prot < 1518) {
	debug(LOG_ERR, "Gateway from raw: unhandled prot %d", prot);
    return 0;
  }

  switch (prot) {
    case PKT_ETH_PROTO_ARP:
    	debug(LOG_DEBUG, "Gateway from raw receives ARP packet of length %d", length);
        return ip_rcvArp(ctx, packet, length);
      break;

    case PKT_ETH_PROTO_IP:
    	debug(LOG_DEBUG, "Gateway from raw receives IP packet of length %d", length);
        return ip_rcvIp(ctx, packet, length);
      break;

    case PKT_ETH_PROTO_PPP:
    case PKT_ETH_PROTO_IPX:
    default:
        debug(LOG_DEBUG, "Gateway from raw Layer2 PROT: 0x%.4x dropped", prot);
      break;
  }

  return 0;
}

/*
 * Entry of select() for gateway when receiving packets from tun device
 * */
int gw_tun_rcvPackets(struct gateway_t *this, int idx) {

  ssize_t length;

  length = net_read_dispatch(&this->gwTun, cb_tun_rcvPackets, this);

  if (length < 0)
  {
	  debug(LOG_ERR, "Gateway receives unhandled packet of length %d from tun", length);
	  return -1;
  }

  return length;
}


/*
 * Entry of select() for gateway when receiving packets from raw interfaces
 * */
int gw_raw_rcvPackets(struct gateway_t *this, int idx) {
  ssize_t length = -1;
  net_interface *iface = 0;
  struct rawif_in if_In;

#ifdef ENABLE_MULTILAN
  iface = &this->rawIf[idx];
#else
  iface = &this->rawIf[0];
#endif

  if_In.parent = this;
  if_In.idx = idx;

  if ((length = net_read_dispatch_eth(iface, cb_raw_rcvPackets, &if_In)) < 0)
  {
	  debug(LOG_ERR, "Gateway receives unhandled packet of length %d from raw interface %d", length, idx);
	  return -1;
  }

  return length;
}

int initGateway(struct gateway_t **ppgateway) {
  struct gateway_t *home_gateway;
  s_gwOptions *gwOptions = get_gwOptions();

  if (!(home_gateway = *ppgateway = calloc(1, sizeof(struct gateway_t)))) {
    debug(LOG_ERR, "%s: calloc() failed", strerror(errno));
    return -1;
  }

  gw_openTun(&home_gateway->gwTun);
  net_set_address(&homeGateway->gwTun, &gwOptions->tundevip, &gwOptions->tundevip, &gwOptions->netmask);
  debug(LOG_DEBUG, "Set gateway IP address %s", inet_ntoa(gwOptions->tundevip));

  gw_openRawsocket(home_gateway, gwOptions->internalif[0], gwOptions->tundevip);

  return 0;
}

/*dhcp_send()*/
int gw_sendDlData(struct gateway_t *this, int idx,
              unsigned char *hismac, uint8_t *packet, size_t length) {
  net_interface *iface = 0;

//    pkt_shape_tcpwin(pkt_iphdr(packet), _options.tcpwin);
//    pkt_shape_tcpmss(packet, &length);

#ifdef ENABLE_MULTILAN
  if (idx < 0) {
    int i, ret = -1;
    for (i=0; i < MAX_RAWIF && this->rawIf[i].fd; i++)
      ret = gw_callNetSend(&this->rawIf[i], hismac, packet, length);
    return ret;
  }
  iface = &this->rawIf[idx];
#else
  iface = &this->rawIf[0];
#endif

  return gw_callNetSend(iface, hismac, packet, length);
}

