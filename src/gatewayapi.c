/*
 * gatewayapi.c
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
#include "gatewayapi.h"
#include "gatewaymain.h"
#include "ipprocessing.h"


/**
 tun_write
 **/
static int gw_callTunWrite(struct _net_interface *tun, uint8_t *pack, size_t len) {
	  return safe_write(tun->fd, pack, len);
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
static int gw_openRawsocket(struct gateway_t *pgateway, char *interface) {
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

  return tun_rcvIp(pgateway, pb);
}

/*call back frome gw_raw_rcvPackets()*/
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
        return raw_rcvArp(ctx, packet, length);
      break;

    case PKT_ETH_PROTO_IP:
    	debug(LOG_DEBUG, "Gateway from raw receives IP packet of length %d", length);
        return raw_rcvIp(ctx, packet, length);
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

  if(gw_openRawsocket(home_gateway, gwOptions->internalif[0]))
	  return -1;

  /* Initialise various variables */
  home_gateway->ourip.s_addr = gwOptions->tundevip;
  debug(LOG_DEBUG, "Set gateway listening IP %s", inet_ntoa(gwOptions->tundevip));

  home_gateway->uamport = gwOptions->gw_port;
  home_gateway->mtu = home_gateway->rawIf[0].mtu;
  home_gateway->netmask = gwOptions->netmask;

  /* Initialise call back functions
  dhcp->cb_data_ind = NULL;
*/
  sendDlGARP(home_gateway, -1);
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


/* cb_dhcp_data_ind */
int gw_sendUlData(struct ipconnections_t *conn, uint8_t *pack, size_t len) {
  int result;
  struct gateway_t *pgateway = conn->parent;

  debug(LOG_DEBUG, "Gateway sending Upstream packet is sending via Tun. Connection authstate: %d",
    conn->authstate);

  switch (conn->authstate) {
    case DHCP_AUTH_DROP:
      debug(LOG_DEBUG, "Upstream packet is dropped for non-authentication");
      return -1;

    case DHCP_AUTH_PASS:
    case DHCP_AUTH_NONE:
    case DHCP_AUTH_DNAT:

      break;

    default:
      debug(LOG_ERR, "Unknown auth state");
      return -1;
  }

  size_t ethlen = sizeofeth(pack);
  pack += ethlen;
  len  -= ethlen;

  debug(LOG_DEBUG, "Gateway tun (%s) fd=%d sending packet len=%zd", pgateway->gwTun.devname, pgateway->gwTun.fd, len);

  result = gw_callTunWrite(&pgateway->gwTun, pack, len);
  if (result < 0)
	  debug(LOG_ERR, "%s:Gateway tun write (%zu) = %d", strerror(errno), len, result);
  return result;
}


