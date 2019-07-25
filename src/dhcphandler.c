/*
 * dhcphandler.c
 *
 *  Created on: 2019年7月1日
 *      Author: jerome
 */


#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "gatewayapi.h"
#include "debug.h"
#include "homenet.h"
#include "ipprocessing.h"
#include "functions.h"
#include "homenet.h"
#include "homeconfig.h"
/**
 * dhcp_create_pkt()
 * Create a new typed DHCP packet
 */
static int createDhcpPkt(uint8_t type, uint8_t *pack, uint8_t *req,
		struct ipconnections_t *conn) {

  struct gateway_t *this = conn->parent;

  struct pkt_ethhdr_t *req_ethh = pkt_ethhdr(req);
  struct dhcp_packet_t *req_dhcp = pkt_dhcppkt(req);

  struct pkt_ethhdr_t *pack_ethh;
  struct pkt_iphdr_t *pack_iph;
  struct pkt_udphdr_t *pack_udph;
  struct dhcp_packet_t *pack_dhcp;

  int pos = 0;

  int is_req_dhcp = (req_dhcp->options[0] == 0x63 &&
		     req_dhcp->options[1] == 0x82 &&
		     req_dhcp->options[2] == 0x53 &&
		     req_dhcp->options[3] == 0x63);

  copy_ethproto(req, pack);

  pack_ethh = pkt_ethhdr(pack);
  pack_iph  = pkt_iphdr(pack);

  /* IP header */
  pack_iph->version_ihl = PKT_IP_VER_HLEN;
  pack_iph->tos = 0;
  pack_iph->tot_len = 0; /* Calculate at end of packet */
  pack_iph->id = 0;
  pack_iph->opt_off_high = 0;
  pack_iph->off_low = 0;
  pack_iph->ttl = 0x10;
  pack_iph->protocol = 0x11;
  pack_iph->check = 0; /* Calculate at end of packet */

  pack_udph = pkt_udphdr(pack);
  pack_dhcp = pkt_dhcppkt(pack);

  pack_dhcp->op     = DHCP_BOOTREPLY;
  pack_dhcp->htype  = DHCP_HTYPE_ETH;
  pack_dhcp->hlen   = PKT_ETH_ALEN;

  if (is_req_dhcp) {
    pack_dhcp->xid      = req_dhcp->xid;
    pack_dhcp->flags[0] = req_dhcp->flags[0];
    pack_dhcp->flags[1] = req_dhcp->flags[1];
    pack_dhcp->giaddr   = req_dhcp->giaddr;

    memcpy(&pack_dhcp->chaddr, &req_dhcp->chaddr, DHCP_CHADDR_LEN);
    debug(LOG_DEBUG, "dhcp server: %s", pack_dhcp->sname);
  }

  switch(type) {
    case DHCPOFFER:
    case DHCPFORCERENEW:
      pack_dhcp->yiaddr = conn->hisip.s_addr;
      break;
    case DHCPACK:
      pack_dhcp->xid    = req_dhcp->xid;
      pack_dhcp->yiaddr = conn->hisip.s_addr;
      break;
    case DHCPNAK:
      break;
  }

  /* Ethernet Header */
  memcpy(pack_ethh->dst, req_ethh->src, PKT_ETH_ALEN);
  memcpy(pack_ethh->src, this->rawIf[0].hwaddr, PKT_ETH_ALEN);

  /* UDP and IP Headers */
  pack_udph->src = htons(DHCP_BOOTPS);
  pack_iph->saddr = conn->ourip.s_addr;

  /** http://www.faqs.org/rfcs/rfc1542.html
      Now see: http://www.faqs.org/rfcs/rfc2131.html

      BOOTREQUEST fields     BOOTREPLY values for UDP, IP, link-layer
      +-----------------------+-----------------------------------------+
      | 'ciaddr'  'giaddr'  B | UDP dest     IP destination   link dest |
      +-----------------------+-----------------------------------------+
      | non-zero     X      X | BOOTPC (68)  'ciaddr'         normal    |
      | 0.0.0.0   non-zero  X | BOOTPS (67)  'giaddr'         normal    |
      | 0.0.0.0   0.0.0.0   0 | BOOTPC (68)  'yiaddr'         'chaddr'  |
      | 0.0.0.0   0.0.0.0   1 | BOOTPC (68)  255.255.255.255  broadcast |
      +-----------------------+-----------------------------------------+

      B = BROADCAST flag

      X = Don't care

      normal = determine from the given IP destination using normal
      IP routing mechanisms and/or ARP as for any other
      normal datagram

      If the 'giaddr' field in a DHCP message from a client is non-zero,
      the server sends any return messages to the 'DHCP server' port on the
      BOOTP relay agent whose address appears in 'giaddr'.

      If the 'giaddr' field is zero and the 'ciaddr' field is nonzero, then the
      server unicasts DHCPOFFER and DHCPACK messages to the address in
      'ciaddr'.

      If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is set,
      then the server broadcasts DHCPOFFER and DHCPACK messages to
      0xffffffff.

      If the broadcast bit is not set and 'giaddr' is zero and 'ciaddr' is
      zero, then the server unicasts DHCPOFFER and DHCPACK messages to the
      client's hardware address and 'yiaddr' address.

      In all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
      messages to 0xffffffff.

  **/

  if (is_req_dhcp) {
    if (req_dhcp->ciaddr) {
      pack_iph->daddr = req_dhcp->ciaddr;
      pack_udph->dst = htons(DHCP_BOOTPC);
    } else if (req_dhcp->giaddr) {
      pack_iph->daddr = req_dhcp->giaddr;
      pack_udph->dst = htons(DHCP_BOOTPS);
    } else if (type == DHCPNAK ||           /* Nak always to broadcast */
	       (req_dhcp->flags[0] & 0x80) ){  /* Broadcast bit set */
      pack_iph->daddr = ~0;
      pack_udph->dst = htons(DHCP_BOOTPC);
      pack_dhcp->flags[0] = 0x80;
      if (req_dhcp->flags[0] & 0x80)
	memcpy(pack_ethh->dst, broadcastmac, PKT_ETH_ALEN);
    } else {
      pack_iph->daddr = pack_dhcp->yiaddr;
      pack_udph->dst = htons(DHCP_BOOTPC);
    }
  } else {
    struct pkt_iphdr_t *iph = pkt_iphdr(req);
    pack_iph->daddr = iph->saddr;
    pack_udph->dst = htons(DHCP_BOOTPC);
  }

  /* Magic cookie */
  pack_dhcp->options[pos++] = 0x63;
  pack_dhcp->options[pos++] = 0x82;
  pack_dhcp->options[pos++] = 0x53;
  pack_dhcp->options[pos++] = 0x63;

  pack_dhcp->options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
  pack_dhcp->options[pos++] = 1;
  pack_dhcp->options[pos++] = type;

  return pos;
}


static int writeDhcpAcceptOpt(struct ipconnections_t *conn, uint8_t *o, int pos) {
  struct gateway_t *this = conn->parent;

  o[pos++] = DHCP_OPTION_SUBNET_MASK;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->hismask.s_addr, 4);
  pos += 4;

  o[pos++] = DHCP_OPTION_ROUTER_OPTION;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  if (conn->dns1.s_addr && conn->dns2.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 8;
    memcpy(&o[pos], &conn->dns1.s_addr, 4);
    pos += 4;
    memcpy(&o[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }
  else if (conn->dns1.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 4;
    memcpy(&o[pos], &conn->dns1.s_addr, 4);
    pos += 4;
  }
  else if (conn->dns2.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 4;
    memcpy(&o[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }


  o[pos++] = DHCP_OPTION_LEASE_TIME;
  o[pos++] = 4;
  o[pos++] = (this->lease >> 24) & 0xFF;
  o[pos++] = (this->lease >> 16) & 0xFF;
  o[pos++] = (this->lease >>  8) & 0xFF;
  o[pos++] = (this->lease >>  0) & 0xFF;

  o[pos++] = DHCP_OPTION_INTERFACE_MTU;
  o[pos++] = 2;
  o[pos++] = (conn->mtu >> 8) & 0xFF;
  o[pos++] = (conn->mtu >> 0) & 0xFF;

  o[pos++] = DHCP_OPTION_SERVER_ID;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  o[pos++] = DHCP_OPTION_END;

  return pos;
}

/**
 * dhcp_gettag()
 * Search a DHCP packet for a particular tag.
 * Returns -1 if not found.
 **/
static int getDhcpTag(struct dhcp_packet_t *pack, size_t length, struct dhcp_tag_t **tag, uint8_t tagtype)
{
  struct dhcp_tag_t *t;
  size_t offset = DHCP_MIN_LEN + DHCP_OPTION_MAGIC_LEN;

  while ((offset + 2) < length) {
    t = (struct dhcp_tag_t *)(((uint8_t *)pack) + offset);
    if (t->t == tagtype) {
      if ((offset + 2 + (size_t)(t->l)) > length)
	return -1; /* Tag length too long */
      *tag = t;
      return 0;
    }
    offset += 2 + t->l;
  }

  return -1; /* Not found  */
}


/**
 * dhcp_sendNAK()
 * Send of a DHCP negative acknowledge message to a peer.
 * NAK messages are always sent to broadcast IP address (
 * except when using a DHCP relay server)
 **/
static int sendDhcpNak(struct ipconnections_t *conn, uint8_t *pack, size_t len) {

  struct gateway_t *this = conn->parent;
  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = createDhcpPkt(DHCPNAK, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  packet_dhcp->options[pos++] = DHCP_OPTION_SERVER_ID;
  packet_dhcp->options[pos++] = 4;
  memcpy(&packet_dhcp->options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  packet_dhcp->options[pos++] = DHCP_OPTION_END;

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);

  chksum(packet_iph);
  uint16_t length = udp_len + sizeofip(packet);

  conn->dhcpstate = 0;
  return gw_sendDlData(this, conn->rawIdx, conn->hismac, packet, length);
}


/**
 * dhcp_sendACK()
 * Send of a DHCP acknowledge message to a peer.
 **/
static int sendDhcpAck(struct ipconnections_t *conn, uint8_t *pack, size_t len) {

  struct gateway_t *this = conn->parent;

  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = createDhcpPkt(DHCPACK, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  pos = writeDhcpAcceptOpt(conn, packet_dhcp->options, pos);

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
  chksum(packet_iph);

  uint16_t length = udp_len + sizeofip(packet);

  return gw_sendDlData(this, conn->rawIdx, conn->hismac, packet, length);
}

/**
 * dhcp_sendOFFER()
 * Send of a DHCP offer message to a peer.
 **/
static int sendDhcpOffer(struct ipconnections_t *conn, uint8_t *pack, size_t len) {

  struct gateway_t *this = conn->parent;

  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = createDhcpPkt(DHCPOFFER, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  pos = writeDhcpAcceptOpt(conn, packet_dhcp->options, pos);

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
  chksum(packet_iph);

  uint16_t length = udp_len + sizeofip(packet);

  if(gw_sendDlData(this, conn->rawIdx, conn->hismac, packet, length) < 0){
	  return WH_FAIL;
  }else{
	  return WH_SUCC;
  }

}


int informDHCP(struct ipconnections_t *conn, uint8_t *pack, size_t len){
	struct dhcp_tag_t *requested_ip = 0;
	struct dhcp_tag_t *host_name = 0;
	struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
	struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);
	struct in_addr addr;
	s_gwOptions *gwOptions = get_gwOptions();

	/*Get client's requested IP address and try to allocate it to the client*/
	addr.s_addr = pack_dhcp->ciaddr;
	if (!getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
			 &requested_ip, DHCP_OPTION_REQUESTED_IP)){
		memcpy(&addr.s_addr, requested_ip->v, 4);
	}
	debug(LOG_DEBUG, "Client inform with IP address %s", inet_ntoa(addr));

	/*But if requested IP address is wrong, NACK it*/
	if (addr.s_addr && ((addr.s_addr & gwOptions->netmask.s_addr)
			!= (gwOptions->tundevip.s_addr& gwOptions->netmask.s_addr))) {
		debug(LOG_DEBUG, "Client inform with IP with wrong net");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}

	/* Request an IP address */
	if (ip_allocClientIP(conn, &addr, pack, len) == WH_FAIL){
	    debug(LOG_DEBUG, "Failed to allocate an IP to client, sending NAK");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}
	if (!conn->hisip.s_addr){
	    debug(LOG_DEBUG, "Failed to allocate an IP to client, sending NAK");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}

	/*记录client的名称*/
	if (!getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
			 &host_name, DHCP_OPTION_HOSTNAME)){
		memcpy(conn->hostname, host_name->v, DHCP_MAX_LENGTH_HOSTNAME);
	}

	if(sendDhcpAck(conn, pack, len)){
		debug(LOG_ERR, "Fail to send ACK to "MAC_FMT" with IP %s",
	    			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
	   	return WH_STOP;
	}

	/* Give client's request the allocated IP address */
    conn->dhcpstate = 2;
	debug(LOG_DEBUG, "Sending ACK to "MAC_FMT" with IP %s",
      			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
   	return WH_GOON;
}

int requestDHCP(struct ipconnections_t *conn, uint8_t *pack, size_t len){
	struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
	struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);

	struct dhcp_tag_t *requested_ip = 0;
	struct in_addr addr;

	/*Client's requested IP address should exist*/
	addr.s_addr = pack_dhcp->ciaddr;
	if (!getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
			 &requested_ip, DHCP_OPTION_REQUESTED_IP)){
		memcpy(&addr.s_addr, requested_ip->v, 4);
	}
	if(addr.s_addr == INADDR_ANY){
		debug(LOG_DEBUG, "Client requests but without address %s", inet_ntoa(addr));
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}
	debug(LOG_DEBUG, "Client requests its address %s", inet_ntoa(addr));

	if (!conn->hisip.s_addr){
	    debug(LOG_ERR, "Client's IP not set! Sending NAK to client");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}
    if (memcmp(&conn->hisip.s_addr, &addr.s_addr, 4)){
	    debug(LOG_DEBUG, "Client request not allocated IP! Sending NAK to client");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
    }

	if(sendDhcpAck(conn, pack, len)){
		debug(LOG_ERR, "Fail to send ACK to "MAC_FMT" with IP %s",
	    			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
	   	return WH_STOP;
	}

	/* Give client's request the allocated IP address */
    conn->dhcpstate = 2;
	debug(LOG_DEBUG, "Sending ACK to "MAC_FMT" with IP %s",
      			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
   	return WH_GOON;
}

int discoverDHCP(struct ipconnections_t *conn, uint8_t *pack, size_t len){
	struct dhcp_tag_t *requested_ip = 0;
	struct dhcp_tag_t *host_name = 0;
	struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
	struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);
	struct in_addr addr;
	s_gwOptions *gwOptions = get_gwOptions();

	/*Get client's requested IP address and try to allocate it to the client*/
	addr.s_addr = pack_dhcp->ciaddr;
	if (!getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
			 &requested_ip, DHCP_OPTION_REQUESTED_IP)){
		memcpy(&addr.s_addr, requested_ip->v, 4);
	}
	debug(LOG_DEBUG, "Client discover IP with a requested address %s", inet_ntoa(addr));

	/*But if requested IP address is wrong, renew it*/
	if (addr.s_addr && ((addr.s_addr & gwOptions->netmask.s_addr)
			!= (gwOptions->tundevip.s_addr& gwOptions->netmask.s_addr))) {
		debug(LOG_DEBUG, "Request an IP address with required IP with wrong net, re-assign an new IP");
		addr.s_addr = INADDR_ANY;
	}

	/* Request an IP address */
	if (ip_allocClientIP(conn, &addr, pack, len) == WH_FAIL){
	    debug(LOG_DEBUG, "Failed to allocate an IP to client, sending NAK");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}
	if (!conn->hisip.s_addr){
	    debug(LOG_DEBUG, "Failed to allocate an IP to client, sending NAK");
	    sendDhcpNak(conn, pack, len);
	    return WH_STOP;
	}
	/*记录client的名称*/
	if (!getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
			 &host_name, DHCP_OPTION_HOSTNAME)){
		memcpy(conn->hostname, host_name->v, DHCP_MAX_LENGTH_HOSTNAME);
	}

	if(sendDhcpOffer(conn, pack, len) == WH_FAIL){
		debug(LOG_ERR, "Fail to send offer to "MAC_FMT" with IP %s",
	    			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
	   	return WH_STOP;
	}

	debug(LOG_DEBUG, "Sending offer to "MAC_FMT" with IP %s",
    			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
    conn->dhcpstate = 1;
   	return WH_GOON;
}

/**
 *  dhcp_getreq()
 *  Process a received DHCP request and sends a response.
 **/
int dhcpHandler(struct rawif_in *ctx, uint8_t *pack, size_t len) {
  struct gateway_t *this = ctx->parent;
  struct ipconnections_t *conn = NULL;

  uint8_t mac[PKT_ETH_ALEN];
  struct dhcp_tag_t *message_type = 0;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
  struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);

  debug(LOG_DEBUG, "DHCP function get packet from "MAC_FMT, MAC_ARG(pack_ethh->src));

  if (pack_udph->dst != htons(DHCP_BOOTPS))
    return 0; /* Not a DHCP packet */

  if (getDhcpTag(pack_dhcp, ntohs(pack_udph->len)-PKT_UDP_HLEN,
		  &message_type, DHCP_OPTION_MESSAGE_TYPE)) {
	  debug(LOG_ERR, "Failed to get DHCP tag of message type");
    return -1;
  }

  /* Wrong length of message type */
  if (message_type->l != 1)
    return -1;

  /* Check if the request message includes another MAC address */
  if (memcmp(pack_dhcp->chaddr, nonmac, PKT_ETH_ALEN))
    memcpy(mac, pack_dhcp->chaddr, PKT_ETH_ALEN);
  else
    memcpy(mac, pack_ethh->src, PKT_ETH_ALEN);
  if (getMacHash(this, &conn, mac)) {
	  /*Should not come here, all new connections will be added in raw_rcvIp()*/
	debug(LOG_DEBUG, "IP: MAC address "MAC_FMT" not found, add new connection",
    		MAC_ARG(pack_ethh->src));
    if (ip_newConnection(this, &conn, mac)){
  	  debug(LOG_DEBUG, "dropping packet; fail of adding connections");
      return -1;
    }
  }else{
	  debug(LOG_DEBUG, "IP handler: MAC Address "MAC_FMT" found with IP %s",
		    		MAC_ARG(pack_ethh->src), inet_ntoa(conn->hisip));
	  if (conn == NULL){
		debug(LOG_ERR,"Connection not allocated well");
		return -1;
	  }
  }

  switch(message_type->v[0]) {
    case DHCPDECLINE:
        debug(LOG_DEBUG,"DHCP-Decline");
        ip_relConnection(this, mac, conn);
        /* No Reply to client is sent */
        return 0;

    case DHCPRELEASE:
        debug(LOG_DEBUG,"DHCP-Release");
        ip_relConnection(this, mac, conn);
        /* No Reply to client is sent */
        return 0;

    case DHCPDISCOVER:
        debug(LOG_DEBUG,"DHCP-DISCOVER");
        if(discoverDHCP(conn, pack, len) == WH_STOP){
            return WH_STOP;
        }
        break;

    case DHCPREQUEST:
        debug(LOG_DEBUG,"DHCP-REQUEST");
        if(requestDHCP(conn, pack, len) == WH_STOP){
            return WH_STOP;
        }
        break;

    case DHCPINFORM:
        debug(LOG_DEBUG,"DHCP-INFORM");
        if(informDHCP(conn, pack, len) == WH_STOP){
            return WH_STOP;
        }
        break;

    default:
    	debug(LOG_INFO, "Unsupported DHCP message ignored");
    	return 0; /* Unsupported message type */
  }


  /**Jerome TBD: how to Relay the DHCP request **/
  /*
  if (this->relayfd > 0) {
    return dhcp_relay(this, pack, len);
  }*/

  conn->lasttime = mainclock_tick();
  return 0;
}
