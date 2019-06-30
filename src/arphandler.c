/*
 * arphandler.c
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

/**
 * Send ARP message to peer
 **/
static
int ip_sendARP(struct gateway_t *this, uint8_t *pack, size_t len) {
  uint8_t packet[1500];

  struct in_addr reqaddr;

  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

  struct pkt_ethhdr_t *packet_ethh;
  struct arp_packet_t *packet_arp;

  /* Get local copy */
  memcpy(&reqaddr.s_addr, pack_arp->spa, PKT_IP_ALEN);

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
  memcpy(packet_arp->spa, &this->ourip, PKT_IP_ALEN);
  memcpy(packet_arp->sha, this->rawIf[0], PKT_ETH_ALEN);

  /* Target address */
  memcpy(packet_arp->tha, pack_arp->sha, PKT_ETH_ALEN);
  memcpy(packet_arp->tpa, &reqaddr.s_addr, PKT_IP_ALEN);

  debug(LOG_DEBUG, "ARP: Replying to %s / "MAC_FMT,
           inet_ntoa(reqaddr),
           MAC_ARG(pack_arp->sha));

  /* Ethernet header */
  memcpy(packet_ethh->dst, pack_arp->sha, PKT_ETH_ALEN);
  memcpy(packet_ethh->src, this->rawIf[0], PKT_ETH_ALEN);

  return gw_sendDlData(this, 0, pack_arp->sha,
		   packet, sizeofarp(packet));
}



/*dhcp_receive_arp*/
int raw_rcvArp(struct rawif_in *ctx, uint8_t *pack, size_t len) {

  struct in_addr reqaddr;
  struct in_addr taraddr;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

	s_gwOptions *gwOptions = get_gwOptions();
	struct gateway_t *this = ctx->parent;
  struct ipconnections_t *conn = NULL;

  /* get sender IP address */
  memcpy(&reqaddr.s_addr, pack_arp->spa, PKT_IP_ALEN);

  /* get target IP address */
  memcpy(&taraddr.s_addr, pack_arp->tpa, PKT_IP_ALEN);

  debug(LOG_DEBUG, "ARP: "MAC_FMT" asking about target IP: %s",
           MAC_ARG(pack_arp->sha),
           inet_ntoa(taraddr));

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

  /* Check to see if we know MAC address. */
  if (ip_getHash(this, &conn, pack_arp->sha)) {
    debug(LOG_DEBUG, "ARP: Address not found with IP: %s", inet_ntoa(reqaddr));

  }else{
	  if (!conn->hisip.s_addr) {
	    debug(LOG_DEBUG, "ARP: request did not come from known client asking for target: %s",
	    		inet_ntoa(taraddr));
	    return 0;
	  }

	  /* Is ARP request for clients own address: Ignore */
	  if (!memcmp(&conn->hisip.s_addr, &taraddr.s_addr, 4)) {
	    debug(LOG_DEBUG, "ARP: hisip equals target ip: %s",
	             inet_ntoa(conn->hisip));
	    return 0;
	  }

	  conn->lasttime = mainclock_tick();
  }

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

  if (memcmp(&gwOptions->tundevip.s_addr, &taraddr.s_addr, 4)) {

	  debug(LOG_DEBUG, "ARP: Did not ask for gateway address: %s, but ask for target: %s",
    		 inet_ntoa(gwOptions->tundevip), inet_ntoa(taraddr));
     return 0;
  }

  ip_sendARP(this, pack, len);
  return 0;
}


/**
 *  dhcp_sendGARP()
 * Send Gratuitous ARP message to network
 **/
/*idx < 0 send data to all raw interfaces*/
int sendDlGARP(struct gateway_t *pgateway, int idx) {
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
