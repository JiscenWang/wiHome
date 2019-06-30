/*
 * dnshandler.c
 *
 *  Created on: 2019年7月1日
 *      Author: jerome
 */



static ssize_t
fullDnsName(char *data, size_t dlen,      /* buffer to store name */
	     uint8_t *res, size_t reslen,  /* current resource */
	     uint8_t *opkt, size_t olen,   /* original packet */
	     int lvl) {
  int ret = 0;
  char *d = data;
  unsigned char l;

  if (lvl >= 15) return -1;

  debug(LOG_DEBUG, "dlen=%zd reslen=%zd olen=%zd lvl=%d", dlen, reslen, olen, lvl);

  /* only capture the first name in query */
  if (d && d[0]) d = 0;

  while (reslen-- > 0 && ++ret && (l = *res++) != 0) {

    if (l >= dlen || l >= olen) {
      debug(LOG_DEBUG, "bad value %d/%zu/%zu", l, dlen, olen);
      return -1;
    }

    debug(LOG_DEBUG, "part[%.*s] reslen=%zd l=%d dlen=%zd", l, res, reslen, l, dlen);

    if (d) {
      memcpy(d, res, l);
      d += l;
      dlen -= l;
    }
    res += l;
    reslen -= l;
    ret += l;

    if (d) {
      *d = '.';
      d += 1;
      dlen -= 1;
    }
  }

  if (lvl == 0 && d) {
    int len = strlen((char *)data);
    if (len && len == (d - data) && data[len-1] == '.')
      data[len-1]=0;
  }

  return ret;
}

static int copyDnsRsp(struct ipconnections_t *conn,
	     uint8_t **pktp, size_t *left,
	     uint8_t *opkt,  size_t olen,
	     uint8_t *question, size_t qsize) {
  uint8_t *p_pkt = *pktp;
  size_t len = *left;

  ssize_t namelen = 0;

  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlen;
  uint8_t *pkt_ttl=0;
  uint32_t ul;
  uint16_t us;

  debug(LOG_DEBUG, "left=%zd olen=%zd qsize=%zd", *left, olen, qsize);

  namelen = fullDnsName((char*)question, qsize-1,
			 p_pkt, len, opkt, olen, 0);

  if (namelen < 0 || namelen > len){
	debug(LOG_DEBUG, "Failed parsing DNS packet");
	return -1;
  }
  debug(LOG_DEBUG, "DNS: %s", question);

    return 0;
}

/* *   dhcp_nakDNS() - */
static
int sendDnsNak(struct ipconnections_t *conn, uint8_t *pack, size_t len) {
	struct gateway_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t *iph = pkt_iphdr(pack);
  struct pkt_udphdr_t *udph = pkt_udphdr(pack);

  uint8_t answer[len];

  struct pkt_ethhdr_t *answer_ethh;
  struct pkt_iphdr_t *answer_iph;
  struct pkt_udphdr_t *answer_udph;
  struct dns_packet_t *answer_dns;

  memcpy(answer, pack, len);

  answer_ethh = pkt_ethhdr(answer);
  answer_iph  = pkt_iphdr(answer);
  answer_udph = pkt_udphdr(answer);
  answer_dns  = pkt_dnspkt(answer);

  /* DNS response, with no host error code */
  answer_dns->flags = htons(0x8583);

  /* UDP */
  answer_udph->src = udph->dst;
  answer_udph->dst = udph->src;

  /* IP */
  answer_iph->check = 0; /* Calculate at end of packet */
  memcpy(&answer_iph->daddr, &iph->saddr, PKT_IP_ALEN);
  memcpy(&answer_iph->saddr, &iph->daddr, PKT_IP_ALEN);

  /* Ethernet */
  memcpy(&answer_ethh->dst, &ethh->src, PKT_ETH_ALEN);
  memcpy(&answer_ethh->src, &ethh->dst, PKT_ETH_ALEN);

  /* checksums */
  chksum(answer_iph);

  gw_sendDlData(this, 0, conn->hismac, answer, len);
  return 0;
}

static int matchRedirectDns(uint8_t *r, char *name) {
  int r_len = strlen((char *)r);
  int name_len = strlen(name);

  debug(LOG_DEBUG, "checking dns for %s in %s", name, r);

  if (r_len == name_len && !memcmp(r, name, name_len)) {
    return 1;
  }

  return 0;
}

/*
 *   dhcp_dns() - Checks DNS for bad packets or locally handled DNS.
 *   returns: 0 = do not forward, 1 = forward DNS
 */
int dnsHandler(struct ipconnections_t *conn, uint8_t *pack, size_t *plen) {

	s_gwOptions *gwOptions = get_gwOptions();
  if (*plen < DHCP_DNS_HLEN + sizeofudp(pack)) {

    debug(LOG_DEBUG, "bad DNS packet of length %zu",   *plen);
    return 0;

  } else {

	debug(LOG_DEBUG, "DNS packet of length %zu",   *plen);

    struct dns_packet_t *dnsp = pkt_dnspkt(pack);

    size_t dlen = *plen - DHCP_DNS_HLEN - sizeofudp(pack);
    size_t olen = dlen;

    uint16_t flags   = ntohs(dnsp->flags);
    uint16_t qdcount = ntohs(dnsp->qdcount);

    uint8_t *dptr = (uint8_t *)dnsp->records;
    uint8_t q[512];

    int mode = 0;
    int qmatch = -1;
    int i;

    uint16_t id = ntohs(dnsp->id);
    debug(LOG_DEBUG, "dhcp_dns plen=%zd dlen=%zd olen=%zd",   *plen, dlen, olen);
    debug(LOG_DEBUG, "DNS ID:    %d",   id);
    debug(LOG_DEBUG, "DNS Flags: %d",   flags);

    /* it was a response? shouldn't be */
	if (((flags & 0x8000) >> 15) == 1) {
		debug(LOG_DEBUG, "Dropping unexpected DNS response");
		return 0;
	}

	memset(q, 0, sizeof(q));

	for (i=0; dlen && i < qdcount; i++) {
		if (copyDnsRsp(conn, &dptr, &dlen,
				(uint8_t *)dnsp, olen, q, sizeof(q))) {
			syslog(LOG_WARNING, "dropping malformed DNS");
			return sendDnsNak(conn, pack, *plen);
		}
	}

      if (flags == 0x0100 && qdcount >= 0x0001) {

        char *hostname = gwOptions->redirhost;

        uint8_t *p;
        uint8_t query[256];
        uint8_t reply[4];
        int match = 0;

        if (!match && hostname) {
        	match = matchRedirectDns(q, hostname);
        	if (match) {
        		memcpy(reply, &gwOptions->tundevip.s_addr, 4);
        	}
        }

        if (match) {

        	uint8_t answer[1500];

        	struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
        	struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
        	struct pkt_udphdr_t *udph = pkt_udphdr(pack);

        	struct pkt_ethhdr_t *answer_ethh;
        	struct pkt_iphdr_t  *answer_iph;
        	struct pkt_udphdr_t *answer_udph;
        	struct dns_packet_t *answer_dns;

        	size_t query_len = 0;
        	size_t udp_len;
        	size_t length;

        	int n;

        	p = dnsp->records;

        	debug(LOG_DEBUG, "It was a matching query!\n");

        	do {
        		if (query_len < 256)
        			query[query_len++] = *p;
        		else
        			break;
        	}
        	while (*p++ != 0); /* TODO */

          for (n=0; n<4; n++) {
            if (query_len < 256)
              query[query_len++] = *p++;
          }

          query[query_len++] = 0xc0;
          query[query_len++] = 0x0c;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x00;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x2c;
          query[query_len++] = 0x00;
          query[query_len++] = 0x04;
          memcpy(query + query_len, reply, 4);
          query_len += 4;

          memcpy(answer, pack, *plen); /* TODO */

          answer_ethh = pkt_ethhdr(answer);
          answer_iph = pkt_iphdr(answer);
          answer_udph = pkt_udphdr(answer);
          answer_dns = pkt_dnspkt(answer);

          /* DNS Header */
          answer_dns->id      = dnsp->id;
          answer_dns->flags   = htons(0x8000);
          answer_dns->qdcount = htons(0x0001);
          answer_dns->ancount = htons(0x0001);
          answer_dns->nscount = htons(0x0000);
          answer_dns->arcount = htons(0x0000);
          memcpy(answer_dns->records, query, query_len);

          /* UDP header */
          udp_len = query_len + DHCP_DNS_HLEN + PKT_UDP_HLEN;
          answer_udph->len = htons(udp_len);
          answer_udph->src = udph->dst;
          answer_udph->dst = udph->src;

          /* Ip header */
          answer_iph->version_ihl = PKT_IP_VER_HLEN;
          answer_iph->tos = 0;
          answer_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
          answer_iph->id = 0;
          answer_iph->opt_off_high = 0;
          answer_iph->off_low = 0;
          answer_iph->ttl = 0x10;
          answer_iph->protocol = 0x11;
          answer_iph->check = 0; /* Calculate at end of packet */
          memcpy(&answer_iph->daddr, &iph->saddr, PKT_IP_ALEN);
          memcpy(&answer_iph->saddr, &iph->daddr, PKT_IP_ALEN);

          /* Ethernet header */
          memcpy(answer_ethh->dst, &ethh->src, PKT_ETH_ALEN);
          memcpy(answer_ethh->src, &ethh->dst, PKT_ETH_ALEN);

          /* Work out checksums */
          chksum(answer_iph);

          /* Calculate total length */
          length = udp_len + sizeofip(answer);

          gw_sendDlData(conn->parent, 0, conn->hismac, answer, length);
          return 0;
        }
      }
      return 1;
  }
}
