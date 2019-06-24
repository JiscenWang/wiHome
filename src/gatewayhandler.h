   /*
 * gatewayhandler.h
 *
 *  Created on: 2019年6月21日
 *      Author: jerome
 */

#ifndef SRC_GATEWAYHANDLER_H_
#define SRC_GATEWAYHANDLER_H_

int initGateway(struct gateway_t **pgateway);
int gw_tun_rcvPackets(struct tun_t *this, int idx);
int gw_raw_rcvPackets(struct dhcp_t *this, int idx);

int gw_sendDlData(struct gateway_t *this, int idx,
              unsigned char *hismac, uint8_t *packet, size_t length);

int gw_sandUpstreamData(struct gateway_t *gateway, struct pkt_buffer *pb, int idx);


#endif /* SRC_GATEWAYHANDLER_H_ */
