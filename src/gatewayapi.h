   /*
 * gatewayapi.h
 *
 *  Created on: 2019年6月21日
 *      Author: jerome
 */

#ifndef SRC_GATEWAYAPI_H_
#define SRC_GATEWAYAPI_H_

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

#include "gatewaymain.h"

int initGateway(struct gateway_t **pgateway);
int gw_tun_rcvPackets(struct gateway_t *this, int idx);
int gw_raw_rcvPackets(struct gateway_t *this, int idx);

int gw_sendDlData(struct gateway_t *this, int idx, unsigned char *hismac, uint8_t *packet, size_t length);

int gw_sendUlData(struct ipconnections_t *conn, uint8_t *pack, size_t len);

int gw_routeData(struct gateway_t *this, struct in_addr dstIP, uint8_t *packet, size_t length);

#endif /* SRC_GATEWAYAPI_H_ */
