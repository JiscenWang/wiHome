/*
 * dhcphandler.h
 *
 *  Created on: 2019年7月1日
 *      Author: jerome
 */

#ifndef SRC_DHCPHANDLER_H_
#define SRC_DHCPHANDLER_H_

int dhcpHandler(struct rawif_in *ctx, uint8_t *pack, size_t len);

#endif /* SRC_DHCPHANDLER_H_ */
