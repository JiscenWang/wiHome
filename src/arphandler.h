/*
 * arphandler.h
 *
 *  Created on: 2019年7月1日
 *      Author: jerome
 */

#ifndef SRC_ARPHANDLER_H_
#define SRC_ARPHANDLER_H_

int raw_rcvArp(struct rawif_in *ctx, uint8_t *pack, size_t len);
int sendDlGARP(struct gateway_t *pgateway, int idx);

#endif /* SRC_ARPHANDLER_H_ */
