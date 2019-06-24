/*
 * functions.c
 *
 *  Created on: 2019年6月21日
 *      Author: jerome
 */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>

#include <string.h>
#include <netdb.h>

#include "common.h"
#include "functions.h"
#include "debug.h"

#include "../config.h"

/*
 * Save pid of this gateway in pid file
 * @param 'pf' as string, it is the pid file absolutely path
 */
void save_pid_file(const char *pf)
{
    if (pf) {
        FILE *f = fopen(pf, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());

            int ret = fclose(f);
            if (ret == EOF) /* check the return value of fclose */
                debug(LOG_ERR, "fclose() on file %s was failed (%s)", pf, strerror(errno));
        } else /* fopen return NULL, open file failed */
            debug(LOG_ERR, "fopen() on flie %s was failed (%s)", pf, strerror(errno));
    }

    return;
}


time_t mainclock_tick() {
  if (time(&mainclock.tv_sec) == (time_t)-1) {
    debug(LOG_ERR, "%s: time()", strerror(errno));
  }
  return mainclock.tv_sec;
}


/*Jerome: J-Module added*/

int safe_sendto(int s, const void *b, size_t blen, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
  int ret;
  do {
    ret = sendto(s, b, blen, flags, dest_addr, addrlen);
  } while (ret == -1 && errno == EINTR);
  return ret;
}


