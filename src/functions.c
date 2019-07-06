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
#include <stdarg.h>
#include <net/if.h>

#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
//#include <netpacket/packet.h>

#include <string.h>
#include <netdb.h>

#include "common.h"
#include "functions.h"
#include "debug.h"
#include "gatewaymain.h"

#include "../config.h"

extern struct timespec mainclock;

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

int safe_write(int s, void *b, size_t blen) {
  int ret;
  do {
    ret = write(s, b, blen);
  } while (ret == -1 && errno == EINTR);

  if (ret < 0)
    debug(LOG_ERR, "%s: write(%d, %zd)", strerror(errno), s, blen);

  return ret;
}


/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}

/** Fork and then close any registered fille descriptors.
 * If fork() fails, we die.
 * @return pid_t 0 for child, pid of child for parent
 */
pid_t
safe_fork(void)
{
    pid_t result;
    result = fork();

    if (result == -1) {
        debug(LOG_CRIT, "Failed to fork: %s.  Bailing out", strerror(errno));
        exit(1);
    } else if (result == 0) {
        /* I'm the child - do some cleanup */
    	termination_handler(1);
    }

    return result;
}


/** Allocate zero-filled ram or die.
 * @param size Number of bytes to allocate
 * @return void * pointer to the zero'd bytes.
 */
void *
safe_malloc(size_t size)
{
    void *retval = NULL;
    retval = malloc(size);
    if (!retval) {
        debug(LOG_CRIT, "Failed to malloc %d bytes of memory: %s.  Bailing out", size, strerror(errno));
        exit(1);
    }
    memset(retval, 0, size);
    return (retval);
}

int safe_read(int s, void *b, size_t blen) {
  int ret;
  do {
    ret = read(s, b, blen);
  } while (ret == -1 && errno == EINTR);
  return ret;
}


int safe_recvfrom(int sockfd, void *buf, size_t len, int flags,
		  struct sockaddr *src_addr, socklen_t *addrlen) {
  int ret;
  do {
    ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  } while (ret == -1 && errno == EINTR);
  return ret;
}
/** Duplicates a string or die if memory cannot be allocated
 * @param s String to duplicate
 * @return A string in a newly allocated chunk of heap.
 */
/*####Jerome, check over*/
char *
safe_strdup(const char *s)
{
    char *retval = NULL;
    if (!s) {
        debug(LOG_CRIT, "safe_strdup called with NULL which would have crashed strdup. Bailing out");
        exit(1);
    }
    retval = strdup(s);
    if (!retval) {
        debug(LOG_CRIT, "Failed to duplicate a string: %s.  Bailing out", strerror(errno));
        exit(1);
    }
    return (retval);
}

/** Sprintf into a newly allocated buffer
 * Memory MUST be freed. Dies if memory cannot be allocated.
 * @param strp Pointer to a pointer that will be set to the newly allocated string
 * @param fmt Format string like sprintf
 * @param ... Variable number of arguments for format string
 * @return int Size of allocated string.
 */
int
safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int retval;

    va_start(ap, fmt);
    retval = safe_vasprintf(strp, fmt, ap);
    va_end(ap);

    return (retval);
}


/** Sprintf into a newly allocated buffer
 * Memory MUST be freed. Dies if memory cannot be allocted.
 * @param strp Pointer to a pointer that will be set to the newly allocated string
 * @param fmt Format string like sprintf
 * @param ap pre-digested va_list of arguments.
 * @return int Size of allocated string.
 */
int
safe_vasprintf(char **strp, const char *fmt, va_list ap)
{
    int retval;

    retval = vasprintf(strp, fmt, ap);

    if (retval == -1) {
        debug(LOG_CRIT, "Failed to vasprintf: %s.  Bailing out", strerror(errno));
        exit(1);
    }
    return (retval);
}
