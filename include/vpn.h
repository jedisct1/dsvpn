#ifndef vpn_H
#define vpn_H 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#define VERSION_STRING "0.1.4"

#ifdef __NetBSD__
#define DEFAULT_MTU 1500
#else
#define DEFAULT_MTU 9000
#endif
#define RECONNECT_ATTEMPTS 100
#define TAG_LEN 6
#define MAX_PACKET_LEN 65536
#define TS_TOLERANCE 7200
#define TIMEOUT (60 * 1000)
#define ACCEPT_TIMEOUT (10 * 1000)
#define OUTER_CONGESTION_CONTROL_ALG "bbr"
#define BUFFERBLOAT_CONTROL 1
#define NOTSENT_LOWAT (128 * 1024)
#define DEFAULT_CLIENT_IP "192.168.192.1"
#define DEFAULT_SERVER_IP "192.168.192.254"
#define DEFAULT_PORT "443"

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && !defined(NATIVE_BIG_ENDIAN)
#define NATIVE_BIG_ENDIAN
#endif

#ifdef NATIVE_BIG_ENDIAN
#define endian_swap16(x) __builtin_bswap16(x)
#define endian_swap32(x) __builtin_bswap32(x)
#define endian_swap64(x) __builtin_bswap64(x)
#else
#define endian_swap16(x) (x)
#define endian_swap32(x) (x)
#define endian_swap64(x) (x)
#endif

extern volatile sig_atomic_t exit_signal_received;

#endif
