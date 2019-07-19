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

#include "charm.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && !defined(NATIVE_BIG_ENDIAN)
#define NATIVE_BIG_ENDIAN
#endif

#define DEFAULT_MTU 9000
#define RECONNECT_ATTEMPTS 30
#define TAG_LEN 6
#define MAX_PACKET_LEN 65536
#define TS_TOLERANCE 7200
#define TIMEOUT (120 * 1000)
#define OUTER_CONGESTION_CONTROL_ALG "bbr"
#define BUFFERBLOAT_CONTROL 0
#define DEFAULT_CLIENT_IP "192.168.192.1"
#define DEFAULT_SERVER_IP "192.168.192.254"
#define DEFAULT_PORT "443"

#ifdef NATIVE_BIG_ENDIAN
#define endian_swap16(x) __builtin_bswap16(x)
#define endian_swap32(x) __builtin_bswap32(x)
#define endian_swap64(x) __builtin_bswap64(x)
#else
#define endian_swap16(x) (x)
#define endian_swap32(x) (x)
#define endian_swap64(x) (x)
#endif

static const int POLLFD_TUN = 0, POLLFD_LISTENER = 1, POLLFD_CLIENT = 2,
                 POLLFD_COUNT = 3;

typedef struct Context_ {
    const char*   wanted_name;
    const char*   local_tun_ip;
    const char*   remote_tun_ip;
    const char*   local_tun_ip6;
    const char*   remote_tun_ip6;
    const char*   server_ip;
    const char*   server_port;
    const char*   ext_if_name;
    const char*   ext_gw_ip;
    char          if_name[IFNAMSIZ];
    int           is_server;
    int           tun_fd;
    int           client_fd;
    int           listen_fd;
    int           congestion;
    int           firewall_rules_set;
    struct pollfd fds[3];
    uint32_t      uc_kx_st[12];
    uint32_t      uc_st[2][12];
} Context;

static volatile sig_atomic_t exit_signal_received;

static void
signal_handler(int sig)
{
    signal(sig, SIG_DFL);
    exit_signal_received = 1;
}

static ssize_t
safe_write(const int fd, const void* const buf_, size_t count,
           const int timeout)
{
    struct pollfd pfd;
    const char*   buf = (const char*) buf_;
    ssize_t       written;

    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) < (ssize_t) 0) {
            if (errno == EAGAIN) {
                pfd.fd     = fd;
                pfd.events = POLLOUT;
                if (poll(&pfd, (nfds_t) 1, timeout) <= 0) {
                    return (ssize_t) -1;
                }
            } else if (errno != EINTR || exit_signal_received) {
                return (ssize_t) -1;
            }
        }
        buf += written;
        count -= written;
    }
    return (ssize_t)(buf - (const char*) buf_);
}

static ssize_t
safe_read(const int fd, void* const buf_, size_t count, const int timeout)
{
    struct pollfd  pfd;
    unsigned char* buf    = (unsigned char*) buf_;
    ssize_t        readnb = (ssize_t) -1;

    while (readnb != 0 && count > (ssize_t) 0) {
        while ((readnb = read(fd, buf, count)) < (ssize_t) 0) {
            if (errno == EAGAIN) {
                pfd.fd     = fd;
                pfd.events = POLLIN;
                if (poll(&pfd, (nfds_t) 1, timeout) <= 0) {
                    return (ssize_t) -1;
                }
            } else if (errno != EINTR || exit_signal_received) {
                return (ssize_t) -1;
            }
        }
        count -= readnb;
        buf += readnb;
    }
    return (ssize_t)(buf - (unsigned char*) buf_);
}

static ssize_t
safe_read_partial(const int fd, void* const buf_, const size_t max_count)
{
    unsigned char* const buf = (unsigned char*) buf_;
    ssize_t              readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 &&
           errno == EINTR && !exit_signal_received)
        ;
    return readnb;
}

static ssize_t
safe_write_partial(const int fd, void* const buf_, const size_t max_count)
{
    unsigned char* const buf = (unsigned char*) buf_;
    ssize_t              writenb;

    while ((writenb = write(fd, buf, max_count)) < (ssize_t) 0 &&
           errno == EINTR && !exit_signal_received)
        ;
    return writenb;
}

#ifdef __linux__
static int
tun_create(char if_name[IFNAMSIZ], const char* wanted_name)
{
    struct ifreq ifr;
    int          fd;
    int          err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s",
             wanted_name == NULL ? "" : wanted_name);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);

    return fd;
}
#elif defined(__APPLE__)
static int
tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id)
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 err;
    int                 fd;

    if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
        return -1;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    memset(&sc, 0, sizeof sc);
    sc = (struct sockaddr_ctl){
        .sc_id      = ci.ctl_id,
        .sc_len     = sizeof sc,
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit    = id + 1,
    };
    if (connect(fd, (struct sockaddr*) &sc, sizeof sc) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "utun%u", id);

    return fd;
}

static int
tun_create(char if_name[IFNAMSIZ], const char* wanted_name)
{
    unsigned int id;
    int          fd;

    if (wanted_name == NULL || *wanted_name == 0) {
        for (id = 0; id < 32; id++) {
            if ((fd = tun_create_by_id(if_name, id)) != -1) {
                return fd;
            }
        }
        return -1;
    }
    if (sscanf(wanted_name, "utun%u", &id) != 1) {
        errno = EINVAL;
        return -1;
    }
    return tun_create_by_id(if_name, id);
}
#else
static int
tun_create(char if_name[IFNAMSIZ], const char* wanted_name)
{
    char path[64];

    if (wanted_name == NULL) {
        fprintf(stderr,
                "The tunnel device name must be specified on that platform "
                "(try 'tun0')\n");
        errno = EINVAL;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", wanted_name);
    snprintf(path, sizeof path, "/dev/%s", wanted_name);

    return open(path, O_RDWR);
}
#endif

static int
tun_set_mtu(const char* if_name, int mtu)
{
    struct ifreq ifr;
    int          fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }
    ifr.ifr_mtu = mtu;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
    if (ioctl(fd, SIOCSIFMTU, &ifr) != 0) {
        return -1;
    }
    return close(fd);
}

#ifdef __linux__
static ssize_t
tun_read(int fd, void* data, size_t size)
{
    return safe_read_partial(fd, data, size);
}

static ssize_t
tun_write(int fd, const void* data, size_t size)
{
    return safe_write(fd, data, size, TIMEOUT);
}
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
static ssize_t
tun_read(int fd, void* data, size_t size)
{
    ssize_t  ret;
    uint32_t family;

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = data,
            .iov_len  = size,
        },
    };

    ret = readv(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return -1;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}

static ssize_t
tun_write(int fd, const void* data, size_t size)
{
    uint32_t family;
    ssize_t  ret;

    if (size < 20) {
        return 0;
    }
    switch (*(const uint8_t*) data >> 4) {
    case 4:
        family = htonl(AF_INET);
        break;
    case 6:
        family = htonl(AF_INET6);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = (void*) data,
            .iov_len  = size,
        },
    };
    ret = writev(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return ret;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}
#endif

static char*
read_from_shell_command(char* result, size_t sizeof_result, const char* command)
{
    FILE* fp;
    char* pnt;

    if ((fp = popen(command, "r")) == NULL) {
        return NULL;
    }
    if (fgets(result, sizeof_result, fp) == NULL) {
        fclose(fp);
        fprintf(stderr, "Command [%s] failed]\n", command);
        return NULL;
    }
    if ((pnt = strrchr(result, '\n')) != NULL) {
        *pnt = 0;
    }
    pclose(fp);

    return *result == 0 ? NULL : result;
}

static char*
get_default_gw_ip(void)
{
    static char gw[64];
#ifdef __APPLE__
    return read_from_shell_command(
        gw, sizeof gw,
        "netstat -rn|awk '/^default/{if(index($6,\"en\")){print $2}}'");
#elif defined(__linux__)
    return read_from_shell_command(
        gw, sizeof gw, "ip route show default|awk '/default/{print $3}'");
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
    return read_from_shell_command(gw, sizeof gw,
                                   "netstat -rn|awk '/^default/{print $2}'");
#else
    return NULL;
#endif
}

static char*
get_default_ext_if_name(void)
{
    static char if_name[64];
#ifdef __APPLE__
    return read_from_shell_command(
        if_name, sizeof if_name,
        "netstat -rn|awk '/^default/{if(index($6,\"en\")){print $6}}'");
#elif defined(__linux__)
    return read_from_shell_command(
        if_name, sizeof if_name,
        "ip route show default|awk '/default/{print $5}'");
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
    return read_from_shell_command(if_name, sizeof if_name,
                                   "netstat -rn|awk '/^default/{print $8}'");
#else
    return NULL;
#endif
}

static int
tcp_opts(int fd)
{
    int on = 1;

    (void) setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*) &on, sizeof on);
#ifdef TCP_QUICKACK
    (void) setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (char*) &on, sizeof on);
#else
    (void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*) &on, sizeof on);
#endif
#ifdef TCP_CONGESTION
    (void) setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION,
                      OUTER_CONGESTION_CONTROL_ALG,
                      sizeof OUTER_CONGESTION_CONTROL_ALG - 1);
#endif
    return 0;
}

static int
tcp_client(const char* address, const char* port)
{
    struct addrinfo hints, *res;
    int             eai;
    int             client_fd;
    int             err;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
#ifdef __OpenBSD__
    if (address == NULL) {
        hints.ai_family = AF_INET;
    }
#endif
    printf("Connecting to %s:%s...\n", address, port);
    if ((eai = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the client socket: [%s]\n",
                gai_strerror(eai));
        errno = EINVAL;
        return -1;
    }
    if ((client_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(client_fd, (const struct sockaddr*) res->ai_addr,
                res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        err = errno;
        close(client_fd);
        errno = err;
        return -1;
    }
    freeaddrinfo(res);
    if (tcp_opts(client_fd) != 0) {
        err = errno;
        close(client_fd);
        errno = err;
        return -1;
    }
    return client_fd;
}

static int
tcp_listener(const char* address, const char* port)
{
    struct addrinfo hints, *res;
    int             on;
    int             listen_fd;
    int             backlog = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
#ifdef __OpenBSD__
    if (address == NULL) {
        hints.ai_family = AF_INET;
    }
#endif
    if ((on = getaddrinfo(address, port, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
        fprintf(stderr, "Unable to create the listening socket: [%s]\n",
                gai_strerror(on));
        errno = EINVAL;
        return -1;
    }
    on = 1;
    if ((listen_fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1 ||
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &on,
                   sizeof on) != 0) {
        freeaddrinfo(res);
        return -1;
    }
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    on = 0;
    (void) setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &on,
                      sizeof on);
#endif
    printf("Listening to %s:%s\n", address == NULL ? "*" : address, port);
    if (bind(listen_fd, (struct sockaddr*) res->ai_addr,
             (socklen_t) res->ai_addrlen) != 0 ||
        listen(listen_fd, backlog) != 0) {
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    return listen_fd;
}

static void
client_disconnect(Context* context)
{
    if (context->client_fd == -1) {
        return;
    }
    (void) close(context->client_fd);
    context->client_fd          = -1;
    context->fds[POLLFD_CLIENT] = (struct pollfd){ .fd = -1, .events = 0 };
    memset(context->uc_st, 0, sizeof context->uc_st);
}

static int
server_key_exchange(Context* context, const int client_fd)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t ts, now;

    memcpy(st, context->uc_kx_st, sizeof st);
    errno = EACCES;
    if (safe_read(client_fd, pkt1, sizeof pkt1, TIMEOUT) != sizeof pkt1) {
        return -1;
    }
    uc_hash(st, h, pkt1, 32 + 8);
    if (memcmp(h, pkt1 + 32 + 8, 32) != 0) {
        return -1;
    }
    memcpy(&ts, pkt1 + 32, 8);
    ts  = endian_swap64(ts);
    now = time(NULL);
    if ((ts > now && ts - now > TS_TOLERANCE) ||
        (now > ts && now - ts > TS_TOLERANCE)) {
        fprintf(stderr,
                "Clock difference is too large: %" PRIu64
                " (client) vs %" PRIu64 " (server)\n",
                ts, now);
        return -1;
    }
    uc_randombytes_buf(pkt2, 32);
    uc_hash(st, pkt2 + 32, pkt2, 32);
    if (safe_write(client_fd, pkt2, sizeof pkt2, TIMEOUT) != sizeof pkt2) {
        return -1;
    }
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int
tcp_accept(Context* context, int listen_fd)
{
    struct sockaddr_storage client_sa;
    socklen_t               client_sa_len = sizeof client_sa;
    int                     client_fd;
    int                     err;

    if ((client_fd = accept(listen_fd, (struct sockaddr*) &client_sa,
                            &client_sa_len)) < 0) {
        return -1;
    }
    if (client_sa_len <= (socklen_t) 0U) {
        (void) close(client_fd);
        errno = EINTR;
        return -1;
    }
    if (tcp_opts(client_fd) != 0) {
        err = errno;
        (void) close(client_fd);
        errno = err;
        return -1;
    }
    context->congestion = 0;
    if (server_key_exchange(context, client_fd) != 0) {
        fprintf(stderr, "Authentication failed\n");
        (void) close(client_fd);
        errno = EACCES;
        return -1;
    }
    return client_fd;
}

static int
shell_cmd(const char* substs[][2], const char* args_str)
{
    char*  args[64];
    char   cmdbuf[4096];
    pid_t  child;
    size_t args_i = 0, cmdbuf_i = 0, args_str_i, i;
    int    c, exit_status, is_space = 1;

    errno = ENOSPC;
    for (args_str_i = 0; (c = args_str[args_str_i]) != 0; args_str_i++) {
        if (isspace((unsigned char) c)) {
            if (!is_space) {
                if (cmdbuf_i >= sizeof cmdbuf) {
                    return -1;
                }
                cmdbuf[cmdbuf_i++] = 0;
            }
            is_space = 1;
            continue;
        }
        if (is_space) {
            if (args_i >= sizeof args / sizeof args[0]) {
                return -1;
            }
            args[args_i++] = &cmdbuf[cmdbuf_i];
        }
        is_space = 0;
        for (i = 0; substs[i][0] != NULL; i++) {
            size_t pat_len = strlen(substs[i][0]),
                   sub_len = strlen(substs[i][1]);
            if (!strncmp(substs[i][0], &args_str[args_str_i], pat_len)) {
                if (sizeof cmdbuf - cmdbuf_i <= sub_len) {
                    return -1;
                }
                memcpy(&cmdbuf[cmdbuf_i], substs[i][1], sub_len);
                args_str_i += pat_len - 1;
                cmdbuf_i += sub_len;
                break;
            }
        }
        if (substs[i][0] == NULL) {
            if (cmdbuf_i >= sizeof cmdbuf) {
                return -1;
            }
            cmdbuf[cmdbuf_i++] = c;
        }
    }
    if (!is_space) {
        if (cmdbuf_i >= sizeof cmdbuf) {
            return -1;
        }
        cmdbuf[cmdbuf_i++] = 0;
    }
    if (args_i >= sizeof args / sizeof args[0]) {
        return -1;
    }
    args[args_i] = NULL;
    if ((child = vfork()) == (pid_t) -1) {
        return -1;
    } else if (child == (pid_t) 0) {
        execvp(args[0], args);
        _exit(1);
    } else if (waitpid(child, &exit_status, 0) == (pid_t) -1 ||
               !WIFEXITED(exit_status)) {
        return -1;
    }
    return 0;
}

typedef struct Cmds {
    const char* const* set;
    const char* const* unset;
} Cmds;

static Cmds
firewall_rules_cmds(const Context* context)
{
    if (context->is_server) {
#ifdef __linux__
        static const char *set_cmds
            []   = { "sysctl net.ipv4.ip_forward=1",
                   "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                   "ip link set dev $IF_NAME up",
                   "iptables -t nat -A POSTROUTING -o $EXT_IF_NAME -s "
                   "$REMOTE_TUN_IP -j MASQUERADE",
                   "iptables -t filter -A FORWARD -i $EXT_IF_NAME -o $IF_NAME "
                   "-m state --state RELATED,ESTABLISHED -j ACCEPT",
                   "iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME "
                   "-j ACCEPT",
                   NULL },
   *unset_cmds[] = {
       "iptables -t nat -D POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j "
       "MASQUERADE",
       "iptables -t filter -D FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state "
       "--state RELATED,ESTABLISHED -j ACCEPT",
       "iptables -t filter -D FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
       NULL
   };
#else
        static const char *const *set_cmds = NULL, *const *unset_cmds = NULL;
#endif
        return (Cmds){ set_cmds, unset_cmds };
    } else {
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        static const char *set_cmds[] =
            { "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up",
              "ifconfig $IF_NAME inet6 $LOCAL_TUN_IP6 $REMOTE_TUN_IP6 "
              "prefixlen 128 up",
              "route add $EXT_IP $EXT_GW_IP",
              "route add 0/1 $REMOTE_TUN_IP",
              "route add 128/1 $REMOTE_TUN_IP",
              "route add -inet6 -blackhole 0000::/1 $REMOTE_TUN_IP6",
              "route add -inet6 -blackhole 8000::/1 $REMOTE_TUN_IP6",
              NULL },
                          *unset_cmds[] = { "route delete $EXT_IP $EXT_GW_IP",
                                            NULL };
#elif defined(__linux__)
        static const char *
            set_cmds[]   = { "sysctl net.ipv4.tcp_congestion_control=bbr",
                           "ip link set dev $IF_NAME up",
                           "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev "
                           "$IF_NAME",
                           "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6 "
                           "dev $IF_NAME",
                           "ip route add $EXT_IP via $EXT_GW_IP",
                           "ip route add 0/1 via $REMOTE_TUN_IP",
                           "ip route add 128/1 via $REMOTE_TUN_IP",
                           "ip -6 route add 0/1 via $REMOTE_TUN_IP6",
                           "ip -6 route add 128/1 via $REMOTE_TUN_IP6",
                           NULL },
           *unset_cmds[] = { "ip route del $EXT_IP via $EXT_GW_IP", NULL };
#else
        static const char *const *set_cmds = NULL, *const *unset_cmds = NULL;
#endif
        return (Cmds){ set_cmds, unset_cmds };
    }
}

static int
firewall_rules(Context* context, int set)
{
    const char* substs[][2] = { { "$LOCAL_TUN_IP6", context->local_tun_ip6 },
                                { "$REMOTE_TUN_IP6", context->remote_tun_ip6 },
                                { "$LOCAL_TUN_IP", context->local_tun_ip },
                                { "$REMOTE_TUN_IP", context->remote_tun_ip },
                                { "$EXT_IP", context->server_ip },
                                { "$EXT_PORT", context->server_port },
                                { "$EXT_IF_NAME", context->ext_if_name },
                                { "$EXT_GW_IP", context->ext_gw_ip },
                                { "$IF_NAME", context->if_name },
                                { NULL, NULL } };
    const char* const* cmds;
    size_t             i;

    if (context->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(context).set
                     : firewall_rules_cmds(context).unset)) == NULL) {
        fprintf(stderr,
                "Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i]) != 0) {
            fprintf(stderr, "Unable to run [%s]: [%s]\n", cmds[i],
                    strerror(errno));
            return -1;
        }
    }
    context->firewall_rules_set = set;
    return 0;
}

static int
client_key_exchange(Context* context)
{
    uint32_t st[12];
    uint8_t  pkt1[32 + 8 + 32], pkt2[32 + 32];
    uint8_t  h[32];
    uint8_t  k[32];
    uint8_t  iv[16] = { 0 };
    uint64_t now;

    memcpy(st, context->uc_kx_st, sizeof st);
    uc_randombytes_buf(pkt1, 32);
    now = endian_swap64(time(NULL));
    memcpy(pkt1 + 32, &now, 8);
    uc_hash(st, pkt1 + 32 + 8, pkt1, 32 + 8);
    if (safe_write(context->client_fd, pkt1, sizeof pkt1, TIMEOUT) !=
        sizeof pkt1) {
        return -1;
    }
    errno = EACCES;
    if (safe_read(context->client_fd, pkt2, sizeof pkt2, TIMEOUT) !=
        sizeof pkt2) {
        return -1;
    }
    uc_hash(st, h, pkt2, 32);
    if (memcmp(h, pkt2 + 32, 32) != 0) {
        return -1;
    }
    uc_hash(st, k, NULL, 0);
    iv[0] = context->is_server;
    uc_state_init(context->uc_st[0], k, iv);
    iv[0] ^= 1;
    uc_state_init(context->uc_st[1], k, iv);

    return 0;
}

static int
client_connect(Context* context)
{
    memset(context->uc_st, 0, sizeof context->uc_st);
    context->uc_st[context->is_server][0] ^= 1;
    context->client_fd = tcp_client(context->server_ip, context->server_port);
    if (context->client_fd == -1) {
        perror("TCP client");
        return -1;
    }
#if BUFFERBLOAT_CONTROL
    fcntl(context->client_fd, F_SETFL,
          fcntl(context->client_fd, F_GETFL, 0) | O_NONBLOCK);
#endif
    context->congestion = 0;
    if (client_key_exchange(context) != 0) {
        fprintf(stderr, "Authentication failed\n");
        client_disconnect(context);
        return -1;
    }
    firewall_rules(context, 1);
    context->fds[POLLFD_CLIENT] = (struct pollfd){ .fd     = context->client_fd,
                                                   .events = POLLIN,
                                                   .revents = 0 };
    puts("Connected");

    return 0;
}

static int
client_reconnect(Context* context)
{
    unsigned int i;

    client_disconnect(context);
    if (context->is_server) {
        return 0;
    }
    for (i = 0; exit_signal_received == 0 && i < RECONNECT_ATTEMPTS; i++) {
        puts("Trying to reconnect");
        sleep(i);
        if (client_connect(context) == 0) {
            return 0;
        }
    }
    return -1;
}

static int
event_loop(Context* context)
{
    struct __attribute__((aligned(16))) {
        unsigned char _pad[16 - TAG_LEN - 2];
        unsigned char len[2];
        unsigned char tag[TAG_LEN];
        unsigned char data[MAX_PACKET_LEN];
    } buf;
    struct pollfd* const fds = context->fds;
    ssize_t              len;
    int                  found_fds;
    int                  new_client_fd;

    if (exit_signal_received != 0) {
        return -2;
    }
    if ((found_fds = poll(fds, POLLFD_COUNT, 1500)) == -1) {
        return -1;
    }
    if (fds[POLLFD_LISTENER].revents & POLLIN) {
        puts("Accepting new client");
        new_client_fd = tcp_accept(context, context->listen_fd);
        if (new_client_fd == -1) {
            perror("tcp_accept");
            return 0;
        }
        if (context->client_fd != -1) {
            (void) close(context->client_fd);
        }
        context->client_fd = new_client_fd;
        puts("Accepted");
        fds[POLLFD_CLIENT] =
            (struct pollfd){ .fd = context->client_fd, .events = POLLIN };
    }
    if ((fds[POLLFD_TUN].revents & POLLERR) ||
        (fds[POLLFD_TUN].revents & POLLHUP)) {
        puts("HUP (tun)");
        return -1;
    }
    if (fds[POLLFD_TUN].revents & POLLIN) {
        len = tun_read(context->tun_fd, buf.data, sizeof buf.data);
        if (len <= 0) {
            perror("tun_read");
            return -1;
        }
        if (context->congestion) {
            context->congestion = 0;
            return 0;
        }
        if (context->client_fd != -1) {
            unsigned char tag_full[16];
            ssize_t       writenb;
            uint16_t      binlen = endian_swap16((uint16_t) len);

            memcpy(buf.len, &binlen, 2);
            uc_encrypt(context->uc_st[0], buf.data, len, tag_full);
            memcpy(buf.tag, tag_full, TAG_LEN);
            writenb = safe_write_partial(context->client_fd, buf.len,
                                         2U + TAG_LEN + len);
            if (writenb != (ssize_t)(2U + TAG_LEN + len)) {
                if (errno == EAGAIN) {
                    context->congestion = 1;
                    writenb = safe_write(context->client_fd, buf.len,
                                         2U + TAG_LEN + len, TIMEOUT);
                }
            }
            if (writenb != (ssize_t)(2U + TAG_LEN + len)) {
                perror("safe_write (client)");
                return client_reconnect(context);
            }
        }
    }
    if ((fds[POLLFD_CLIENT].revents & POLLERR) ||
        (fds[POLLFD_CLIENT].revents & POLLHUP)) {
        puts("HUP (client)");
        return client_reconnect(context);
    }
    if (fds[POLLFD_CLIENT].revents & POLLIN) {
        uint16_t binlen;

        if (safe_read(context->client_fd, &binlen, sizeof binlen, TIMEOUT) !=
            sizeof binlen) {
            len = -1;
        } else {
            len = (ssize_t) endian_swap16(binlen);
            if ((size_t) len > sizeof buf.data) {
                len = -1;
            } else {
                len = safe_read(context->client_fd, buf.tag,
                                TAG_LEN + (size_t) binlen, TIMEOUT);
            }
        }
        if (len < TAG_LEN) {
            puts("Client disconnected");
            return client_reconnect(context);
        } else {
            len -= TAG_LEN;
            if (uc_decrypt(context->uc_st[1], buf.data, len, buf.tag,
                           TAG_LEN) != 0) {
                fprintf(stderr, "Corrupted stream\n");
                return client_reconnect(context);
            }
            if (tun_write(context->tun_fd, buf.data, len) != len) {
                perror("tun_write");
            }
        }
    }
    return 0;
}

static int
doit(Context* context)
{
    context->client_fd = context->listen_fd = -1;
    memset(context->fds, 0, sizeof *context->fds);
    context->fds[POLLFD_TUN] = (struct pollfd){ .fd      = context->tun_fd,
                                                .events  = POLLIN,
                                                .revents = 0 };
    if (context->is_server) {
        if ((context->listen_fd = tcp_listener(context->server_ip,
                                               context->server_port)) == -1) {
            perror("tcp_listener");
            return -1;
        }
        context->fds[POLLFD_LISTENER] = (struct pollfd){
            .fd     = context->listen_fd,
            .events = POLLIN,
        };
    }
    if (!context->is_server && client_reconnect(context) != 0) {
        fprintf(stderr, "Unable to connect to server: [%s]\n", strerror(errno));
        return -1;
    }
    while (event_loop(context) == 0)
        ;
    return 0;
}

static int
load_key_file(Context* context, const char* file)
{
    unsigned char key[32];
    int           fd;

    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (safe_read(fd, key, sizeof key, TIMEOUT) != sizeof key) {
        return -1;
        memset(key, 0, sizeof key);
    }
    uc_state_init(context->uc_kx_st, key,
                  (const unsigned char*) "VPN Key Exchange");
    uc_memzero(key, sizeof key);

    return close(fd);
}

static void
usage(void)
{
    puts(
        "Usage:\n"
        "\n"
        "dsvpn\t\"server\"\n\t<key file>\n\t<vpn server ip>|\"auto\"\n\t<vpn "
        "server port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
        "ip>|\"auto\"\n\t<remote tun ip>\"auto\"\n\t<external ip>|\"auto\""
        "\n\n"
        "dsvpn\t\"client\"\n\t<key file>\n\t<vpn server ip>\n\t<vpn server "
        "port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun "
        "ip>|\"auto\"\n\t<remote tun ip>|\"auto\"\n\t<gateway ip>\"auto\"\n");
    exit(254);
}

static void
get_tun6_addresses(Context* context)
{
    static char local_tun_ip6[40], remote_tun_ip6[40];

    snprintf(local_tun_ip6, sizeof local_tun_ip6, "64:ff9b::%s",
             context->local_tun_ip);
    snprintf(remote_tun_ip6, sizeof remote_tun_ip6, "64:ff9b::%s",
             context->remote_tun_ip);
    context->local_tun_ip6  = local_tun_ip6;
    context->remote_tun_ip6 = remote_tun_ip6;
}

int
main(int argc, char* argv[])
{
    Context context;

    (void) safe_read_partial;

    if (argc < 3) {
        usage();
    }
    memset(&context, 0, sizeof context);
    context.is_server = strcmp(argv[1], "server") == 0;
    if (load_key_file(&context, argv[2]) != 0) {
        fprintf(stderr, "Unable to load the key file [%s]\n", argv[2]);
        return 1;
    }
    context.server_ip =
        (argc <= 3 || strcmp(argv[3], "auto") == 0) ? NULL : argv[3];
    if (context.server_ip == NULL && !context.is_server) {
        usage();
    }
    context.server_port =
        (argc <= 4 || strcmp(argv[4], "auto") == 0) ? DEFAULT_PORT : argv[4];
    context.wanted_name =
        (argc <= 5 || strcmp(argv[5], "auto") == 0) ? NULL : argv[5];
    context.local_tun_ip =
        (argc <= 6 || strcmp(argv[6], "auto") == 0)
            ? (context.is_server ? DEFAULT_SERVER_IP : DEFAULT_CLIENT_IP)
            : argv[6];
    context.remote_tun_ip =
        (argc <= 7 || strcmp(argv[7], "auto") == 0)
            ? (context.is_server ? DEFAULT_CLIENT_IP : DEFAULT_SERVER_IP)
            : argv[7];
    if ((context.ext_gw_ip = (argc <= 8 || strcmp(argv[8], "auto") == 0)
                                 ? get_default_gw_ip()
                                 : argv[8]) == NULL &&
        !context.is_server) {
        fprintf(stderr, "Unable to automatically determine the gateway IP\n");
        return 1;
    }
    if ((context.ext_if_name = get_default_ext_if_name()) == NULL &&
        context.is_server) {
        fprintf(stderr,
                "Unable to automatically determine the external interface\n");
        return 1;
    }
    get_tun6_addresses(&context);
    context.tun_fd = tun_create(context.if_name, context.wanted_name);
    if (context.tun_fd == -1) {
        perror("tun_create");
        return 1;
    }
    printf("Interface: [%s]\n", context.if_name);
    if (tun_set_mtu(context.if_name, DEFAULT_MTU) != 0) {
        perror("mtu");
    }
    if (context.is_server && firewall_rules(&context, 1) != 0) {
        return -1;
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (doit(&context) != 0) {
        return -1;
    }
    firewall_rules(&context, 0);

    return 0;
}
