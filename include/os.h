#ifndef os_H
#define os_H 1

#include "vpn.h"

ssize_t safe_read(const int fd, void *const buf_, size_t count, const int timeout);

ssize_t safe_write(const int fd, const void *const buf_, size_t count, const int timeout);

ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count);

ssize_t safe_write_partial(const int fd, void *const buf_, const size_t max_count);

typedef struct Cmds {
    const char *const *set;
    const char *const *unset;
} Cmds;

Cmds firewall_rules_cmds(int is_server);

int shell_cmd(const char *substs[][2], const char *args_str, int silent);

const char *get_default_gw_ip(void);

const char *get_default_ext_if_name(void);

int tcp_opts(int fd);

int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);

int tun_set_mtu(const char *if_name, int mtu);

ssize_t tun_read(int fd, void *data, size_t size);

ssize_t tun_write(int fd, const void *data, size_t size);

#endif
