#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <wchar.h>
#include <stdint.h>
#include <threads.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <syslog.h>
#include <dirent.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <utime.h>
#include <sodium.h>
#include <fcntl.h> 
#include <limits.h>
#include <locale.h>
#include <sodium/randombytes_internal_random.h>

#define BUF_SIZ (1024 * 4)
#define KEY_SIZ crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define VPN_KEY_FILE "vpn.key"

extern volatile sig_atomic_t running;
extern struct traffic_stat tr_stat;

struct traffic_stat {
    int udp_packs_sent;
    int udp_packs_rec;
    int bytes_sent;
    int bytes_rec;
};

void exit_error(const char *err);
void log_error(const char *msg);
void sigint_handler(int signo);
const char *tolower_str(const char *line);
unsigned char *give_key(void);

#endif
