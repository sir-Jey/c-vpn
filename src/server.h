#ifndef SERVER_H
#define SERVER_H

#include "common.h"

#define UDP_PORT_DEFAULT 12346
#define MAX_PEERS_DEFAULT 256
#define SERVER_ADDR_DEFAULT "10.0.0.1"
#define VPN_SERV_CONF_FILE "vpn_serv.conf"
#define LOG_FILE "/var/log/vpn.log"

struct peer {
    struct sockaddr_in addr;
    int utun_fd;
    int used;
};

extern int udp_fd;
extern int udp_port;
extern char tun_ip[INET_ADDRSTRLEN];
extern char log_file[126];
extern int max_clients;
extern struct peer peers[MAX_PEERS_DEFAULT];
extern int peer_n;
extern char ifname[IFNAMSIZ];
extern struct pollfd fds[MAX_PEERS_DEFAULT];
extern nfds_t nfds;

int check_new_cli(struct sockaddr_in cliaddr);
int create_utun_fd(void);
void set_ifconfig_addr(void);
int find_utun_by_addr(struct sockaddr_in cliaddr);
void rebuild_fds(void);
void remove_peer(int fd);
void parse_line(const char *line);     
void load_config(const char *filename);

#endif
