#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include <netinet/ip.h>      
#include <netinet/ip_icmp.h> 

#define REMOTE_IP "127.0.0.1"
#define SERVER_TUN_IP_DEFAULT "10.0.0.1"
#define TUN_IP_DEFAULT "10.0.0.2"
#define REMOTE_PORT_DEFAULT 12346
#define VPN_CLI_CONF_FILE "vpn_cli.conf"

extern char remote_ip[INET_ADDRSTRLEN];
extern int remote_port;
extern char tun_ip[INET_ADDRSTRLEN];
extern char server_tun_ip[INET_ADDRSTRLEN];

uint16_t ip_checksum(void *data, int len);
int handle_icmp_echo(unsigned char *packet, int len);
void parse_line(const char *line);      
void load_config(const char *filename);

#endif
