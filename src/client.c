#include "client.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/fcntl.h>

char remote_ip[INET_ADDRSTRLEN] = REMOTE_IP;
int remote_port = REMOTE_PORT_DEFAULT;
char tun_ip[INET_ADDRSTRLEN] = TUN_IP_DEFAULT;
char server_tun_ip[INET_ADDRSTRLEN] = SERVER_TUN_IP_DEFAULT;

int main(void)
{
    int utun_fd, sfd;
    struct ctl_info ctlInfo;
    struct sockaddr_ctl sc;
    char ifname[IFNAMSIZ];
    socklen_t ifname_len;
    char cmd[256];
    struct sockaddr_in addr, remote_addr;
    unsigned char packet[65536];
    struct pollfd fds[2];
    struct sigaction mask;
    int ret;

    if (sodium_init() < 0) {
      exit_error("sodium_init");
    }
  
    unsigned char *key = give_key();

    utun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (utun_fd == -1) {
        exit_error("socket utun");
    }

    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strncpy(ctlInfo.ctl_name, "com.apple.net.utun_control", sizeof(ctlInfo.ctl_name)-1);

    if (ioctl(utun_fd, CTLIOCGINFO, &ctlInfo) == -1) {
        exit_error("ioctl");
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_family = AF_SYS_CONTROL;
    sc.sc_unit = 0;
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);

    if (connect(utun_fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
        exit_error("connect utun");
    }

    ifname_len = IFNAMSIZ;
    if (getsockopt(utun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == -1) {
        exit_error("getsockopt");
    }

    printf("utun %s create!\n", ifname);

    snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s up", ifname, tun_ip, server_tun_ip);
    system(cmd);

    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        exit_error("socket udp");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_aton("0.0.0.0", &addr.sin_addr);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        exit_error("bind");
    }

    printf("the udp socket is bound to the address 0.0.0.0:12345\n\n");

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);
    inet_aton(remote_ip, &remote_addr.sin_addr);

    fds[0].fd = utun_fd;
    fds[0].events = POLLIN;
    fds[1].fd = sfd;
    fds[1].events = POLLIN;

    tr_stat.udp_packs_sent = 0;
    tr_stat.udp_packs_rec = 0;
    tr_stat.bytes_sent = 0;
    tr_stat.bytes_rec = 0;

    sigemptyset(&mask.sa_mask);
    mask.sa_handler = sigint_handler;
    mask.sa_flags = 0;
    
    if (sigaction(SIGINT, &mask, NULL) == -1) {
        exit_error("sigaction");
    }

    load_config(VPN_CLI_CONF_FILE);

    for (;;)
    {
        ret = poll(fds, 2, -1);
        if (ret < 0) 
        {
            if (errno == EINTR) {
                continue;
            } else {
                exit_error("poll");
            }
        }

        /* TUN - > Network */
        if (fds[0].revents & POLLIN)
        {
            ssize_t n = recv(utun_fd, packet, sizeof(packet), 0);
            if (n == -1) {
                exit_error("recv tun");
            }

            if (handle_icmp_echo(packet, (int)n)) {
                write(utun_fd, packet, n);
                continue;
            }

            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            randombytes_buf(nonce, sizeof(nonce));

            unsigned char ciphertext[4096];
            unsigned long long ciphertext_len;

            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext, 
                &ciphertext_len,
                packet, 
                n, 
                NULL, 
                0, 
                NULL, 
                nonce, 
                key);

            if (sendto(sfd, nonce, sizeof(nonce), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1) {
                log_error("sendto nonce");
            }
            
            if (sendto(sfd, ciphertext, ciphertext_len, 0,
                       (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
                log_error("sendto ciphertext");

            tr_stat.udp_packs_sent++;
            tr_stat.bytes_sent += n;
        }

        /* Network - > TUN */
        if (fds[1].revents & POLLIN)
        {
            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            unsigned char ciphertext[4096];
            unsigned char decrypted[4096];
            unsigned long long decrypted_len;
            
            ssize_t n;

            if (recvfrom(sfd, nonce, sizeof(nonce), 0, NULL, NULL) == -1) {
                    log_error("recvfrom nonce");
            }
            
            n = recvfrom(sfd, ciphertext, sizeof(ciphertext), 0, NULL, NULL);
            if (n < 0) {
                continue;
            }

            tr_stat.udp_packs_rec++;
            tr_stat.bytes_rec += n;

            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                decrypted, &decrypted_len, NULL,
                ciphertext, n, NULL, 0, nonce, key) != 0) 
            {
                continue;
            }

            if (send(utun_fd, decrypted, decrypted_len, 0) == -1) {
                log_error("send to tun");
            }
        }
    }

    free(key);
    exit(EXIT_SUCCESS);
}

/* ICMP Echo Reply */
uint16_t ip_checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = data;
    
    while (len > 1) 
    {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

int handle_icmp_echo(unsigned char *packet, int len)
{
    struct ip *ip = (struct ip*)packet;
    int ip_len = ip->ip_hl * 4;

    if (ip->ip_p != IPPROTO_ICMP) {
        return 0;
    }

    struct icmp *icmp = (struct icmp*)(packet + ip_len);
    
    if (icmp->icmp_type != ICMP_ECHO) {
        return 0;
    }

    printf("ICMP echo request от %s\n", inet_ntoa(ip->ip_src));

    struct in_addr tmp = ip->ip_src;
    
    ip->ip_src = ip->ip_dst;
    ip->ip_dst = tmp;

    icmp->icmp_type = ICMP_ECHOREPLY;

    ip->ip_sum = 0;
    ip->ip_sum = ip_checksum(ip, ip_len);

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ip_checksum(icmp, len - ip_len);

    return 1;
}

void parse_line(const char *line)
{
    if (strstr(line, "#")) {
        return;
    }

    const char *low = tolower_str(line);
    
    if (!low) {
        return;
    }

    char *p;
    char *space; 
    char *eq;

    if (strstr(low, "remote_ip")) 
    {
        space = strrchr(low, ' ');
        eq = strrchr(low, '=');
        
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) {
            strcpy(remote_ip, p + 1);
        }
    }
    
    if (strstr(low, "remote_port")) {
        space = strrchr(low, ' ');
        eq = strrchr(low, '=');
        
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) {
            remote_port = atoi(p + 1);
        }
    }
    
    if (strstr(low, "tun_ip")) {
        space = strrchr(low, ' ');
        eq = strrchr(low, '=');
        
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) {
            strcpy(tun_ip, p + 1);
        }
    }
    
    if (strstr(low, "server_tun_ip")) {
        space = strrchr(low, ' ');
        eq = strrchr(low, '=');
        
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) {
            strcpy(server_tun_ip, p + 1);
        }
    }

    free((void*)low);
}

void load_config(const char *filename)
{
    int fd;
    char buf[BUF_SIZ];
    ssize_t bytes;
    char line[BUF_SIZ];
    int i;
    int pos;
    
    fd = open(filename, O_RDONLY);
    if (fd == -1) 
    {
        log_error("open config");
        return;
    }

    bytes = read(fd, buf, sizeof(buf));
    close(fd);
    
    if (bytes <= 0) {
        return;
    }

    pos = 0;
    for (i = 0; i < bytes; i++) {
        if (buf[i] == '\n') 
        {
            line[pos] = 0;
            parse_line(line);
            pos = 0;
        } else {
            line[pos++] = buf[i];
        }
    }
    if (pos > 0) 
    {
        line[pos] = 0;
        parse_line(line);
    }
}
