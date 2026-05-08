#include "server.h"

int udp_fd = -1;
int udp_port = UDP_PORT_DEFAULT;
char tun_ip[INET_ADDRSTRLEN] = SERVER_ADDR_DEFAULT;
char log_file[126] = LOG_FILE;
int max_clients = MAX_PEERS_DEFAULT;
struct peer peers[MAX_PEERS_DEFAULT];
int peer_n = -1;
char ifname[IFNAMSIZ];
struct pollfd fds[MAX_PEERS_DEFAULT];
nfds_t nfds = 0;

int main(int argc, char *argv[])
{
    int utun_fd = -1;
    struct sockaddr_in udp_addr;
    unsigned char buf[65535];
    struct sigaction mask;

    if (sodium_init() < 0) exit_error("sodium_init");
    unsigned char *key = give_key();

    if ((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        exit_error("socket");

    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(udp_port);
    udp_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp_fd, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0)
        exit_error("bind");

    printf("UDP listens to 0.0.0.0:%d\n\n", udp_port);

    fds[0].fd = udp_fd;
    fds[0].events = POLLIN;
    tr_stat.udp_packs_sent = 0;
    tr_stat.udp_packs_rec = 0;
    tr_stat.bytes_sent = 0;
    tr_stat.bytes_rec = 0;

    sigemptyset(&mask.sa_mask);
    mask.sa_handler = sigint_handler;
    mask.sa_flags = 0;
    if (sigaction(SIGINT, &mask, NULL) == -1)
        exit_error("sigaction");

    load_config(VPN_SERV_CONF_FILE);

    for (;;)
    {
        int ret = poll(fds, nfds+1, -1);
        if (!running) exit(EXIT_SUCCESS);
        if (ret < 0) {
            if (errno == EINTR) continue;
            else exit_error("poll");
        }

        if (fds[0].fd == udp_fd && fds[0].revents & POLLIN) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            ssize_t nonce_len = recvfrom(udp_fd, nonce, sizeof(nonce), 0,
                                        (struct sockaddr*)&client_addr, &client_len);
            if (nonce_len != sizeof(nonce)) {
                log_error("recvfrom nonce");
                continue;
            }

            unsigned char ciphertext[65535];
            ssize_t n = recvfrom(udp_fd, ciphertext, sizeof(ciphertext), 0,
                                (struct sockaddr*)&client_addr, &client_len);
            if (n < 0) {
                log_error("recvfrom ciphertext");
                continue;
            }

            tr_stat.udp_packs_rec++;
            tr_stat.bytes_rec += n;

            unsigned char decrypted[65535];
            unsigned long long decrypted_len;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                decrypted, &decrypted_len, NULL, ciphertext, n, NULL, 0, nonce, key) != 0) {
                log_error("decryption failed");
                continue;
            }

            if (check_new_cli(client_addr) && nfds <= max_clients) {
                printf("new client! CREATE UTUN\n");
                utun_fd = create_utun_fd();
                if (utun_fd == -1) exit(EXIT_SUCCESS);
                set_ifconfig_addr();

                peer_n++;
                peers[peer_n].addr = client_addr;
                peers[peer_n].used = 1;
                peers[peer_n].utun_fd = utun_fd;
                ++nfds;
                fds[nfds].fd = utun_fd;
                fds[nfds].events = POLLIN;
            } else {
                utun_fd = find_utun_by_addr(client_addr);
                if (utun_fd == -1) {
                    fprintf(stderr, "the tunnel descriptor (utun) was not found at the address\n");
                    continue;
                }
            }

            if (write(utun_fd, decrypted, decrypted_len) != decrypted_len) {
                remove_peer(utun_fd);
                continue;
            }
        }

        for (int i = 1; i <= nfds; i++) {   
            if (!(fds[i].revents & POLLIN)) continue;
            int found = -1;
            for (int j = 0; j <= peer_n; j++) {
                if (fds[i].fd == peers[j].utun_fd) {
                    found = j;
                    break;
                }
            }
            if (found == -1) continue;

            ssize_t n = read(fds[i].fd, buf, sizeof(buf));
            if (n < 0) {
                remove_peer(peers[found].utun_fd);
                continue;
            }

            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            randombytes_buf(nonce, sizeof(nonce));
            unsigned char ciphertext[65535];
            unsigned long long ciphertext_len;

            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext, &ciphertext_len, buf, n, NULL, 0, NULL, nonce, key);

            struct sockaddr_in *client_addr = &peers[found].addr;

            sendto(udp_fd, nonce, sizeof(nonce), 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
            sendto(udp_fd, ciphertext, ciphertext_len, 0, (struct sockaddr*)client_addr, sizeof(*client_addr));

            tr_stat.udp_packs_sent++;
            tr_stat.bytes_sent += n;
        }
    }
    free(key);
    return 0;
}

int check_new_cli(struct sockaddr_in cliaddr)
{
    for (int i = 0; i <= peer_n; i++) {
        if (cliaddr.sin_addr.s_addr == peers[i].addr.sin_addr.s_addr)
            return 0;
    }
    return 1;
}

int create_utun_fd(void)
{
    int utun_fd = -1;
    int u, fd;
    struct sockaddr_ctl sc;
    socklen_t ifname_len;

    for (u = 0; u < 100; u++) {
        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) continue;

        struct ctl_info info;
        memset(&info, 0, sizeof(info));
        strcpy(info.ctl_name, "com.apple.net.utun_control");
        if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
            close(fd);
            continue;
        }

        memset(&sc, 0, sizeof(sc));
        sc.sc_family = AF_SYS_CONTROL;
        sc.sc_id = info.ctl_id;
        sc.sc_unit = u;

        if (connect(fd, (struct sockaddr*)&sc, sizeof(sc)) == 0) {
            utun_fd = fd;
            break;
        }
        close(fd);
    }

    if (utun_fd < 0) {
        fprintf(stderr, "couldn't open utun\n");
        return -1;
    }

    ifname_len = IFNAMSIZ;
    getsockopt(utun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
    printf("UTUN interface: %s\n", ifname);
    return utun_fd;
}

void set_ifconfig_addr(void)
{
    static int cli_host = 2;
    char cmd[128];
    snprintf(cmd, 126, "ifconfig %s %s 10.0.0.%d", ifname, tun_ip, cli_host++);
    system(cmd);
    printf("%s\n\n", cmd);
}

int find_utun_by_addr(struct sockaddr_in cliaddr)
{
    for (int i = 0; i <= peer_n; i++) {
        if (peers[i].used && peers[i].addr.sin_addr.s_addr == cliaddr.sin_addr.s_addr)
            return peers[i].utun_fd;
    }
    return -1;
}

void rebuild_fds(void)
{
    int n = 0;
    fds[n].fd = udp_fd;
    fds[n].events = POLLIN;
    n++;

    for (int i = 0; i <= peer_n; i++) {
        if (!peers[i].used) continue;
        fds[n].fd = peers[i].utun_fd;
        fds[n].events = POLLIN;
        n++;
    }
    nfds = n - 1;   // исправлено
}

void remove_peer(int fd)
{
    int idx = -1;
    for (int i = 0; i <= peer_n; i++) {
        if (peers[i].utun_fd == fd) {
            idx = i;
            break;
        }
    }
    if (idx == -1) return;

    close(peers[idx].utun_fd);
    peers[idx].used = 0;

    for (int j = idx; j < peer_n; j++) {
        peers[j] = peers[j+1];
    }
    peer_n--;
    rebuild_fds();
}

void parse_line(const char *line)
{
    if (strstr(line, "#")) return;
    char *p, *space, *eq;
    const char *low = tolower_str(line);
    if (!low) return;

    if (strstr(low, "udp_port")) {
        space = strrchr(low, ' '); eq = strrchr(low, '=');
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) udp_port = atoi(p+1);
    }
    if (strstr(low, "tun_ip")) {
        space = strrchr(low, ' '); eq = strrchr(low, '=');
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) strcpy(tun_ip, p+1);
    }
    if (strstr(low, "max_clients")) {
        space = strrchr(low, ' '); eq = strrchr(low, '=');
        p = (space && eq) ? (space > eq ? space : eq) : (space ? space : eq);
        if (p) max_clients = atoi(p+1);
    }
    free((void*)low);
}

void load_config(const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) { log_error("open config"); return; }

    char buf[BUF_SIZ];
    ssize_t bytes = read(fd, buf, sizeof(buf));
    close(fd);
    if (bytes <= 0) return;

    char line[BUF_SIZ];
    int pos = 0;
    for (int i = 0; i < bytes; i++) {
        if (buf[i] == '\n') {
            line[pos] = 0;
            parse_line(line);
            pos = 0;
        } else {
            line[pos++] = buf[i];
        }
    }
    if (pos > 0) {
        line[pos] = 0;
        parse_line(line);
    }
}
