#include "common.h"
#include <fcntl.h>

volatile sig_atomic_t running = 1;
struct traffic_stat tr_stat;

void exit_error(const char *err)
{
    perror(err);
    exit(EXIT_FAILURE);
}

void log_error(const char *msg) 
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stderr, "ERROR [%s]: %s: %s\n", time_buf, msg, strerror(errno));
}

void sigint_handler(int signo)
{
    (void)signo;

    static int already_handled = 0;
    if (already_handled) {
        return;
    }
    
    already_handled = 1;

    int saved_errno = errno;

    fprintf(stderr, "\n\n=== VPN STATISTICS ===\n");
    fprintf(stderr, "UDP packets sent: %d, received: %d\n",
            tr_stat.udp_packs_sent, tr_stat.udp_packs_rec);
    fprintf(stderr, "Bytes sent: %d, received: %d\n",
            tr_stat.bytes_sent, tr_stat.bytes_rec);
    fprintf(stderr, "======================\n");

    errno = saved_errno;
    exit(EXIT_SUCCESS);
}

const char *tolower_str(const char *line)
{
    unsigned int n = strlen(line);
    if (n == 0) {
        return NULL;
    }
    char *low_line = malloc(n + 1);
    if (!low_line) {
        exit_error("malloc");
    }
    
    for (unsigned int i = 0; i < n; i++)
        low_line[i] = tolower(line[i]);
    low_line[n] = 0;
    
    return low_line;
}

unsigned char *give_key(void)
{
    unsigned char *key = malloc(KEY_SIZ);
    if (!key) {
        exit_error("malloc key");
    }

    FILE *f = fopen(VPN_KEY_FILE, "rb");
    if (!f) {
        exit_error("cannot open vpn.key");
    }

    if (fread(key, KEY_SIZ, 1, f) != 1)
        exit_error("cannot read key");

    fclose(f);
    return key;
}
