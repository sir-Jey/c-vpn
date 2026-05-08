CC = gcc
CFLAGS = -Wall -Wextra -O2 -lsodium -std=gnu99

all: vpn_server vpn_client

vpn_server: common.o server.o
	$(CC) $(CFLAGS) -o vpn_server common.o server.o

vpn_client: common.o client.o
	$(CC) $(CFLAGS) -o vpn_client common.o client.o

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c

server.o: server.c server.h common.h
	$(CC) $(CFLAGS) -c server.c

client.o: client.c client.h common.h
	$(CC) $(CFLAGS) -c client.c

clean:
	rm -f *.o vpn_server vpn_client
