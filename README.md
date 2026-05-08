# VPN Server & Client

This project implements a full VPN tunnel between a client and a server.  
The client creates a `utun` virtual interface, routes all its traffic through it, and sends it to the server over UDP.  
The server accepts connections from multiple clients, creates a separate `utun` for each one, forwards traffic, and provides internet access.

**The project is written in C, uses libsodium for encryption (ChaCha20-Poly1305), and runs on macOS (with minor changes required for Linux).**

---

## How It Works

The client opens a `utun` interface, assigns it an IP address (e.g., `10.0.0.2`), and sends all traffic through an encrypted UDP tunnel to the server.  
The server receives a packet, identifies which client it came from (by IP and port), creates a new `utun` for a new client (e.g., `utun5` with IP `10.0.0.1`), and forwards the traffic.

<img width="789" height="336" alt="Screenshot 2026-05-08 at 18 40 27" src="https://github.com/user-attachments/assets/cd1616b7-1c79-4a02-9bcd-f1151ceaa33f" />

---

## Dependencies

- macOS  
- `libsodium` (for encryption)

### Installing libsodium on macOS

```bash
brew install libsodium
```

**Only libsodium is required for compilation. Everything else is built-in.**

---

## Build

```bash
make          # builds both server and client
make server   # builds only the server
make client   # builds only the client
make clean    # removes compiled files
```

---

## Key Generation (Required)

Both the client and the server must use the **same 32-byte key**.

You can generate the key using a separate program or with the following code:

```c
#include <sodium.h>
// ...
unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
crypto_aead_xchacha20poly1305_ietf_keygen(key);
FILE *f = fopen("vpn.key", "wb");
fwrite(key, sizeof(key), 1, f);
fclose(f);
```

Then copy the resulting `vpn.key` file to both the client and the server.

---

## Configuration

Copy the `vpn_serv.conf` and `vpn_cli.conf` files to the directory with the binaries.

### Example `vpn_serv.conf`

```
UDP_PORT = 12346
TUN_IP = 10.0.0.1
MAX_CLIENTS = 256
LOG_FILE = /var/log/vpn.log
```

### Example `vpn_cli.conf`

```
REMOTE_IP = 127.0.0.1
REMOTE_PORT = 12346
TUN_IP = 10.0.0.2
SERVER_TUN_IP = 10.0.0.1
```

<img width="282" height="124" alt="Screenshot 2026-05-08 at 18 42 39" src="https://github.com/user-attachments/assets/779b1f0d-95e8-4b5d-b08c-f9544f7ee176" />

<img width="295" height="124" alt="Screenshot 2026-05-08 at 18 42 48" src="https://github.com/user-attachments/assets/c9c6a94e-505b-40bb-a9d2-38d250e306b7" />

---

## Running

### Server

```bash
sudo ./bin/vpn_server
```

The server will listen on the UDP port specified in the configuration file and create TUN interfaces as clients connect.

<img width="435" height="284" alt="Screenshot 2026-05-08 at 18 43 44" src="https://github.com/user-attachments/assets/5212ac37-cdb8-46ae-8b00-31ef888a130a" />

### Client

```bash
sudo ./bin/vpn_client
```

The client will connect to the server, create its own `utun` interface, and route all its traffic through the tunnel.

<img width="443" height="238" alt="Screenshot 2026-05-08 at 18 44 48" src="https://github.com/user-attachments/assets/3d6dedd4-6021-4680-a8f5-f1d520f56263" />

---

## Technical Explanation (Tutorial Section)

### 1. Why UDP Instead of TCP

TCP inside TCP causes problems: packet loss triggers retransmission at both the inner and outer levels, leading to delays and confusion. UDP is simpler, faster, and does not interfere.

### 2. What Is TUN

TUN is a virtual network interface at Layer 3 (IP). When a program writes to it, the kernel processes the IP packet as if it came from the network. Conversely, packets routed to the TUN interface can be read by the program.

### 3. How the Client Forces All Traffic Through the VPN

After startup, the client creates a TUN interface and adds a default route through it:

```bash
route add default 10.0.0.2
```

Now every packet not destined for the local network goes into the TUN interface.

### 4. How the Handshake Works

The client sends the first UDP packet (this can be regular encrypted traffic).  
The server receives a packet from an unknown address, creates a new TUN for that client, and assigns it an IP address from the internal network.  
All subsequent packets from that client are directed into its dedicated TUN interface.

### 5. Why There Is No `listen`/`accept`

UDP is connectionless. Each datagram arrives independently, and the server does not need to establish a persistent connection. It only needs to remember the sender’s address.

### 6. How Routing Works on the Server

For each client, the server creates a separate TUN interface and assigns an IP address (typically `10.0.0.1` for the server and `10.0.0.x` for the client).  
The kernel automatically creates a route to the client. Internet access may require masquerading (NAT), but this project focuses only on tunneling.

### 7. A Note on `select` and `poll`

Network operations must not block each other. The program uses `poll` (or `select`) to monitor multiple file descriptors at once:

- TUN for incoming packets from the kernel.
- UDP socket for incoming packets from the remote peer.

---

## Control

Press `Ctrl+C` to stop the program. It will close the TUN interface and display statistics showing how many bytes and packets were transferred.

---

## Project Structure

```
vpn/
├── vpn_server          
├── vpn_client          
├── vpn.key             (shared secret key, 32 bytes)
├── vpn_serv.conf
├── vpn_cli.conf
├── common.h / common.c
├── server.h / server.c
└── client.h / client.c
```

---

## Testing

From the client, ping the server’s tunnel IP address:

```bash
ping 10.0.0.1
```

You should receive replies.

<img width="443" height="238" alt="Screenshot 2026-05-08 at 18 44 48" src="https://github.com/user-attachments/assets/af830c45-ecd1-45cf-9d69-50798f1c2788" />

---

## References

- [Silence on the Wire by Michal Zalewski](https://lcamtuf.coredump.cx/) (main inspiration for passive analysis)
- [Beej’s Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Linux TUN/TAP documentation](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- libsodium documentation

---

## Notes

- To run this project on Linux, replace the `socket(PF_SYSTEM, ...)` calls with `open("/dev/net/tun", ...)`.  
- The project uses ChaCha20-Poly1305 from libsodium, a modern and fast encryption algorithm.  
- This is an educational implementation, not optimized for high performance or production use.
