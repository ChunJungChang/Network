#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <net/if.h>

/* One's Complement checksum algorithm */
unsigned short cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1)
    {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

int main(int argc, char *argv[])
{
    int sock;
    char send_buf[400], recv_buf[400], src_name[256], src_ip[15], dst_ip[15];
    struct ip *ip = (struct ip *)send_buf;
    struct icmp *icmp = (struct icmp *)(ip + 1);
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in src, dst;
    struct timeval t;
    int on;
    int num = 10;
    int failed_count = 0;
    int bytes_sent, bytes_recv;
    int dst_addr_len;
    int result;
    fd_set socks;

    /* Initialize variables */
    on = 1;
    memset(send_buf, 0, sizeof(send_buf));

    /* Check for valid args */
    if (argc != 4) {
        printf("\nUsage: %s <interface> <src IP> <dst IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *intf = argv[1];
    char *src_addr = argv[2];
    char *dst_addr = argv[3];

    /* Check for root access */
    if (getuid() != 0) {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Create socket */
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("socket() error");

        /* If something wrong, just exit */
        exit(EXIT_FAILURE);
    }

    /* Set interface for socket */
    int intf_found = 0;
    struct ifreq ifr;

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs() error");
        close(sock);
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, intf, IFNAMSIZ);
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, intf) == 0) {
            if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
                perror("setsockopt() error");
                close(sock);
                exit(EXIT_FAILURE);
            }
            intf_found = 1;
            break;
        }
    }

    if (!intf_found) {
        fprintf(stderr, "Interface %s not found\n", intf);
        close(sock);
        exit(EXIT_FAILURE);
    } else {
        printf("Interface %s found\n", intf);
    }

    freeifaddrs(ifaddr);

    /* Socket options, tell the kernel we provide the IP structure */
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() for IP_HDRINCL error");
        exit(EXIT_FAILURE);
    }

    /* Get source IP address */
    /*
    if (gethostname(src_name, sizeof(src_name)) < 0) {
        perror("gethostname() error");
        exit(EXIT_FAILURE);
    } else {
        if ((src_hp = gethostbyname(src_name)) == NULL) {
            fprintf(stderr, "%s: Can't resolve, unknown source.\n", src_name);
            exit(EXIT_FAILURE);
        } else
            ip->ip_src = (*(struct in_addr *)src_hp->h_addr);
    }
    */
    inet_pton(AF_INET, src_addr, &(src.sin_addr));
    ip->ip_src = src.sin_addr;

    /* Get destination IP address */
    /*
    if ((dst_hp = gethostbyname(argv[1])) == NULL) {
        if ((ip->ip_dst.s_addr = inet_addr(argv[1])) == -1) {
            fprintf(stderr, "%s: Can't resolve, unknown destination.\n", argv[1]);
            exit(EXIT_FAILURE);
        }
    } else {
        ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
        dst.sin_addr = (*(struct in_addr *)dst_hp->h_addr);
    }
    */
    inet_pton(AF_INET, dst_addr, &(dst.sin_addr));
    ip->ip_dst = dst.sin_addr;

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));
    printf("Source IP: '%s' -- Destination IP: '%s'\n", src_ip, dst_ip);

    /* IP structure, check the ip.h */
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(send_buf));
    ip->ip_id = htons(321);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = 0;

    /* ICMP structure, check ip_icmp.h */
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = 123;
    icmp->icmp_seq = 0;

    /* Set up destination address family */
    dst.sin_family = AF_INET;

    /* Loop based on the packet number */
    for (int i = 1; i <= num; i++) {
        /* Header checksums */
        icmp->icmp_cksum = 0;
        ip->ip_sum = cksum((unsigned short *)send_buf, ip->ip_hl);
        icmp->icmp_cksum = cksum((unsigned short *)icmp,
                           sizeof(send_buf) - sizeof(struct icmp));

        /* Get destination address length */
        dst_addr_len = sizeof(dst);

        /* Set listening timeout */
        t.tv_sec = 5;
        t.tv_usec = 0;

        /* Set socket listening descriptors */
        FD_ZERO(&socks);
        FD_SET(sock, &socks);

        /* Send packet */
        if ((bytes_sent = sendto(sock, send_buf, sizeof(send_buf), 0,
                                 (struct sockaddr *)&dst, dst_addr_len)) < 0) {
            perror("sendto() error");
            failed_count++;
            printf("Failed to send packet.\n");
            fflush(stdout);
        } else {
            printf("Sent %d byte packet... ", bytes_sent);

            fflush(stdout);

            /* Listen for the response or timeout */
            if ((result = select(sock + 1, &socks, NULL, NULL, &t)) < 0) {
                perror("select() error");
                failed_count++;
                printf("Error receiving packet!\n");
            } else if (result > 0) {
                printf("Waiting for packet... ");
                fflush(stdout);

                if((bytes_recv = recvfrom(sock, recv_buf,
                     sizeof(ip) + sizeof(icmp) + sizeof(recv_buf), 0,
                     (struct sockaddr *)&dst,
                     (socklen_t *)&dst_addr_len)) < 0) {
                    perror("recvfrom() error");
                    failed_count++;
                    fflush(stdout);
                } else
                    printf("Received %d byte packet!\n", bytes_recv);
            } else {
                printf("Failed to receive packet!\n");
                failed_count++;
            }

            fflush(stdout);

            icmp->icmp_seq++;
        }
    }

    /* Display success rate */
    printf("Ping test completed with %d%% success rate.\n",
           (((num - failed_count) / num) * 100));

    /* close socket */
    close(sock);

    return 0;
}
