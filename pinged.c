#include <stdio.h>
#include <stdlib.h>         // exit() func
#include <unistd.h>         // getoopt() library
#include <sys/socket.h>     // socket library, domain arg macro(AF_INET for IPv4) and sockaddr_in struct(for Internet), \
                            // which will be casted before use into sockaddr struct, wchich shouldn't cause conflict
#include <sys/types.h>      // socket library for the sake of potrability, Linux doesnt requiere this library
#include <arpa/inet.h>      // ntoa() hton() etc.
#include <string.h>         // memset() func
#include <errno.h>          // for in case of socket fail errno gets updated
#include <netinet/ip.h>     // ip header structure and macros, netinet/in.h is also valid, INADDR_ANY = 0.0.0.0
#include <netinet/in.h>
#include <netinet/ip_icmp.h>   // icmp header structure and macros
#include <sys/select.h>     // for select() func and timeval struct for timeout in socket read or write


#define MAX_PKT_S 65535     // IP_MAXPACKET defined in netinet/ip is the same *todo*
#define MAX_PAYLOAD 1472    // to avoid packet fragmentation due to MTU over internet. 20 bytes IP header, 8 bytes ICMP header
#define CODE_DATA 20        // unused value in icmp codes of icmp ECHO type for distnguishing payload packets from nomal ICMP traffic
#define ICMPH_LEN 8         // length of icmp header


int fflag, b64flag;
struct sockaddr_in srcaddr, dstaddr;
struct icmp_pkt
{
    struct icmphdr hdr;
    char data[MAX_PAYLOAD];
};



void print_data(char *buffer, int size);
void listen_for_icmp();
void send_data(char *file_name, char *address);
unsigned short checksum(void *buffer, int length);
void usage();

int main(int argc, char *argv[])
{
     if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(1);
    }

    if (argc == 1)
    {
        listen_for_icmp();
    }
    else
    {
        int opt;
        char *file, *ip_addr;
        fflag = b64flag = 0;
        file = NULL;
        ip_addr = NULL;

        while ((opt = getopt (argc, argv, ":bf:")) != -1)
        {
            switch (opt)
            {
               case 'b':
                    b64flag = 1;
                    break;
                case 'f':
                    fflag = 1;
                    file = optarg;
                    break;
                case '?':
                    printf("Unknown option %c\n", optopt);
                    usage();
                    exit(1);
                    break;
                case ':':
                    fprintf(stderr, "Option -%c requires a path to file\n", optopt);
                    usage();
                    exit(1);
                    break;
            }
        }

        if (optind + 1 == argc)
        {
            ip_addr = argv[optind];
            printf("%s\n", ip_addr);
        }
        else
        {
            printf("Missing destination address or to many arguments\n");
            usage();
            exit(1);
        }
        send_data(file, ip_addr);
    }
    return 0;
}


void send_data(char *file_name, char *address)
{
    FILE *file = stdin;
    if(fflag)
    {
        if((file = fopen(file_name, "r")) == NULL)
        {
            fprintf(stderr, "Couldnt open %s file\nError: %s\n", file_name, strerror(errno));
            exit(1);
        }
    }

    int socket_fd;
    // by default kernel builds source part of ip header for pkt, this behaviour may be turned off with IP_HDRINCL socket option \
    // destination part is determained with sendto() supplied with sockaddr_in struck
    if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        fprintf(stderr, "Error getting socket number\nError: %s\n", strerror(errno));
        exit(1);
    }

    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    if ((inet_aton(address, &dstaddr.sin_addr)) == 0)
    {
        fprintf(stderr, "inet_aton() invalid ip address\nError: %s\n", strerror(errno));
        exit(1);
    }
    // build icmp packet including payload
    int sent_bytes, i = 0;
    struct icmp_pkt pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.type = ICMP_ECHO;
    pkt.hdr.code = CODE_DATA;
    pkt.hdr.un.echo.id = getpid();
    for (int n = sizeof(pkt.data); i < n - 1; i++)
    {
        pkt.data[i] = 'L';
    }
    pkt.data[i] = '\0';
    pkt.hdr.checksum = checksum(&pkt, sizeof(pkt));
    if ((sent_bytes = sendto(socket_fd, &pkt, sizeof(pkt), 0, &dstaddr, sizeof(dstaddr))) < 0)
    {
        fprintf(stderr, "Couldn't send packet\nError: %s\n", strerror(errno));
        exit(1);
    }
    printf("Sent %d bytes with sendto() at dst: %s\n", sent_bytes, address);


}

void listen_for_icmp()
{
    int socket_fd;

    if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)   // IPPROTO_ICMP ignores any other L3 or L4 protocols
    {
        fprintf(stderr, "Error getting socket number\nError: %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr sockaddr;
    char buffer[MAX_PKT_S];
    int pkt_size;
    socklen_t sockaddr_s = sizeof(sockaddr_s);      // recvform expects socklen_t type


    while(1)
    {
        if((pkt_size = recvfrom(socket_fd, buffer, MAX_PKT_S, 0, &sockaddr, &sockaddr_s)) < 0)   // recfrom() doesn't save source address into supplied src_addr struct as documentation pointed
        {
            fprintf(stderr, "Error recvform() func\nError: %s\n", strerror(errno));
            exit(1);
        }
        printf("Got packet of length: %d\n", pkt_size);
        // parse and print all metadata and then print data(in final print data only)
        print_data(buffer, pkt_size);
    }

}



void print_data(char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    int iph_len = iph->ihl * 4;    // length of header is stored as number of 32-bit words, resulting in number * 4 = # bytes

    memset(&srcaddr, 0, sizeof(srcaddr));
    srcaddr.sin_addr.s_addr = iph->saddr;
    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_addr.s_addr = iph->daddr;

    struct icmphdr *icmph = (struct icmphdr*)(buffer + iph_len);

    printf("Source: %s\n", inet_ntoa(srcaddr.sin_addr));
    printf("Destination: %s\n", inet_ntoa(dstaddr.sin_addr));

    printf("Type: %d\tCode: %d\n", icmph->type, icmph->code);

    if(icmph->code == CODE_DATA)
    {
        printf("Got payload ICMP\n");
        char *data = (char *)(buffer + iph_len + ICMPH_LEN);
        printf("Data: \n%s\n", data);
    }
}


unsigned short checksum(void *buffer, int length)
{
    unsigned short *buf = buffer;
    unsigned int sum;
    unsigned short result;

    for (sum = 0; length > 1; length -= 2)
    {
        sum += *buf++;
    }
    if (length == 1)
    {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}


void usage()
{
    printf("Usage: pinged [-f path] [-b] [destiantion ip]\n");
}