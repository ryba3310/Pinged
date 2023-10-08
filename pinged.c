#include <stdio.h>
#include <stdlib.h>         // Exit() func
#include <unistd.h>         // Getoopt() library
#include <sys/socket.h>     // Socket library, domain arg macro(AF_INET for IPv4) and sockaddr_in struct(for Internet), \
                            // Which will be casted before use into sockaddr struct, wchich shouldn't cause conflict
#include <sys/types.h>      // Socket library for the sake of potrability, Linux doesnt requiere this library
#include <arpa/inet.h>      // Ntoa() hton() etc.
#include <string.h>         // Memset() func
#include <errno.h>          // For in case of socket fail errno gets updated
#include <netinet/ip.h>     // Ip header structure and macros, netinet/in.h is also valid, INADDR_ANY = 0.0.0.0
#include <netinet/in.h>
#include <netinet/ip_icmp.h>   // Icmp header structure and macros
#include <sys/time.h>       // For timeval struct
#include <sys/select.h>     // For select() func for timeout in socket read or write
#include "helpers.h"        // Usage() verbose() base64 func


#define MAX_PKT_S 65535     // IP_MAXPACKET defined in netinet/ip is the same *todo*
#define MAX_PAYLOAD 1472    // To avoid packet fragmentation due to MTU over internet. 20 bytes IP header, 8 bytes ICMP header
#define MAX_B64 1104        // Maximum payload read for base64 encoidng to fit into icmp packet
#define CODE_DATA 20        // Unused value in icmp codes of icmp ECHO type for distnguishing payload packets from nomal ICMP traffic
#define CODE_DATA_END 21    // Indicates end of transmisios for target host, EOT signal could be defined as data_len < max_payload, but it omits case with total data length as max_payload
#define ICMPH_LEN 8         // Length of icmp header
#define IP_ICMP_S 28        // Total length of ip header + icmp header


struct sockaddr_in srcaddr, dstaddr;
struct icmp_pkt
{
    struct icmphdr hdr;
    char data[];    // Flexible array member introduced in C99
};

int fflag = 0, b64flag = 0;

int print_data(const char *buffer, int size);
void listen_for_icmp();
void send_data(char *file_name, char *address);
unsigned short checksum(void *buffer, int length);


int main(int argc, char *argv[])
{
     if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(1);
    }

    int opt;
    char *file, *ip_addr;
    fflag = b64flag = 0;
    file = NULL;
    ip_addr = NULL;

    while ((opt = getopt (argc, argv, ":bf:v")) != -1)
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
            case 'v':
                set_verbose(1);
                break;
            case '?':
                fprintf(stderr, "Unknown option %c\n", optopt);
                usage();
                exit(1);
                break;
            case ':':
                fprintf(stderr, "Option -%c requires a path to file\n", optopt);
                usage();
                exit(1);
                break;
            default:
                usage();
                exit(1);
        }
    }
    verbose("Flags: f = %d with argument = %s\tb = %d\t v = 1\n", fflag, file, b64flag);
    // optind value at start is 1, it gose first through all the switch '-' arguments and if there are non-options arguments it is less thna argc which indicates non-option argument
    if (optind + 1 == argc)
    {
        ip_addr = argv[optind];
        verbose("Destination address is: %s\n", ip_addr);
        send_data(file, ip_addr);
    }
    else
    {
        if (b64flag || fflag)
        {
            fprintf(stderr, "Wrong options for listening\n");
            usage();
            exit(1);
        }
        listen_for_icmp();
    }
    return 0;
}


void send_data(char *file_name, char *address)
{
    FILE *file = stdin;
    if (fflag)
    {
        if ((file = fopen(file_name, "r")) == NULL)
        {
            fprintf(stderr, "Couldnt open %s file\nError: %s\n", file_name, strerror(errno));
            exit(1);
        }
    }
    // Setting socket and timeout on recvfrom()
    int socket_fd;
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    // By default kernel builds source part of ip header for pkt, this behaviour may be turned off with IP_HDRINCL socket option \
    // Destination part is determained with sendto() supplied with sockaddr_in struck
    if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        fprintf(stderr, "Error getting socket number\nError: %s\n", strerror(errno));
        exit(1);
    }
    // Setting timeout for recvfrom() at socket level instead of select() which is suited for multiple socket fds
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        fprintf(stderr, "setsockopt error\nError: %s\n", strerror(errno));
    }

    // Set dst ip address for sendto()
    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    if ((inet_aton(address, &dstaddr.sin_addr)) == 0)
    {
        fprintf(stderr, "inet_aton() invalid ip address\nError: %s\n", strerror(errno));
        exit(1);
    }
    // Build icmp packet including payload
    int sent_bytes, bytes_read;
    socklen_t src_sockaddr_s = sizeof(srcaddr);      // Recvfrom() expects socklen_t type
    socklen_t dst_sockaddr_s = sizeof(dstaddr);      // Sendto() expects socklen_t type
    struct icmp_pkt *pkt;
    char buffer[MAX_PAYLOAD];
    char reply_buffer[MAX_PKT_S];

    while ((bytes_read = fread(&buffer, 1, b64flag ? MAX_B64 : MAX_PAYLOAD, file)) > 0)
    {
        verbose("Read bytes: %d\n", bytes_read);
        if (b64flag)
        {
            verbose("Encoding data into base64\n");
            char *encoded = encode_b64(buffer, bytes_read);
            bytes_read = strlen(encoded);
            verbose("Encoded length: %d\nEncoded data: %s\n", bytes_read, encoded);
            memset(buffer, 0, MAX_PAYLOAD);
            memcpy(buffer, encoded, bytes_read);
            free(encoded);      // encode_b64 allocates memory on heap becouse data length may vary
        }
        pkt = malloc(sizeof(struct icmp_pkt) + bytes_read);   // Flexible array member
        pkt->hdr.type = ICMP_ECHO;
        pkt->hdr.code = feof(file) ? CODE_DATA_END : CODE_DATA;    // If its end of payload to transmit, it is indicated insied icmp header for receiver
        pkt->hdr.un.echo.id = getpid();  // Not mandatory, but provides information to kernel for incoming reyply
        memcpy(pkt->data, buffer, bytes_read);
        pkt->hdr.checksum = checksum(&pkt, sizeof(struct icmp_pkt) + bytes_read);    // Setting checksum after the whole packet is assembled
        // Wait for reply packet and resend in case of no reply which indicates target didn't receive payload
        do
        {
            if ((sent_bytes = sendto(socket_fd, pkt, sizeof(struct icmp_pkt) + bytes_read, 0, (struct sockaddr *)&dstaddr, dst_sockaddr_s)) < 0)
            {
                fprintf(stderr, "Couldn't send packet\tError: %s\n", strerror(errno));
                exit(1);
            }
            verbose("Sent %d bytes with sendto() at dst: %s\n", sent_bytes, address);
            // Set sockaddr_in struct for every reacvfrom()
            /* memset(&srcaddr, 0, sizeof(srcaddr)); */
            if (recvfrom(socket_fd, reply_buffer, MAX_PKT_S, 0, (struct sockaddr *)&srcaddr, &src_sockaddr_s) < 0)
            {
                fprintf(stderr, "Error receiving packet\tError: %s\n", strerror(errno));
            }
            timeout.tv_sec = 2;     // Reinitialization is necessary after every call to recvfrom beacouse internal implementation stores elapsed time after every call
            timeout.tv_usec = 0;
        } while (srcaddr.sin_addr.s_addr != dstaddr.sin_addr.s_addr);
        verbose("Got reply\nSource: %s\tsock_addr_s: %d\t", inet_ntoa(srcaddr.sin_addr), src_sockaddr_s);
        verbose("%s received %d bytes in reply\n", inet_ntoa(srcaddr.sin_addr), strlen(reply_buffer));
        memset(buffer, 0, MAX_PAYLOAD);
        memset(reply_buffer, 0, MAX_PAYLOAD);
    }
    free(pkt);
    return;
}


void listen_for_icmp()
{
    int socket_fd;

    if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)   // IPPROTO_ICMP ignores any other L3 or L4 protocols
    {
        fprintf(stderr, "Error getting socket number\nError: %s\n", strerror(errno));
        exit(1);
    }

    char buffer[MAX_PKT_S];
    int pkt_size;
    socklen_t sockaddr_s = sizeof(srcaddr);      // Recvfrom expects socklen_t type

    while (1)
    {
        if ((pkt_size = recvfrom(socket_fd, buffer, MAX_PKT_S, 0, (struct sockaddr*)&srcaddr, &sockaddr_s)) < 0)
        {
            fprintf(stderr, "Error Recvfrom() func\nError: %s\n", strerror(errno));
            exit(1);
        }
        char reply[IP_ICMP_S];
        memcpy(reply, buffer, IP_ICMP_S);
        if (sendto(socket_fd, buffer, IP_ICMP_S, 0, (struct sockaddr *)&srcaddr, sockaddr_s) < 0)
        {
            fprintf(stderr, "Couldn't send packet\tError: %s\n", strerror(errno));
            exit(1);
        }
        // Parse and print all metadata and then print data(in final print data only)
        if (print_data(buffer, pkt_size) == CODE_DATA_END)
        {
            break;
        }
        memset(buffer, 0, MAX_PKT_S);
    }
    return;
}



int print_data(const char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    int iph_len = iph->ihl * 4;    // Length of header is stored as number of 32-bit words, resulting in number * 4 = # bytes
    // No need to set source address, recvfrom() does it, only dst address needs to be initilized, but set anyway for clarity and consistency
    memset(&srcaddr, 0, sizeof(srcaddr));
    srcaddr.sin_addr.s_addr = iph->saddr;
    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_addr.s_addr = iph->daddr;

    struct icmphdr *icmph = (struct icmphdr*)(buffer + iph_len);
    char *data = (char *)(buffer + iph_len + ICMPH_LEN);
    int data_len = strlen(data);
    verbose("Source: %s\n", inet_ntoa(srcaddr.sin_addr));
    verbose("Destination: %s\n", inet_ntoa(dstaddr.sin_addr));
    verbose("Type: %d\tCode: %d\n", icmph->type, icmph->code);

    if (icmph->code == CODE_DATA)
    {
        verbose("Got payload ICMP\n");
        verbose("Length of data: %d\n Last char: %d\n", data_len, data[data_len]);
        verbose("Data:\n");
        printf("%s", data);
        fflush(stdout);     // Data sent to stoud without '\n' char at the end needs to be explicitly flushed beacouse the stream is line buffered
        verbose("\n");
    }
    else if(icmph->code == CODE_DATA_END)
    {
        verbose("Got last payload ICMP\n");
        verbose("Length of data: %d\n Last char: %d\n", data_len, data[data_len]);
        verbose("Data:\n");
        printf("%s", data);
        fflush(stdout);     // Data sent to stoud without '\n' char at the end needs to be explicitly flushed beacouse the stream is line buffered
        verbose("\n");
        return CODE_DATA_END;
    }
    return data_len;
}






