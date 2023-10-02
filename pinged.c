#include <stdio.h>
#include <stdlib.h>         // exit() func
#include <unistd.h>         // getoopt() library
#include <sys/socket.h>     // socket library, domain arg macro(AF_INET for IPv4)
#include <sys/types.h>      // socket library for the sake of potrability, Linux doesnt requiere this library
#include <string.h>         // memset() func
#include <errno.h>          // for in case of socket fail errno gets updated
#include <netinet/ip.h>     // ip header structure and macros, netinet/in.h is also valid, INADDR_ANY = 0.0.0.0
#include <netinet/ip_icmp.h>   // icmp header structure and macros


#define MAX_ICMP_S 65536



void listen_for_icmp();

int main(int argc, char *argv[])
{

    if (argc == 1)
    {
        listen_for_icmp();
    }
    else
    {
        int fflag, b64flag, opt;
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
                    break;
                case ':':
                    fprintf("Option -%c requires a path to file\n", optopt);
                    break;
            }
        }
    }
    return 0;
}


void listen_for_icmp()
{
    int socket_fd;

    if((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("Error getting socket number\n");
        exit(1);
    }

    struct sockaddr_in sock_addr;
    char buffer[MAX_ICMP_S];
    int pkt_size;
    socklen_t sock_addr_s;      // recvform expect socklen_t type
    sock_addr_s = sizeof(sock_addr);

    while(1)
    {
        if((pkt_size = recvfrom(socket_fd, buffer, MAX_ICMP_S, 0, &sock_addr, &sock_addr_s)) < 0)
        {
            perror("Error recvform() func\n");
            exit(1);
        }
        printf("Got packet of length: %d\n", pkt_size);
    }
    // parse and print all metadata and then print data

}
