#include <stdio.h>
#include <unistd.h>


int main(int argc, char *argv[])
{

    if (argc == 1)
    {
        /* listen_for_icmp(); */
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
                    printf("Option -%c requires a path to file\n", optopt);
                    break;
            }
        }
    }
    return 0;
}
