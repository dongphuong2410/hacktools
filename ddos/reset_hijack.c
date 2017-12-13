#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include <pcap/pcap.h>

typedef struct _cb_data
{
    libnet_t *lnet;
    libnet_ptag_t *ptag;
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
    char lnet_errbuf[LIBNET_ERRBUF_SIZE];

    /* Open network interface */
    libnet_t *lnet = libnet_init(LIBNET_RAW4, NULL, lnet_errbuf);
    if (!lnet) {
        fprintf(stderr, "Error init libnet interface %s\n", lnet_errbuf);
        exit(EXIT_FAILURE);
    }

    /* Resove IP address */
    u_long target_ip = libnet_name2addr4(lnet, argv[2], LIBNET_RESOLVE);
    if (target_ip == -1) {
        fprintf(stderr, "Error resolve target ip %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    char *dev = argv[1];
    char pcap_errbuf[PCAP_ERRBUF_SIZE];

    /* Open pcap handle (pcap_open_live) */
    pcap_t *hdlr = pcap_open_live(dev, 1024, 1, 1000, pcap_errbuf);
    if (!hdlr) {
        fprintf(stderr, "Error open pcap  handler %s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }


    /* Random seed */
    libnet_seed_prand(lnet);

    /* Set packet filter to filter ACK packet only */
    struct in_addr target;
    target.s_addr = target_ip;
    set_packet_filter(hdlr, argv[2]);

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
    printf("caught packet\n");
    /* Build packet ip part (libnet_build_ip)*/

    /* Build packet tcp part (RESET flags enabled) (libnet_build_tcp)*/

    /* Send packet to network */ 

    /* Pause 5s */
}
