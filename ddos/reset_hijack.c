#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>

/**
  * @brief Set packet filter to filter ACK packet only
  * @param hdlr pcap_t
  * @param target_ip
  * return 0 if success
  */
int set_packet_filter(pcap_t *hdlr, struct in_addr *target_ip);

/**
  * @brief Callback function when a packet captured
  */
void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

int main(int argc, char **argv)
{
    /* usage: reset_hijack <target IP> */

    /* Resove IP address (using libnet_name_resolve) */

    /* lookup default device (using pcap_lookupdev) */

    /* Open pcap handle (pcap_open_live) */

    /* Open raw socket and allocate memory for a packet (libnet_open_raw_sock, libnet_init_packet) */

    /* Random seed (libnet_seed_prand) */

    /* Set packet filter to filter ACK packet only (pcap_compile) */

    /* Start capture packet (pcap_loop) */

    /* Release resource */

    return 0;
}

int set_packet_filter(pcap_t *hdlr, struct in_addr *target_ip) {
    return 0;
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet)
{
    /* Build packet ip part (libnet_build_ip)*/

    /* Build packet tcp part (RESET flags enabled) (libnet_build_tcp)*/

    /* Send packet to network */ 

    /* Pause 5s */
}
