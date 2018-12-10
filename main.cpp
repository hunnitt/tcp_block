#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include "tcp_block.h"

void usage(void) {
    printf("Usage  : ./tcp_block <interface>\n");
    printf("Sample : ./tcp_block ens33\n");
    exit(0);
}

int main(int argc, char * argv[]) {
    if (argc != 3) 
        usage(); 

    const char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t my_mac[6];
    uint8_t my_ip[4];

    int block_opt;
    uint8_t pkt_buf[2000];
    memset(pkt_buf, 0, sizeof(pkt_buf));

    basic_init(my_mac, my_ip, dev);

    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while(1) {
        block_opt = capture_tcp_pkt(pkt_buf, handle);
        switch(block_opt) {
            case 1:

            break;
            case 2:

            break;
            default:

        }
    }
    return 0;
}