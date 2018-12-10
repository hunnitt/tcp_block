#include <linux/types.h>
#include <linux/socket.h>
#include <linux/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include "tcp_block.h"

void dump(const u_char * pkt, 
          int size) {
    for(int i=0; i<size; i++) {
        if (i % 16 == 0) printf("\n");
        printf("%02X ", pkt[i]);
    }
}

int get_mac(uint8_t * my_mac, 
            const char * interface) {
	int sock_fd;
	struct ifreq ifr;
    char buf[20];
    char * ptr = buf;
    memset(buf, 0, sizeof(buf));

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket error : ");
		return -1;
	}

    strcpy(ifr.ifr_name, interface);

	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl error : ");
		close(sock_fd);
		return -1;
	}
	
    sprintf((char *)buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
        (__uint8_t)ifr.ifr_hwaddr.sa_data[0],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[1],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[2],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[3],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[4],
        (__uint8_t)ifr.ifr_hwaddr.sa_data[5]);

    for(int i=0; i<6; i++) {
        char * end = ptr+2;
        my_mac[i] = (__uint8_t)strtol(ptr, &end, 16);
        ptr += 3;
    }

    close(sock_fd);
    return 0;
}

int get_ip(uint8_t * my_ip, 
           const char * interface) {
    int sock_fd;
	struct ifreq ifr;
	struct sockaddr_in * sin;
    __uint32_t ip;

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket error : ");
		return -1;
	}

	strcpy(ifr.ifr_name, interface);

	if (ioctl(sock_fd, SIOCGIFADDR, &ifr)< 0) {
		perror("ioctl error : ");
		close(sock_fd);
		return -1;
	}

	sin = (struct sockaddr_in*)&ifr.ifr_addr;
    ip = ntohl(sin->sin_addr.s_addr);

    my_ip[0] = (ip & 0xFF000000)>>24;
    my_ip[1] = (ip & 0x00FF0000)>>16;
    my_ip[2] = (ip & 0x0000FF00)>>8;
    my_ip[3] = (ip & 0x000000FF);

	close(sock_fd);
	return 0;
}

void basic_init(uint8_t * my_mac,
                uint8_t * my_ip,
                const char * interface){
    get_mac(my_mac, interface);
    get_ip(my_ip, interface);    
}

int capture_tcp_pkt(uint8_t * pkt_buf, pcap_t * handle) {
    struct libnet_ethernet_hdr * eth_hdr = (struct libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct libnet_ipv4_hdr * ipv4_hdr = (struct libnet_ipv4_hdr *)malloc(LIBNET_IPV4_H);
    struct libnet_tcp_hdr * tcp_hdr = (struct libnet_tcp_hdr *)malloc(LIBNET_TCP_H);

    uint8_t * ptr;
    int ip_len, tcp_len;
    int pkt_len = 0;
    const char * http_method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

    while(1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 0) { 
            perror("pcap_next_ex : "); 
            continue;
        }
        if (result == -1 || result == -2) { 
            perror("pcap_next_ex : "); 
            printf("please restart program\n");
            goto error;
        }
        
        // is it ipv4 packet? Or is it ipv6 packet?
        ptr = (uint8_t *)packet;
        memcpy(eth_hdr, ptr, LIBNET_ETH_H);
        if (eth_hdr->ether_type != ETHERTYPE_IP) continue;
        pkt_len += LIBNET_ETH_H;

        // is it tcp packet?
        ptr += LIBNET_ETH_H;
        memcpy(ipv4_hdr, ptr, LIBNET_IPV4_H);
        if (ipv4_hdr->ip_p != IPV4PROTO_TCP) continue;
        ip_len = ipv4_hdr->ip_hl * 4;
        pkt_len += ipv4_hdr->ip_len;

        memcpy(pkt_buf, packet, pkt_len);

        // is it http request?
        ptr += ip_len;
        for(int i=0; i<6; i++) {
            if (!strncmp((const char*)ptr, http_method[i], strlen(http_method[i]))) {
                free(eth_hdr);
                free(ipv4_hdr);
                free(tcp_hdr);
                return 2;   // http pkt
            }
        }
        break;
    }
    free(eth_hdr);
    free(ipv4_hdr);
    free(tcp_hdr);
    return 1;   // tcp pkt not http

error:
    free(eth_hdr);
    free(ipv4_hdr);
    free(tcp_hdr);
    exit(0);
}

void send_rst_pkt(uint8_t * pkt,
                  uint8_t * my_mac,
                  uint8_t * my_ip,
                  pcap_t * handle,
                  char choice) {

    struct libnet_ethernet_hdr * pkt_eth_hdr    = (struct libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct libnet_ipv4_hdr     * pkt_ipv4_hdr   = (struct libnet_ipv4_hdr *)malloc(LIBNET_IPV4_H);
    struct libnet_tcp_hdr      * pkt_tcp_hdr    = (struct libnet_tcp_hdr *)malloc(LIBNET_TCP_H);

    struct libnet_ethernet_hdr * rst_eth_hdr    = (struct libnet_ethernet_hdr *)malloc(LIBNET_ETH_H);
    struct libnet_ipv4_hdr     * rst_ipv4_hdr   = (struct libnet_ipv4_hdr *)malloc(LIBNET_IPV4_H);
    struct libnet_tcp_hdr      * rst_tcp_hdr    = (struct libnet_tcp_hdr *)malloc(LIBNET_TCP_H);

    uint8_t * rst_pkt = (uint8_t *)malloc(RST_SIZE);              // rst packet to send
    uint8_t * pkt_ptr = pkt;                                      // to copy

    // extract headers of the packet
    // init ETH
    memcpy(pkt_eth_hdr, pkt_ptr, LIBNET_ETH_H);
    pkt_ptr += LIBNET_ETH_H;

    // init IPv4 (+ extended header)
    memcpy(pkt_ipv4_hdr, pkt_ptr, LIBNET_IPV4_H);
    pkt_ptr += (pkt_ipv4_hdr->ip_hl*4);

    // init TCP
    memcpy(pkt_tcp_hdr, pkt_ptr, LIBNET_TCP_H);
    pkt_ptr += LIBNET_TCP_H;
    
    switch(choice) {
        case 'f':
            // initialize headers of the forward rst packet 
            // init ETH
            memcpy(rst_eth_hdr->ether_shost, my_mac, MAC_ADDR_LEN);
            
            // init IP
            rst_ipv4_hdr->ip_hl         = 5;
            rst_ipv4_hdr->ip_v          = 4;
            rst_ipv4_hdr->ip_tos        = 0;
            rst_ipv4_hdr->ip_len        = 40;
            rst_ipv4_hdr->ip_id         = pkt_ipv4_hdr->ip_id;
            rst_ipv4_hdr->ip_off        = 0;
            rst_ipv4_hdr->ip_ttl        = 0x64;
            rst_ipv4_hdr->ip_p          = IPPROTO_TCP;
          //rst_ipv4_hdr->ip_sum        = ip_checksum;
            rst_ipv4_hdr->ip_src        = pkt_ipv4_hdr->ip_src;
            rst_ipv4_hdr->ip_dst        = pkt_ipv4_hdr->ip_dst;
            
            // init TCP
            rst_tcp_hdr->th_sport       = pkt_tcp_hdr->th_sport;
            rst_tcp_hdr->th_dport       = pkt_tcp_hdr->th_dport;
            rst_tcp_hdr->th_seq         = pkt_tcp_hdr->th_ack;
            rst_tcp_hdr->th_ack         = pkt_tcp_hdr->th_seq;
            rst_tcp_hdr->th_off         = 5;
            rst_tcp_hdr->th_flags       = FLAGS_RST_ACK;
            rst_tcp_hdr->th_win         = pkt_tcp_hdr->th_win;
          //rst_tcp_hdr->th_sum         = tcp_checksum;
            rst_tcp_hdr->th_urp         = 0;
        break;

        case 'b':
            // 2. initialize headers of the backward rst packet
            // init ETH
            memcpy(rst_eth_hdr->ether_shost, my_mac, MAC_ADDR_LEN);
            memcpy(rst_eth_hdr->ether_dhost, pkt_eth_hdr->ether_shost, MAC_ADDR_LEN);
            
            // init IP
            rst_ipv4_hdr->ip_hl         = 5;
            rst_ipv4_hdr->ip_v          = 4;
            rst_ipv4_hdr->ip_tos        = 0;
            rst_ipv4_hdr->ip_len        = 40;
            rst_ipv4_hdr->ip_id         = pkt_ipv4_hdr->ip_id;
            rst_ipv4_hdr->ip_off        = 0;
            rst_ipv4_hdr->ip_ttl        = 0x64;
            rst_ipv4_hdr->ip_p          = IPPROTO_TCP;
          //rst_ipv4_hdr->ip_sum        = ip_checksum;
            rst_ipv4_hdr->ip_src        = pkt_ipv4_hdr->ip_dst;
            rst_ipv4_hdr->ip_dst        = pkt_ipv4_hdr->ip_src;

            
            // init TCP
            rst_tcp_hdr->th_sport       = pkt_tcp_hdr->th_dport;
            rst_tcp_hdr->th_dport       = pkt_tcp_hdr->th_sport;
            rst_tcp_hdr->th_seq         = pkt_tcp_hdr->th_ack;
            rst_tcp_hdr->th_ack         = pkt_tcp_hdr->th_seq;
            rst_tcp_hdr->th_off         = 5;
            rst_tcp_hdr->th_flags       = FLAGS_RST_ACK;
            rst_tcp_hdr->th_win         = pkt_tcp_hdr->th_win;
          //rst_tcp_hdr->th_sum         = tcp_checksum;
            rst_tcp_hdr->th_urp         = 0;m;

        break;
    }
    memcpy(rst_pkt, rst_eth_hdr, LIBNET_ETH_H);
    rst_pkt += LIBNET_ETH_H;
    memcpy(rst_pkt, rst_ipv4_hdr, LIBNET_IPV4_H);
    rst_pkt += LIBNET_IPV4_H;
    memcpy(rst_pkt, rst_tcp_hdr, LIBNET_TCP_H);



exit:
    free(pkt_eth_hdr);
    free(pkt_ipv4_hdr);
    free(pkt_tcp_hdr);
    free(rst_eth_hdr);
    free(rst_ipv4_hdr);
    free(rst_tcp_hdr);
    free(rst_pkt);
}

