#define IPV4PROTO_TCP       0x06
#define IPV6PROTO_TCP       0x06
#define IPV6_HDR_LEN        40
#define EXTENDED_HDR_LEN    40
#define MAC_ADDR_LEN        6
#define IP_ADDR_LEN         4

void dump(const u_char * pkt, int size);

int get_mac(uint8_t * my_mac, const char * interface);

int get_ip(uint8_t * my_ip, const char * interface);

void basic_init(uint8_t * my_mac, uint8_t * my_ip, const char * interface);

int capture_tcp_pkt(uint8_t * pkt_buf, pcap_t * handle);


