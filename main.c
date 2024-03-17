#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <arpa/inet.h>
#include <string.h>

#define ETHER_ADDR_LEN          6
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define IPTYPE_TCP              0x06

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    //struct in_addr ip_src, ip_dst; /* source and dest address */
    u_int32_t ip_src, ip_dst;
};

struct tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
        th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
        th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
// 제대로 return 되면
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet; // ethernet 헤더의 시작 주소 가리킴

        int res = pcap_next_ex(pcap, &header, &packet);
        // & header : 패킷 잡힌 시간(크기), &packet(실제 패킷) : 버퍼의 시작 위치
        // packet은 1 byte
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen); // byte length

        //ETHERNET Header//
        struct ethernet_hdr *eth_hdr = packet; // packet is pointer
        // you print MAC address using pointer *eth_hdr
        if(ntohs(eth_hdr->ether_type)!= ETHERTYPE_IP)continue; // I will check IP Headers existence. IF not, return to while frist part
        printf("type : %04x\n", ntohs(eth_hdr->ether_type)); // It will print in four number
        uint8_t *p_mac_src = &(eth_hdr->ether_shost);
        printf("des MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", *p_mac_src, *(p_mac_src+1), *(p_mac_src+2), *(p_mac_src+3), *(p_mac_src+4), *(p_mac_src+5));

        uint8_t *p_mac_dst = &(eth_hdr->ether_dhost);
        printf("des MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", *p_mac_dst, *(p_mac_dst+1), *(p_mac_dst+2), *(p_mac_dst+3), *(p_mac_dst+4), *(p_mac_dst+5));

        //IP Header//

        struct ipv4_hdr *ip_hdr = packet + sizeof(struct ethernet_hdr);// eth_hdr's size is static
        if(ip_hdr->ip_p != IPTYPE_TCP)continue; // 1 byte, don't need to transfer ## 6 change to define
        printf("proto = %d\n", ip_hdr->ip_p); // print 6(ip communicate)
        uint8_t *p_src = &(ip_hdr->ip_src);
        printf("SRC IP Address : %d.%d.%d.%d\n", *p_src, *(p_src+1), *(p_src+2), *(p_src+3));
        uint8_t *p_dst = &(ip_hdr->ip_dst);
        printf("DST IP Address : %d.%d.%d.%d\n", *p_dst, *(p_dst+1), *(p_dst+2), *(p_dst+3));

        //TCP Header//
        struct tcp_hdr *tcp_hdr = packet + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr); //sizeof(struct ipv4_hdr)
        printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
        printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));

        //TCP payload//
        uint8_t *buf = packet + sizeof(struct ethernet_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);
        if (*buf == 0x00) continue;
        for (int i = 0; i < 10; i++)
        {
            if (*(buf+i) == 0x00) break;

            if(i == 0)
                printf("payload : %02x", *(buf+i));

            else
                printf(" %02x", *(buf+i));
        }
        printf("\n\n");
        *buf = 0x00;

    }

    pcap_close(pcap);
}
