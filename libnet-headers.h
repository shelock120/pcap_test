#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHER_ADDR_LEN			6
#define IP_ADDR_LEN				4

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

#define IP_RF 0x8000        /* reserved fragment flag */

#define IP_DF 0x4000        /* dont fragment flag */

#define IP_MF 0x2000        /* more fragments flag */ 

#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IP_ADDR_LEN]; 
    u_int8_t ip_dst[IP_ADDR_LEN]; /* source and dest address */
};

/*
 *  IP options
 */

#define IPOPT_EOL       0   /* end of option list */

#define IPOPT_NOP       1   /* no operation */   

#define IPOPT_RR        7   /* record packet route */

#define IPOPT_TS        68  /* timestamp */

#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   

#define IPOPT_LSRR      131 /* loose source route */

#define IPOPT_SATID     136 /* satnet id */

#define IPOPT_SSRR      137 /* strict source route */



 struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */

#define TH_FIN    0x01      /* finished send data */

#define TH_SYN    0x02      /* synchronize sequence numbers */

#define TH_RST    0x04      /* reset the connection */

#define TH_PUSH   0x08      /* push data to the app layer */

#define TH_ACK    0x10      /* acknowledge */

#define TH_URG    0x20      /* urgent! */

#define TH_ECE    0x40
   
#define TH_CWR    0x80
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};