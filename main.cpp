#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include<cstdlib>
#include <netinet/in.h>
#include "libnet-headers.h"

void dump(libnet_ethernet_hdr *eth_hdr, libnet_ipv4_hdr *ip_hdr, libnet_tcp_hdr * tcp_hdr, const u_char * packet) {
	int i;
	int ip_hdr_len;
	int pckt_len;
	int tcp_hdr_len;
	int data_len;
	int p;

	printf("\nSrc MAC : %02x:%02x:%02x:%02x:%02x:%02x", eth_hdr -> ether_shost[0],eth_hdr -> ether_shost[1],eth_hdr -> ether_shost[2],eth_hdr -> ether_shost[3],eth_hdr -> ether_shost[4],eth_hdr -> ether_shost[5]);
	printf("\nDst MAC : %02x:%02x:%02x:%02x:%02x:%02x", eth_hdr -> ether_dhost[0],eth_hdr -> ether_dhost[1],eth_hdr -> ether_dhost[2],eth_hdr -> ether_dhost[3],eth_hdr -> ether_dhost[4],eth_hdr -> ether_dhost[5]);
	
	ip_hdr_len = (ip_hdr -> ip_hl * 4);
	pckt_len = ip_hdr -> ip_len;
	tcp_hdr_len = (tcp_hdr -> th_off * 4);
	data_len = pckt_len - ip_hdr_len - tcp_hdr_len;
	
	printf("\nSrc IP : %d.%d.%d.%d",ip_hdr -> ip_src[0], ip_hdr -> ip_src[1], ip_hdr -> ip_src[2], ip_hdr -> ip_src[3]);
	printf("\nDst IP : %d.%d.%d.%d",ip_hdr -> ip_dst[0], ip_hdr -> ip_dst[1], ip_hdr -> ip_dst[2], ip_hdr -> ip_dst[3]);
	
	printf("\nSrc PORT : %d", tcp_hdr -> th_sport);
	printf("\nDst PORT : %d", tcp_hdr -> th_dport);
	
	printf("\nAdditional data... \n");
	if(data_len == 0) printf("NULL");
	else {
		p = sizeof(struct libnet_ethernet_hdr) + ip_hdr_len + tcp_hdr_len;
		i = data_len;
	for (int cnt = 0; (cnt < i) && (cnt < 32); p++, cnt++) {
		
		printf("%02x ", packet[p]);
		if((cnt & 0x0f) == 0x0f)
        printf("\n");
	}
	
	printf("\n\n");
	}
	
}

bool check(libnet_ethernet_hdr *eth_hdr,libnet_ipv4_hdr *ip_hdr ) {
	
	if ((ip_hdr -> ip_p == IPPROTO_TCP) && (eth_hdr -> ether_type == ETHERTYPE_IP)){
		return true;
	}
	else return false;
}
	

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  bool chk;
  struct libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr*)malloc(sizeof(libnet_ethernet_hdr));
  struct libnet_ipv4_hdr *ip_hdr = (libnet_ipv4_hdr*)malloc(sizeof(libnet_ipv4_hdr));
  struct libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr*)malloc(sizeof(libnet_tcp_hdr));

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    const u_char* p;
    p = packet;
    eth_hdr = (struct libnet_ethernet_hdr *) p;
    p += sizeof(struct libnet_ethernet_hdr);
    ip_hdr = (struct libnet_ipv4_hdr *) p;
    u_int16_t byte = eth_hdr -> ether_type;
    eth_hdr -> ether_type = ntohs(byte);
	p += ((ip_hdr -> ip_hl) * 4);
    tcp_hdr = (struct libnet_tcp_hdr *)p ;
    byte = tcp_hdr -> th_sport;
    tcp_hdr -> th_sport = ntohs(byte);
    byte = tcp_hdr -> th_dport;
    tcp_hdr -> th_dport = ntohs(byte);

    printf("%u bytes captured...\n", header->caplen);
	
	chk = check(eth_hdr, ip_hdr);
	if (chk) {

		printf("\n%u bytes captured...", header->caplen);
		dump(eth_hdr, ip_hdr, tcp_hdr, packet);

	}
  }

  pcap_close(handle);
  return 0;
}

