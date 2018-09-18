#include <pcap.h>
#include <stdio.h>

void dump(const u_char * p, int len) {
	int a,i;
	int iphdrlen;
	int ipstndrd;
	int tcphdrlen;
	int hdrslen;

	printf("dump:\n");
 for(int i = 0; i < len; i++){
  printf("%02x ",*p);
  p++;
  if((i & 0x0f) == 0x0f)
   printf("\n");
 }
    p = p - len;
	printf("\n\ndst mac : ");
	for (int i = 0; i < 6; i++) {
		printf("%02x", p[i]);
		if (i == 5) break;
		printf(":");
	}
	printf("\nsrc mac : ");
	for (int i = 6; i < 12; i++) {
		printf("%02x", p[i]);
		if (i == 11) break;
		printf(":");
	}
	iphdrlen = (p[14] & 0x0f) * 4;
	ipstndrd = iphdrlen - 20;
	printf("\nsrc ip : ");
	for (int i = 26; i < 30; i++) {
		printf("%d", p[i]);
		if (i == 29) break;
		printf(".");
	}
	printf("\ndst ip : ");
	for (int i = 30; i < 34; i++) {
		printf("%d", p[i]);
		if (i == 33) break;
		printf(":");
	}

	tcphdrlen = (p[46 + ipstndrd] & 0xf0)  / 4;
	
	printf("\nsrc port : ");
	a = (p[34+ipstndrd]*256) + p[35+ipstndrd];
	printf("%d", a);
	if (a == 443) printf("(https)");
	
	printf("\ndst port : ");
	a = (p[36+ipstndrd]*256) + p[37+ipstndrd];
	printf("%d", a);
	printf("\n\n");
	
	hdrslen = 14 + iphdrlen + tcphdrlen;
	printf("additional data: ");
	i = hdrslen;
	for (; (i < len && i < hdrslen + 32); i++) {
		
		printf("%02x ", p[i]);
		if(((i-hdrslen) & 0x0f) == 0x0f)
        printf("\n");
	}
	if(i == hdrslen) printf("NULL");
	printf("\n\n");
}

int check(const u_char * p) {
	if (p[23] == 0x06)
		return 0;
	else return 1;
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
	int chk;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
	chk = check(packet);
	if (chk == 0) {
		printf("%u bytes captured\n", header->caplen);
		dump(packet, header->caplen);
	}
  }

  pcap_close(handle);
  return 0;
}

/*
1. ip header의 23번째 protocol이 tcp인 0x06을 가리키는가
2. Ethernet Header의 src mac / dst mac
dst mac : packet[0]~packet[5]
src mac : packet[6]~packet[11]
(IP인 경우) IP Header의 src ip / dst ip
src ip : packet[26]~packet[29]
dst ip : packet[30]~packet[33]
(TCP인 경우) TCP Header의 src port / dst port
src port : packet[34]~packet[35]
dst port : packet[36]~packet[37]
(Data가 존재하는 경우) 해당 Payload(Data)의 hexa decimal value(32바이트까지만)

*/
