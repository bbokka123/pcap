#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  
  char* dev = argv[1];  //옵션 1: 네트웍 디바이스 이름을 인자로 넘겨준다.
  //char *dev=pcap_lookupdev(errbuf); //옵션 2:사용중인 네트웍 디바이스 이름을 얻어온다.
  char errbuf[PCAP_ERRBUF_SIZE];
  if(dev == NULL){
	  printf("%s\n", errbuf);
	  exit(1);
  }
  // 네트웍 디바이스 이름 출력
  printf("DEV: %s\n",dev);

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  //descriptor를 생성한다. 3 번째 인자 1은 promiscuous mode로 로컬네트웍의
  //모든 패킷을 캡처한다. 
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    //header packet값을 통해 패킷 정보를 얻어온다.
    if(res==0) continue;
    if(res == -1 || res == -2) break;
    printf("%u bytes captured\n",header->caplen);

    int count =1 ;
    int length= header ->len;
    
    struct ether_header *ethh;
    uint16_t ether_type;   
    ethh = (struct ether_header *)packet;
    printf("Src ether addr:");
    for(int i=0; i<5;i++){
    printf("%02x:",ethh->ether_shost[i]);
    }	
    printf("%02x\n",ethh->ether_shost[5]);
    printf("Dst ether addr:");
    for(int i=0; i<5; i++){
    printf("%02x:",ethh->ether_dhost[i]);
    }
    printf("%02x\n",ethh->ether_dhost[5]);

    packet += sizeof(struct ether_header);
    
    ether_type = ntohs(ethh->ether_type);
    
    if(ether_type == ETHERTYPE_IP)
    {
	    struct ip *iph;
	    iph=(struct ip *)packet;
	    printf("IP packet\n");
	    printf("Src Address: %s\n", inet_ntoa(iph->ip_src));
	    printf("Dst Address: %s\n", inet_ntoa(iph->ip_dst));
    if(iph->ip_p==IPPROTO_TCP){
	    struct tcphdr *tcph;
	    packet += sizeof(struct ip);
	    tcph = (struct tcphdr*)packet;
	    printf("<TCP information>\n");
	    printf("source port : %u\n", ntohs(tcph->source));
	    printf("destination port : %u\n",ntohs(tcph->dest));
    }
    }
    while(length--){
	   printf("%02x",*(packet++));
	   if((++count)==16) {printf("\n"); break;} 
    }
    	    
    
    	
  printf("====================\n");  
  }
    
  pcap_close(handle);
  return 0;
}
