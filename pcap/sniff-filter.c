/*
 * sniff.c: live sniffing of packets with a simple  L2 analysis and filtering
 * 
 * Usage: ./sniff-filter <pcap filter>, e.g. sniff "port 80"
 *
 * Advanced rights (bpf group) required to run the application
 *
 * (c) Petr Matousek, 2023
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#define __FAVOR_BSD          // important for tcphdr structure
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <err.h>

#ifdef __linux__            // for Linux
#include <netinet/ether.h> 
#include <time.h>
#include <pcap/pcap.h>
#define ETHERTYPE_LLDP 0x88cc
struct ether_vlan_header {
        uint8_t evl_dhost[ETHER_ADDR_LEN];
        uint8_t evl_shost[ETHER_ADDR_LEN];
        uint16_t evl_encap_proto;
        uint16_t evl_tag;
        uint16_t evl_proto;
} __packed;
#endif

#ifdef __APPLE__           // for MacOS
struct ether_vlan_header {
        uint8_t evl_dhost[ETHER_ADDR_LEN];
        uint8_t evl_shost[ETHER_ADDR_LEN];
        uint16_t evl_encap_proto;
        uint16_t evl_tag;
        uint16_t evl_proto;
} __packed;
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define ETHERNET_HEADER (14)     // offset of Ethernet header
#define IPV6_HEADER (40)         // length of IPv6 header
#define VLAN_HEADER (4)          // length of IEEE 802.1q header

int n = 0;

/*
 *  analyze_tcp() - receives a pointer to the TCP header; extracts, and prints selected TCP headers
 * 
 */
void analyze_tcp(const u_char *packet){     // see TH_ definitions in /usr/include/netinet/tcp.h
  const struct tcphdr *my_tcp;
  my_tcp = (const struct tcphdr*) packet;
  printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
  if (my_tcp->th_flags & TH_SYN)           
    printf(", SYN");
  if (my_tcp->th_flags & TH_FIN)
    printf(", FIN");
  if (my_tcp->th_flags & TH_RST)
    printf(", RST");
  if (my_tcp->th_flags & TH_PUSH)
    printf(", PUSH");
  if (my_tcp->th_flags & TH_ACK)
    printf(", ACK");
  printf("\n");
  return;
}

/*
 *  analyze_udp() - receives a pointer to the UDP header; extracts, and prints selected UDP headers
 * 
 */
void analyze_udp(const u_char *packet){ // see /usr/include/netinet/udp.h
  const struct udphdr *my_udp;

  my_udp = (const struct udphdr*) packet;
  printf("\tSrc port = %d, dst port = %d, UDP length = %d B\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
  return;
}

/*
 *  analyze_icmp() - receives a pointer to the ICMPv4 header; extracts, and prints selected ICMP headers
 * 
 */
void analyze_icmp(const u_char *packet){ // see /usr/include/netinet/ip_icmp.h
  const struct icmp *my_icmp;

  my_icmp = (const struct icmp *) packet;
  switch (my_icmp->icmp_type){
  case ICMP_ECHOREPLY:
    printf("\tICMP type = %u (ECHO REPLY)",my_icmp->icmp_type);
    break;
  case ICMP_UNREACH:
    printf("\tICMP type = %u (DESTINATION UNREACHABLE)",my_icmp->icmp_type);
    break;
  case ICMP_ECHO:
    printf("\tICMP type = %u (ECHO)",my_icmp->icmp_type);
    break;
  case ICMP_TIMXCEED:
    printf("\tICMP type = %u (TIME EXCEEDED)",my_icmp->icmp_type);
	  break;
  default:
    printf("\tICMP type = %u",my_icmp->icmp_type);
    break;
	}
  printf(", ICMP code = %u\n",my_icmp->icmp_code);
  return;
}

/*
 *  analyze_ip() - receives a pointer to the IPv4 header; extracts, and prints selected IP headers
 * 
 */
void analyze_ip(const u_char *packet){    // see /usr/include/netinet/ip.h
  u_int header_len;                       // IPv4 header length
  struct ip* my_ip;

  my_ip = (struct ip*) (packet);
  header_len = my_ip->ip_hl*4;            // compute IP4 header length
  printf("\tIP: id 0x%x, hlen = %d bytes, version %d, IP length = %d bytes, TTL = %d\n",ntohs(my_ip->ip_id),header_len,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
  printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
  printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));
      
  switch (my_ip->ip_p){                         // see IPPROTO_ definitions in /usr/include/netinet/in.h
  case IPPROTO_ICMP:   // ICMP protocol = 1
    printf(", protocol = %d (ICMP)\n",my_ip->ip_p);
    analyze_icmp(packet + header_len);          // move the pointer to the beginning of ICMP header
	break;
  case IPPROTO_IGMP:   // IGMP protocol = 2
    printf(", protocol = %d (IGMP)\n",my_ip->ip_p);
    break;
  case IPPROTO_TCP:    // TCP protocol =  6
    printf(", protocol = %d (TCP)\n",my_ip->ip_p);
    analyze_tcp(packet + header_len);           // move the pointer to the beginning of TCP header
    break;
  case IPPROTO_UDP:    // UDP protocol = 17
    printf(", protocol = %d (UDP)\n",my_ip->ip_p);
    analyze_udp(packet + header_len);           // move the pointer to the beginning of UDP header
    break;
  default: 
    printf(", protocol %d\n",my_ip->ip_p);
  }
  return;
}

/*
 *  analyze_ip6() - receives a pointer to the IPv6 header; extracts, and prints selected IP headers
 * 
 */
// void analyze_ip6(const u_char* packet){   // see /usr/include/netinet/ip6.h
void analyze_ip6(const u_char* packet){
  char buf6[INET6_ADDRSTRLEN]; 
  uint16_t ip6_len;
  struct ip6_hdr *my_ip6;                    // pointer to the IPv6 datagram

  my_ip6 = (struct ip6_hdr*) (packet);
  if (inet_ntop(AF_INET6,&my_ip6->ip6_src,buf6,INET6_ADDRSTRLEN) != NULL)  // extract src IPv6 address
    printf("\tIPv6 src = %s, ",buf6);
  else {
    perror("inet_ntop");
    exit(EXIT_FAILURE);
  }
  if (inet_ntop(AF_INET6,&my_ip6->ip6_dst,buf6,INET6_ADDRSTRLEN) != NULL)  // extract dst IPv6 address
    printf("IPv6 dst = %s",buf6);
  else {
    perror("inet_ntop");
    exit(EXIT_FAILURE);
  }
  ip6_len = ntohs(my_ip6->ip6_plen);                   // extract IPv6 payload length
  printf("\n\tIPv6 payload = %d bytes",ntohs(my_ip6->ip6_plen));
  switch(my_ip6->ip6_nxt){                             // analyze IPv6 next header field
  case IPPROTO_UDP:    // UDP protocol = 17
    printf(", next header = %d (UDP)\n",my_ip6->ip6_nxt);
    analyze_udp(packet + IPV6_HEADER);                 // move the pointer to the beginning of UDP header
    break;
  case IPPROTO_TCP:    // TCP protocol = 6
    printf(", next header = %d (TCP)\n",my_ip6->ip6_nxt);
    analyze_tcp(packet + IPV6_HEADER);
    break;
  case IPPROTO_ICMPV6: // ICMPv6 protocol = 58
    printf(", next header = %d (ICMPv6)\n",my_ip6->ip6_nxt);
    break;
  default:             // remaining IPv6 next headers
    printf(", next header = %d\n",my_ip6->ip6_nxt);
    break;
  }
  return;
}

// mypcap_handle() is a function that processes captured packets
// the function is called by pcap_loop()
void mypcap_handle(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ether_header *eptr;          // Ethernet header
  struct ether_vlan_header *my_vlan;  // 802.1q VLAN header - see /usr/include/net/ethernet.h
  pcap_t *handle;                     // file handle

  n++;
  // print the packet header data
  printf("Packet no. %d:\n",n); 
  printf("\tPacket length = %d bytes, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  
    
  // read the Ethernet header
  eptr = (struct ether_header *) packet;
  printf("\tSource MAC = %s, ",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
  printf("Destination MAC = %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;
  
  switch (ntohs(eptr->ether_type)){               // see /usr/include/net/ethernet.h for types
  case ETHERTYPE_IP:    // IPv4 = 0x0800
    printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(eptr->ether_type));
    analyze_ip(packet+ETHERNET_HEADER);           // skip the Ethernet header
    break;
  case ETHERTYPE_IPV6:  // IPv6 = 0x86DD
    printf("\tEthernet type = 0x%04x (IPv6 packet)\n",ntohs(eptr->ether_type));
    analyze_ip6(packet+ETHERNET_HEADER);          // skip the Ethernet header
    break; 
  case ETHERTYPE_ARP:  // ARP = 0x0806
    printf("\tEthernet type  = 0x%04x (ARP packet)\n",ntohs(eptr->ether_type));
    break;
  case ETHERTYPE_VLAN: // VLAN 802.1q = 0x8100
    my_vlan = (struct ether_vlan_header *) packet;
    printf("\tEthernet type = 0x%04x (VLAN encapsulation), VLAN ID = %d, Protocol = 0x%04x\n",ntohs(eptr->ether_type),ntohs(my_vlan->evl_tag), ntohs(my_vlan->evl_proto));
    switch (ntohs(my_vlan->evl_proto)){           // analyze encapsulated protocols following VLAN tag
    case ETHERTYPE_IP:
      printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(my_vlan->evl_proto));
      analyze_ip(packet+ETHERNET_HEADER+VLAN_HEADER);      // skip Ethernet and 802.1q headers
      break;
    case ETHERTYPE_IPV6:
      printf("\tEthernet type = 0x%04x (IPv4 packet)\n", ntohs(my_vlan->evl_proto));
      analyze_ip6(packet+ETHERNET_HEADER+VLAN_HEADER);     // skip Ethernet and 802.1q headers
      break;
    case ETHERTYPE_ARP:
      printf("\tEthernet type = 0x%04x (ARP packet)\n",ntohs(my_vlan->evl_proto));
      break;
    default:
      printf("\tEthernet type = 0x%04x\n",ntohs(my_vlan->evl_proto));
      break;
    }
    break;
  case ETHERTYPE_LLDP: // Link Layer Discovery Protocol
    printf("\tEthernet type = 0x%04x (LLDP frame)\n",ntohs(eptr->ether_type));
    break;
  default:             // other L2 protocols
    printf("\tEthernet type = 0x%04x (not an IP packet)\n", ntohs(eptr->ether_type));
  }
}

int main(int argc, char *argv[]){
  char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
  pcap_t *handle;                 // packet capture handle 
  pcap_if_t *alldev, *dev ;       // a list of all input devices
  char *devname;                  // a name of the device
  struct in_addr a,b;
  bpf_u_int32 netaddr;            // network address configured at the input device
  bpf_u_int32 mask;               // network mask of the input device
  struct bpf_program fp;          // the compiled filter

  if (argc != 2)
    errx(1,"Usage: %s <pcap filter>", argv[0]);

  // open the input devices (interfaces) to sniff data
  if (pcap_findalldevs(&alldev, errbuf))
    err(1,"Can't open input device(s)");

  // list the available input devices
  printf("Available input devices are: ");
  for (dev = alldev; dev != NULL; dev = dev->next){
    printf("%s ",dev->name);
  }
  printf("\n");

  devname = alldev->name;  // select the name of first interface (default) for sniffing 
  
  // get IP address and mask of the sniffing interface
  if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1)
    err(1,"pcap_lookupnet() failed");

  a.s_addr=netaddr;
  printf("Opening interface \"%s\" with network number %s,",devname,inet_ntoa(a));
  b.s_addr=mask;
  printf("mask %s for listening...\n",inet_ntoa(b));

  // open the interface for live sniffing
  if ((handle = pcap_open_live(devname,BUFSIZ,1,1000,errbuf)) == NULL)
    err(1,"pcap_open_live() failed");

  // compile the filter
  if (pcap_compile(handle,&fp,argv[1],0,netaddr) == -1)
    err(1,"pcap_compile() failed");
  
  // set the filter to the packet capture handle
  if (pcap_setfilter(handle,&fp) == -1)
    err(1,"pcap_setfilter() failed");

  // read packets from the interface in the infinite loop (count == -1)
  // incoming packets are processed by function mypcap_handle() 
  if (pcap_loop(handle,-1,mypcap_handle,NULL) == -1)
    err(1,"pcap_loop() failed");

  // close the capture device and deallocate resources
  pcap_close(handle);
  pcap_freealldevs(alldev);
  return 0;
}
