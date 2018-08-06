#include "send_arp.h"

int send_arp_req(char* interface, char* senderIp, char* targetIp)
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

	struct ether_header *etherHeader = (ether_header *)requestPacket;

	u_char *mac = get_my_mac_address(interface);
	if (mac == NULL) return -1;

	for(int i = 0; i < 6; i++)
	{
		etherHeader->ether_dhost[i] = 255;
		etherHeader->ether_shost[i] = mac[i];
	}

	etherHeader->ether_type = htons(ETHERTYPE_ARP); // htons()함수는 short intger(일반적으로 2byte)데이터를 네트워크 byte order로 변경
	requestPacket += sizeof(struct ether_header);
	// END : Set Ethernet header

	// START : Set ARP header
	struct ether_arp *arpHeader = (ether_arp*)requestPacket;

	arpHeader->ea_hdr.ar_hrd = htons(0x0001); // 하드웨어 주소 타입, 0x0001 == ETHERNET
	arpHeader->ea_hdr.ar_pro = htons(ETHERTYPE_IP); // 프로토콜 주소 타입
	arpHeader->ea_hdr.ar_hln = 6; // 하드웨어 주소 길이
	arpHeader->ea_hdr.ar_pln = 4; // 프로토콜 주소 길이
	arpHeader->ea_hdr.ar_op = htons(0x0001); // 패킷 종류 ARP request : 0x0001, ARP reply : 0x0002         

	for(int i = 0; i < 6; i++)
	{
		arpHeader->arp_sha[i] = mac[i]; // source(my) hardware address
		arpHeader->arp_tha[i] = 0; // destination hardware address
	}

	struct sockaddr_in senderAddr, targetAddr;
	
	if(inet_pton(AF_INET, senderIp, &senderAddr.sin_addr) == 0 || inet_pton(AF_INET, targetIp, &targetAddr.sin_addr) == 0) // convert IPv4 addresses from text to binary form
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
