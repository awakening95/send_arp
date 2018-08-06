#include "send_arp.h"

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
		if(send_arp_req(interface, senderIp, targetIp) == -1) return NULL;

		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == -1 || res == -2) 
		{
			fprintf(stderr, "couldn't capture next packet\n");
			return NULL;
		}

		struct ether_header *etherHeader = (struct ether_header *)packet;
		uint16_t etherType = ntohs(etherHeader->ether_type);

		if (etherType == ETHERTYPE_ARP)
		{
			packet += sizeof(struct ether_header);

			struct ether_arp *arpHeader;
			arpHeader = (struct ether_arp *)packet;

			if(ntohs(arpHeader->ea_hdr.ar_op) == 0x0002) // ARP Reply 패킷일 경우
			{
				for(int i = 0; i < 6; i++) targetMac[i] = arpHeader->arp_sha[i]; // 패킷의 출발지 MAC 주소를 targetMac에 할당
				break;
			}
		}
	}
	pcap_close(handle);
	return targetMac;
}
