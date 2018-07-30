#include "send_arp.h"

void usage() 
{
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char * argv[])
{	
	if (argc != 4)
	{
		usage();
		return -1;
	}

	u_char* targetMac = get_target_mac(argv[1], argv[2], argv[3]);
	if (targetMac == NULL)
		return -1;

	int attack = arp_reply_attack(argv[1], argv[2], argv[3], targetMac);
	if (attack == 0)
	{
		printf("Attack success\n");
		return 0;
	}
	else
	{
		printf("Attack fail\n");
		return -1;
	}
}
