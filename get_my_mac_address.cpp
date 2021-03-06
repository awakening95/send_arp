#include "send_arp.h"

u_char* get_my_mac_address(char* interface)
{
	struct ifreq ifr;
	memset(&ifr, 0x00, sizeof(ifr)); // ifr 초기화
	strcpy(ifr.ifr_name, interface);

	int sock=socket(AF_UNIX, SOCK_DGRAM, 0); // 소켓 생성, AF_UNIX : 같은 시스템 내에서 프로세스 끼리 통신, SOCK_DGRAM : UDP/IP 프로토콜 이용
 
	if(sock < 0)
	{
		perror("socket ");
		return NULL;
	}

	if(ioctl(sock, SIOCGIFHWADDR,&ifr) < 0) // 디바이스 io 제어 함수, SIOCGIFHWADDR를 통해 하드웨어 주소를 얻어 ifr.ifr_hwaddr.sa_data에 할당
	{
		perror("ioctl ");
		return NULL;
	}
 
	u_char* mac = (u_char*)ifr.ifr_hwaddr.sa_data;
	shutdown(sock, SHUT_RD); // 입력스트림 종료
	return mac;
}
