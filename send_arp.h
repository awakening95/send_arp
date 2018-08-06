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

int arp_reply_attack(char* interface, char * senderIp, char * targetIp, u_char* targetMac);
u_char* get_my_mac_address(char * interface);
u_char* get_target_mac(char * interface, char * senderIp, char * targetIp);
int send_arp_req(char * interface, char * senderIp, char * targetIp);
