all : send_arp

send_arp: main.o get_my_mac_address.o send_arp_req.o get_target_mac.o arp_reply_attack.o
	g++ -g -o send_arp get_my_mac_address.o send_arp_req.o get_target_mac.o arp_reply_attack.o main.o -lpcap

main.o: main.cpp send_arp.h
	g++ -g -c -o main.o main.cpp

get_my_mac_address.o: get_my_mac_address.cpp
	g++ -g -c -o get_my_mac_address.o get_my_mac_address.cpp

send_arp_req.o: send_arp_req.cpp
	g++ -g -c -o send_arp_req.o send_arp_req.cpp

get_target_mac.o: get_target_mac.cpp
	g++ -g -c -o get_target_mac.o get_target_mac.cpp

arp_reply_attack.o: arp_reply_attack.cpp
	g++ -g -c -o arp_reply_attack.o arp_reply_attack.cpp

clean:
	rm -f send_arp
	rm -f *.o

