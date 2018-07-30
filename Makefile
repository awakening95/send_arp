all : send_arp

send_arp: main.o
	g++ -g -o send_arp main.o -lpcap

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -f send.arp
	rm -f *.o

