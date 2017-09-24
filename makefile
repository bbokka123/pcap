#makefile
all: pcap

pcap: pcap.cpp
	gcc -o pcap pcap.cpp -lpcap

