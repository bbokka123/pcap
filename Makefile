#makefile
all: pcap

pcap: pcap.o
	g++ -g -o pcap pcap.o -lpcap

pcap.o:
	g++ -g -c -o pcap.o pcap.cpp

clean:
	rm -f pcap
	rm -f *.o
