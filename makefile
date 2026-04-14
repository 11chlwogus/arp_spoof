all:
	g++ -o arp_spoof arp_spoof.c -lpcap

clean:
	rm -f arp_spoof
