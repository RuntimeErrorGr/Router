#include <queue.h>
#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];
my_rtable_entry *rtable;
int rtable_size;

my_arptable_entry *arp_table;
int arp_table_len = 0;



int main(int argc, char *argv[]) {

	packet m;
	int rc;
	init(argc - 2, argv + 2);
	queue q;
	q = queue_create();

	rtable_size = count_entries(argv[1]);				// Lungime tabela rutare
	rtable = malloc(sizeof(my_rtable_entry) * rtable_size);
	DIE(!rtable, "Malloc failed");
	arp_table = malloc(sizeof(my_arptable_entry) * 100);// Lungime tabela ARP
	DIE(!arp_table, "Malloc failed");
	myRead_rtable(rtable, rtable_size, argv[1]);		// Citeste tabela rutare
	while (1) { 										// Start router
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		uint8_t* macIntAdd = malloc(sizeof(uint8_t) * ETH_ALEN);
		DIE(!macIntAdd, "Malloc failed");
		get_interface_mac(m.interface, macIntAdd);		// MAC interfata pachet
		if (ntohs(eth_hdr -> ether_type) == ARP_TYPE) {			// pachet ARP
			struct arp_header *arp_hdr = parse_arp(m.payload);
			DIE(!arp_hdr, "This packet is not ARP packet");
			if (ntohs(arp_hdr -> op) == 2) {					// ARP reply primit
				processARPReply(m, q, eth_hdr, macIntAdd);		// proceseaza
			}
			else {                                              // ARP req primit
				processARPReq(m, arp_hdr, eth_hdr, macIntAdd);	// proceseaza
			}
		}
		else if (ntohs(eth_hdr -> ether_type) == IP_TYPE) {		// pachet IP
			if (processEchoReq(m, eth_hdr, macIntAdd) == 1) {	// proceseaza
				continue;
			}				
			// verifica ttl
			if (checkTTL(m, ip_hdr, eth_hdr, macIntAdd) == 1) {
				continue;
			}
			// verifica checksum
			if (checkChecksum(ip_hdr) == 1) {
				continue;
			}
			// decrementez ttl, update checksum
			updateChecksum(ip_hdr);
			my_rtable_entry* best_route = get_best_route(htonl(ip_hdr -> daddr));
			if (best_route) {								// exista ruta
				int interface = best_route -> interface;
				memset(macIntAdd, 0, sizeof(uint8_t) * ETH_ALEN);
				get_interface_mac(interface, macIntAdd);
				my_arptable_entry* best_arp = getARPentry(ntohl(ip_hdr -> daddr));
			
				/* ARP request*/
				if (!best_arp) { 							// trimite ARP req
					sendARPReq(m, q, macIntAdd, interface, best_route);
				}
				else {										// fara ARP req
					memcpy(eth_hdr -> ether_dhost, best_arp -> mac, 6);
					memcpy(eth_hdr -> ether_shost, macIntAdd, 6);
					send_packet(interface, &m);
				}
			}
			else {										// nu exista ruta
				ICMPUnreach(macIntAdd, m, eth_hdr);		// trimite ICMP unreach
			}	
		}	
	}
}
