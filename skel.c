#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i) {
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}


uint16_t icmp_checksum(uint16_t *buffer, uint32_t size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size )
    {
        cksum += *(unsigned short*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}


uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}

void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
		.un.echo = {
			.id = id,
			.sequence = seq,
		}
	};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_packet(interface, &packet);
}

void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	send_packet(interface, &packet);
}

void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op)
{
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	send_packet(interface, &packet);
}

struct arp_header* parse_arp(void *buffer)
{
	struct arp_header *arp_hdr;
	struct ether_header *eth_hdr;

	eth_hdr = (struct ether_header *)buffer;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
		arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));
		return arp_hdr;
	} else
		return NULL;

}

struct icmphdr * parse_icmp(void *buffer)
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;

	eth_hdr = (struct ether_header *)buffer;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));
			if (ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr;
				icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
				return icmp_hdr;
			} else
				return NULL;


	} else
		return NULL;

}

int count_entries(char* rtableFileName) {
	FILE *rtableFile = fopen(rtableFileName, "r");
	DIE(!rtableFile, "Can't open rtable file");
	int noEntries = 0;
	while (!feof(rtableFile)) {
		char c = fgetc(rtableFile);
		if (c == '\n') {
			noEntries++;
		}
	}
	fclose(rtableFile);
	return noEntries;
}

void myRead_rtable(my_rtable_entry *rtable, int rtable_size, char* rtableFileName) {
	FILE *rtableFile = fopen(rtableFileName, "r");
	DIE(!rtableFile, "Can't open rtable file");
	char* entry = malloc(sizeof(char) * ROW_LEN);
	DIE(!entry, "Malloc failed");
	for (int i = 0; i < rtable_size; i++) {
		int nrCrt = 0;
		char row[ROW_ELEMENTS][ADDR_LEN];
		fgets(entry, ROW_LEN, rtableFile);
		char* token = strtok (entry, " ");
		while (token) {
    		strcpy(row[nrCrt], token);		
			nrCrt++;
    		token = strtok (NULL, " ");
  		}
  		rtable[i].prefix = ntohl(inet_addr(row[0]));
  		rtable[i].next_hop = ntohl(inet_addr(row[1]));
  		rtable[i].mask = ntohl(inet_addr(row[2]));
  		rtable[i].interface = atoi(row[3]);
	}
	free(entry);
	fclose(rtableFile);
}
void updateARPtable(uint32_t ip, uint8_t* mac) {
	int i;
	for (i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			break;
		}
	}
	if (i == arp_table_len) {
		arp_table[i].ip = ip;
		memcpy(arp_table[i].mac, mac, 6);
		arp_table_len ++;
	}
}

my_arptable_entry* getARPentry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == htonl(ip)) {
			return &arp_table[i];
		}
	}
	return NULL;
}

my_rtable_entry* get_best_route(uint32_t ip) {
	my_rtable_entry* aux = NULL;				// retine best route
	char first_match = 0; 				
	uint32_t max;
	for(int i = 0; i < rtable_size; i++) { 		// parcurg tabela de rutare
		uint32_t network = rtable[i].prefix;	
		uint32_t mask = rtable[i].mask;
		if ((ip & mask) == network) {			// daca ip & mask == network
			if (first_match == 0) {				// daca este prima intrare
				max = mask;						// retine masca ca max
				first_match = 1;				// retine first match
				aux = &rtable[i];				// retine intrarea din tabela
			}
			if (mask > max) {
				max = mask;						// update max
				aux = &rtable[i];				// update intrare
			}
		}
	}
	return aux;
}

void processARPReply(packet m, queue q, struct ether_header *eth_hdr, uint8_t* macIntAdd) {
	struct arp_header *new_hdr = parse_arp(m.payload);
	DIE(!new_hdr, "This packet is not ARP packet");
	updateARPtable(new_hdr -> spa, new_hdr -> sha); // update tabela ARP

	while (!queue_empty(q)) { 						// exista pachete in coada
		packet *new_m = malloc(sizeof(packet));
		new_m = (packet*)queue_deq(q);
		eth_hdr = (struct ether_header *)new_m->payload;
		memcpy(eth_hdr -> ether_dhost, new_hdr -> sha, MAC_LEN);
		memcpy(eth_hdr -> ether_shost, macIntAdd, MAC_LEN);
		send_packet(m.interface, new_m);			// trimite pachete
	}
}

void processARPReq(packet m, struct arp_header *arp_hdr, struct ether_header *eth_hdr,
uint8_t* macIntAdd) {
	updateARPtable(arp_hdr -> spa, arp_hdr -> sha); 
	uint32_t ipIntAdd = inet_addr(get_interface_ip(m.interface));
	if (arp_hdr -> tpa == ipIntAdd) { 				
		build_ethhdr(eth_hdr, macIntAdd, arp_hdr -> sha, htons(ARP_TYPE));
		send_arp(arp_hdr -> spa, arp_hdr -> tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));
	}
}

int processEchoReq(packet m, struct ether_header *eth_hdr, uint8_t* macIntAdd) {
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr;
	uint32_t destIp = ip_hdr -> saddr;
	uint32_t senderIp = inet_addr(get_interface_ip(m.interface));
	uint8_t* destMac = eth_hdr -> ether_shost;
	if (ip_hdr -> protocol == 1) {						// daca este ICMP
		icmp_hdr = parse_icmp(m.payload);				// extrage header
	}

	if (ip_hdr -> daddr == senderIp) { 					// verifica destinatia
		if (icmp_hdr -> type == 8) { 					// ECHO request
			send_icmp(destIp, senderIp, macIntAdd, destMac, 0, 0,
			m.interface, icmp_hdr -> un.echo.id, icmp_hdr -> un.echo.sequence);
			return 1;							       // trimtie ECHO reply
		}
	}
	return 0;
}

int checkTTL(packet m, struct iphdr *ip_hdr, struct ether_header *eth_hdr, uint8_t* macIntAdd) {
	uint32_t destIp = ip_hdr -> saddr;
	uint32_t senderIp = inet_addr(get_interface_ip(m.interface));
	uint8_t* destMac = eth_hdr -> ether_shost;
	if (ip_hdr -> ttl <= 1) {
		send_icmp_error(destIp, senderIp, macIntAdd, destMac, 11, 0,
		m.interface);
		return 1;
	}
	return 0;
}

int checkChecksum(struct iphdr *ip_hdr) {
	uint16_t oldCheckSum = ip_hdr -> check;
	ip_hdr -> check = 0;
	uint16_t newCheckSum = ip_checksum(ip_hdr, sizeof(struct iphdr));
	if (newCheckSum != oldCheckSum) {
		return 1;
	}
	return 0;
}

void updateChecksum(struct iphdr *ip_hdr) {
	ip_hdr -> ttl -= 1;
	ip_hdr -> check = 0;
	ip_hdr -> check = ip_checksum(ip_hdr, sizeof(struct iphdr));
}

void sendARPReq(packet m, queue q, uint8_t* macIntAdd, int interface, my_rtable_entry* best_route) {
	packet* new_m = malloc(sizeof(packet));			// copiaza pachetul initial
	memcpy(new_m, &m, sizeof(packet));
	queue_enq(q, new_m);							// introdu in coada de asteptare
					
	// constuieste un nou header pentru ARP request
	struct ether_header *new_ethdr = malloc(sizeof(struct ether_header));
	DIE(!new_ethdr, "Malloc failed");

	uint8_t* macBroadcast = malloc(sizeof(uint8_t) * ETH_ALEN);
    DIE(!new_ethdr, "Malloc failed");

	int h = hwaddr_aton("ff:ff:ff:ff:ff:ff", macBroadcast);
	DIE(h == -1, "hwaddr_aton failed");

	build_ethhdr(new_ethdr, macIntAdd, macBroadcast, htons(ARP_TYPE));
	uint32_t ipIntAdd = inet_addr(get_interface_ip(interface));
	send_arp(ntohl(best_route -> next_hop), ipIntAdd, new_ethdr, interface, htons(ARPOP_REQUEST));
}

void ICMPUnreach(uint8_t* macIntAdd, packet m, struct ether_header *eth_hdr) {
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	uint32_t destIp = ip_hdr -> saddr;
	uint32_t senderIp = inet_addr(get_interface_ip(m.interface));
	uint8_t* destMac = eth_hdr -> ether_shost;
	memset(macIntAdd, 0, sizeof(uint8_t) * ETH_ALEN);
	get_interface_mac(m.interface, macIntAdd);
	send_icmp_error(destIp, senderIp, macIntAdd, destMac, 3, 0, m.interface);
}