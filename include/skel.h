#pragma once
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include "queue.h"
#include "list.h"
/* 
 *Note that "buffer" should be at least the MTU size of the 
 * interface, eg 1500 bytes 
 */
#define MAX_LEN 1600
#define ROW_ELEMENTS 4
#define ADDR_LEN 15
#define ROW_LEN 50
#define MAC_LEN 6 * sizeof(uint8_t)
#define ROUTER_NUM_INTERFACES 3
#define ARP_TYPE 0x0806
#define IP_TYPE 0x0800

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[%d]: %s\n", __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

typedef struct {
	int len;
	char payload[MAX_LEN];
	int interface;
} packet;

/*My routing table entry struct*/
typedef struct {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} my_rtable_entry;

/*My arp table entry struct*/
typedef struct {
	uint32_t ip;
	uint8_t mac[ETH_ALEN];
} my_arptable_entry;

/* Ethernet ARP packet from RFC 826 */
struct arp_header {
	uint16_t htype;   /* Format of hardware address */
	uint16_t ptype;   /* Format of protocol address */
	uint8_t hlen;    /* Length of hardware address */
	uint8_t plen;    /* Length of protocol address */
	uint16_t op;    /* ARP opcode (command) */
	uint8_t sha[ETH_ALEN];  /* Sender hardware address */
	uint32_t spa;   /* Sender IP address */
	uint8_t tha[ETH_ALEN];  /* Target hardware address */
	uint32_t tpa;   /* Target IP address */
} __attribute__((packed)); 

extern int interfaces[ROUTER_NUM_INTERFACES];
extern my_rtable_entry *rtable;
extern int rtable_size;
extern int arp_table_len;
extern my_arptable_entry* arp_table;
/**
 * @brief 
 * 
 * @param interface interface to send packet on
 * @param m packet
 * @return int 
 */
int send_packet(int interface, packet *m);
/**
 * @brief Get the packet object
 * 
 * @param m 
 * @return int 
 */
int get_packet(packet *m);

/**
 * @brief Get the interface ip object
 * 
 * @param interface 
 * @return char* 
 */
char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object
 * 
 * @param interface 
 * @param mac 
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief 
 * 
 * @param argc 
 * @param argv 
 */
void init(int argc, char *argv[]);

/**
 * @brief 
 * 
 */
void parse_arp_table();

/**
 * @brief 
 * 
 * @param daddr destination IP
 * @param saddr source IP
 * @param sha source MAC
 * @param dha destination MAC
 * @param type Type
 * @param code Code
 * @param interface interface 
 * @param id id
 * @param seq sequence
 */
void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq);


/**
 * @brief 
 * 
 * @param daddr destination IP
 * @param saddr source IP
 * @param sha source MAC
 * @param dha destination MAC
 * @param type Type
 * @param code Code
 * @param interface interface 
 */
void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface);


/**
 * @brief 
 * 
 * @param daddr destination IP address
 * @param saddr source IP address
 * @param eth_hdr ethernet header
 * @param interface interface
 * @param arp_op ARP OP: ARPOP_REQUEST or ARPOP_REPLY
 */
void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op);
/**
 * @brief 
 * 
 * @param buffer 
 * @return struct icmphdr* A pointer to a structure of type icmphdr that is inside the buffer. Basically, we return the
 * icmp header from buffer.
 * If this is not an ICMP packet, we return NULL.
 */
struct icmphdr * parse_icmp(void *buffer);

/**
 * @brief 
 * 
 * @param buffer 
 * @return struct arp_header* A pointer to a structure of type arp_header that is inside the buffer. Basically, we return the
 * arp header from buffer.
 * If this is not an ARP frame, we return NULL.
 */
struct arp_header* parse_arp(void *buffer);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type);

uint16_t icmp_checksum(uint16_t *buffer, uint32_t size);

uint16_t ip_checksum(void* vdata,size_t length);

/*
* La primirea unui ARP reply, ARP cache este updatat, adaugand o noua intrare de
* forma ip - mac.
*/
void updateARPtable(uint32_t ip, uint8_t* mac);

/**
* Numara intrarile dintr-o tabela de rutare data ca fisier text.
*/
int count_entries(char* rtableFileName);

/*
* Returneaza intrarea corespunzatoare unei anumite adrese ip din tabela ARP.
*/
my_arptable_entry* getARPentry(uint32_t ip);

/**
* Parseaza tabela de rutare intr-o reprezentare interna
*/
void myRead_rtable(my_rtable_entry *rtable, int rtable_size, char* rtableFileName);

/*
* Returneaza ruta corespunzatoare pe baza LPM din tabela de rutare.
*/
my_rtable_entry* get_best_route(uint32_t ip);

/**
* La primirea unui ARP reply, tabela ARP este updatata si se proceseaza toate
* pachetele care sunt in asteptare in coada spre trimitere.
*/
void processARPReply(packet m, queue q, struct ether_header *eth_hdr, uint8_t* macIntAdd);

/**
* La primirea unui ARP request, se verifica destinatia pachetului. Daca acesta
* este destinat routerului, se trimite un ARP reply cu adresa MAC a interfetei
* routerului care a primit pachetul initial.
*/
void processARPReq(packet m, struct arp_header *arp_hdr, struct ether_header *eth_hdr, uint8_t* macIntAdd);

/**
* La primirea unui echo request se verifica destinatia pachetului. Daca acesta
* este destinat routerului se trimite un mesaj echo reply. Altfel se arunca 
* pachetul.
*/
int processEchoReq(packet m, struct ether_header *eth_hdr, uint8_t* macIntAdd);

/**
* Se verifica campul time to live al pachetului ip primit. Daca este <= 1,
* pachetul se arunca. 
*/
int checkTTL(packet m, struct iphdr *ip_hdr, struct ether_header *eth_hdr, uint8_t* macIntAdd);

/**
* Se verifica checksumul unui pachet. Daca noul checksum difera de cel vechi,
* pachetul se arunca.
*/
int checkChecksum(struct iphdr *ip_hdr);

/**
* Se decrementeaza campul time to live al unui pachet la trecerea printr-un hop
* si se calculeaza noul checksum.
*/
void updateChecksum(struct iphdr *ip_hdr);

/**
* Se construieste un nou pachet ARP request cu adresa MAC broadcast 
* ff:ff:ff:ff:ff:ff si se trimite la next hopul indicat de intrarea din tabela
* de rutare.
*/
void sendARPReq(packet m, queue q, uint8_t* macIntAdd, int interface, my_rtable_entry* best_route);

/**
* In cazul in care nu exista o intrare in tabela de rutare prin care sa se poata
* dirija un pachet, se trimite catre vechiul destinatar un mesaj icmp destination
* unreachable. 
*/
void ICMPUnreach(uint8_t* macIntAdd, packet m, struct ether_header *eth_hdr);