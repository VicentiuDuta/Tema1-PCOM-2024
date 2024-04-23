#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct route_table_entry *rtable;
int rtable_size;

struct arp_table_entry *arp_table;
int arp_table_size;

queue q;

int cmpfunc (const void *a, const void *b) {
	struct route_table_entry *route1 = (struct route_table_entry *) a;
	struct route_table_entry *route2 = (struct route_table_entry *) b;

	//Daca prefixele sunt diferite, sortam descrescator in functie de prefix
	if(route1->prefix != route2->prefix)
		return route2->prefix - route1->prefix;
	//Daca prefixele sunt egale, sortam descrescator in functie de masca
	return route2->mask - route1->mask;

}

struct arp_table_entry *get_arp_entry(uint32_t ip) {
	if(arp_table == NULL)
		return NULL;
	int i;
	for(i = 0; i < arp_table_size; i++)
		if(arp_table[i].ip == ip)
			return &arp_table[i];

	//Daca nu am gasit adresa MAC in tabela ARP, returnam NULL		
	return NULL;
}


struct route_table_entry* find_route_eficient (uint32_t ip_dest) {
	int left = 0;
	int right = rtable_size - 1;
	struct route_table_entry *best_route = NULL;

	while(left <= right) {
		int mid = (left + right) / 2;
		uint32_t masked_dest_ip = ip_dest & rtable[mid].mask;

		if(masked_dest_ip == rtable[mid].prefix) {
			best_route = &rtable[mid];	
			right = mid - 1;
		}
		else if(masked_dest_ip > rtable[mid].prefix) {
			right = mid - 1;
		}
		else {
			left = mid + 1;
		}


	}
	return best_route;
}
 
void send_ICMP_err(char* buf, size_t len, int interface, uint8_t icmp_type, uint8_t icmp_code) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	
	//Construim un nou pachet
	char* new_packet = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(uint64_t));
	
	//Construim noul header Ethernet
	struct ether_header *new_eth_hdr = (struct ether_header *) new_packet;
	memcpy(&new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(&new_eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	new_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	//Construim noul header IP
	struct iphdr *new_ip_hdr = (struct iphdr *) (new_packet + sizeof(struct ether_header));
	new_ip_hdr->tos = 0;
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->ttl = 64;
	new_ip_hdr->protocol = IPPROTO_ICMP;
	new_ip_hdr->id = htons(1);

	new_ip_hdr->daddr = htonl(ip_hdr->saddr);
	new_ip_hdr->saddr = htonl(ip_hdr->daddr);
	uint16_t new_tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(uint64_t);
	new_ip_hdr->tot_len = htons(new_tot_len);
	new_ip_hdr->check = 0;
	new_ip_hdr->check = checksum((uint16_t *) new_ip_hdr, sizeof(struct iphdr));

	//Construim noul header ICMP
	struct icmphdr *new_icmp_hdr = (struct icmphdr *) (new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	new_icmp_hdr->type = icmp_type;
	new_icmp_hdr->code = icmp_code;
	new_icmp_hdr->checksum = 0;

	//Construim payload-ul
	memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));
	memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr), buf, sizeof(uint64_t));
	//Calculam checksum-ul ICMP-ului
	new_icmp_hdr->checksum = htons(checksum((uint16_t *) new_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(uint64_t)));

	//Trimitem pachetul
	send_to_link(interface, new_packet, new_tot_len + sizeof(struct ether_header));
	//Eliberam memoria
	free(new_packet);
}

void forward_packet_IP (char* buf, size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	//Daca TTL-ul este mai mic sau egal cu 1, aruncam pachetul si trimitem un pachet ICMP TIME_EXCEEDED catre expeditorul pachetului
	if(ip_hdr->ttl <= 1) {
		send_ICMP_err(buf, len, interface, 11, 0);
		return;
	}
	//Daca TTL-ul este > 1, il decrementam si recalculam checksum-ul
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	uint16_t new_checksum = ntohs (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
	ip_hdr->check = new_checksum;

	//Cautam ruta cea mai buna pentru pachet
	struct route_table_entry *best_route = find_route_eficient(ip_hdr->daddr);
	//Daca nu am gasit ruta, trimitem un pachet ICMP DESTINATION_UNREACHABLE catre expeditorul pachetului
	if(best_route == NULL) {
		send_ICMP_err(buf, len, interface, 3, 0);
		return;
	}

	//Cautam adresa MAC a urmatorului hop
	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
	//Daca nu am gasit adresa MAC, trimitem un pachet ARP REQUEST
	if(arp_entry == NULL) {
		//Adaugam pachetul in coada
		queue_enq(q, buf);
		//Construim pachetul ARP REQUEST
		char* new_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
		struct ether_header *new_eth_hdr = (struct ether_header*) new_packet;
		new_eth_hdr->ether_type = htons(ETHERTYPE_ARP);
		//Adresa MAC sursa va fi adresa MAC a interfetei din best_route
		get_interface_mac(best_route->interface, new_eth_hdr->ether_shost);
		//Adresa MAC destinatie va fi adresa MAC de broadcast
		memset(new_eth_hdr->ether_dhost, 0xff, sizeof(new_eth_hdr->ether_dhost));

		//Construim header-ul ARP
		struct arp_header *new_arp_hdr = (struct arp_header*) (new_packet + sizeof (struct ether_header));
		new_arp_hdr->htype = htons(1); 
		new_arp_hdr->ptype = htons(ETHERTYPE_IP);
		new_arp_hdr->hlen = 6; 
		new_arp_hdr->plen = 4; 
		new_arp_hdr->op = htons(1); 
		get_interface_mac(best_route->interface, new_arp_hdr->sha);
		new_arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
		//Adresa MAC destinatie va fi 0
		memset(new_arp_hdr->tha, 0, sizeof(new_arp_hdr->tha));
		//Adresa IP destinatie va fi adresa IP a urmatorului hop
		new_arp_hdr->tpa = best_route->next_hop;

		//Trimitem pachetul
		send_to_link(best_route->interface, new_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
		return;
	}
	
	//Setam adresa MAC sursa si destinatie
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));

	//Trimitem pachetul
	send_to_link(best_route->interface, buf, len);
 
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(100000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);

	//Sortam tabela de rutare in ordine descrescatoare dupa masca
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmpfunc);

	//Alocam memorie pentru tabela ARP
	arp_table = NULL;
	arp_table_size = 0;

	//Initializam coada
	q = queue_create();


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			//Verificam checksum-ul
			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t new_checksum = ntohs (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

			//Daca nu este corect, aruncam pachetul
			if (old_checksum != new_checksum) {
				continue;
			}

			ip_hdr->check = htons (new_checksum);
			
			//Verificam daca adresa IP destinatie este adresa IP a routerului
			uint32_t dest_ip = ip_hdr->daddr;
			char* router_ip = get_interface_ip(interface);
			uint32_t router_ip_INT = inet_addr(router_ip);

			//Daca adresele IP coincid, aruncam pachetul
			if (dest_ip == router_ip_INT) {
				if(ip_hdr->protocol == IPPROTO_ICMP) {
				//Verificam daca pachetul este de tip ICMP
					struct icmphdr *icmp_hdr = (struct icmphdr*) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
					//Verificam daca pachetul este de tip ECHO REQUEST
					if(icmp_hdr->type == 8 && icmp_hdr->code == 0) {
						if(ip_hdr->ttl <= 1) {
							//Daca TTL-ul este mai mic sau egal cu 1, trimitem un pachet ICMP TIME_EXCEEDED catre expeditorul pachetului
							send_ICMP_err(buf, len, interface, 11, 0);
						}
						else {
							//Construim pachetul de tip ECHO_REPLY
							uint32_t aux = ip_hdr->saddr;
							ip_hdr->saddr = ip_hdr->daddr;
							ip_hdr->daddr = aux;
							//Setam type-ul pe 0 si recalculam checksum-ul
							icmp_hdr->type = 0;
							icmp_hdr->checksum = 0;
							icmp_hdr->checksum = ntohs(checksum ((uint16_t *) icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));

							//Trimitem pachetul
							send_to_link(interface, buf, len);
						}
					}
					//Daca pachetul nu este de tip ECHO REQUEST, aruncam pachetul
					else
						continue;
				}
				//Daca nu este ICMP, aruncam pachetul
				else {
					forward_packet_IP(buf, len, interface);
					continue;
				}

			}
			//Daca adresele IP nu coincid, forwardam pachetul
			else {
                forward_packet_IP(buf, len, interface);
				continue;
			}

		}
		//Daca pachetul este de tip ARP
		else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			//verificam daca pachetul este de tip ARP REQUEST
			if(ntohs(arp_hdr->op) == 1) {
				uint32_t arp_dest_ip = arp_hdr->tpa;
				char* router_ip = get_interface_ip(interface);
				uint32_t router_ip_INT = inet_addr(router_ip);
				
				//Verificam daca adresa IP destinatie este a routerului
				if(arp_dest_ip == router_ip_INT) {
					//Construim pachetul ARP REPLY
					char* new_packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
					//Initializam header-ul Ethernet
					struct ether_header *new_eth_hdr = (struct ether_header *) new_packet;
					//Inversam adresele MAC
					memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
					get_interface_mac(interface, new_eth_hdr->ether_shost);
					new_eth_hdr->ether_type = htons(ETHERTYPE_ARP);
					//Initializam header-ul ARP
					struct arp_header *new_arp_hdr = (struct arp_header *) (new_packet + sizeof(struct ether_header));
					new_arp_hdr->htype = htons(1); 
					new_arp_hdr->ptype = htons(ETHERTYPE_IP); 
					new_arp_hdr->hlen = 6;
					new_arp_hdr->plen = 4; 
					new_arp_hdr->op = htons(2); 
					//Inversam adresele MAC
					memcpy(new_arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));
					get_interface_mac(interface, new_arp_hdr->sha);
					//Inversam adresele IP
					new_arp_hdr->tpa = arp_hdr->spa;
					new_arp_hdr->spa = inet_addr(get_interface_ip(interface));
					//Trimitem pachetul
					send_to_link(interface, new_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
					continue;
				}
				else
					continue;
			}
			//Verificam daca pachetul este de tip ARP REPLY
			else if(ntohs(arp_hdr->op) == 2) {
				//Adaugam adresa MAC in tabela ARP
				arp_table = realloc(arp_table, (arp_table_size + 1) * sizeof(struct arp_table_entry));
				arp_table_size++;
				arp_table[arp_table_size - 1].ip = arp_hdr->spa;
				memcpy(arp_table[arp_table_size - 1].mac, arp_hdr->sha, sizeof(arp_hdr->sha));

				//Verificam daca avem pachete in coada si incercam sa le trimitem
				while(!queue_empty(q)) {
					char* packet = queue_deq(q);
					struct iphdr *ip_hdr = (struct iphdr *) (packet + sizeof(struct ether_header));
					forward_packet_IP(packet, sizeof(struct ether_header) + ip_hdr->tot_len, interface);
				}
				continue;
			}
			else
				continue;
		}
		else
			continue;

	}
}

