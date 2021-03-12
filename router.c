#include "skel.h"
#include "queue.h"

int interfaces[ROUTER_NUM_INTERFACES];
struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

//functia cauta in in tabela de routare best route
struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *best = NULL;
	
	for(int i = 0; i <= rtable_size; i++){
		
		int x = dest_ip & rtable[i].mask;
		
		if(x == rtable[i].prefix){
			if(best == NULL){
				best = &rtable[i];
			}
			else if(best->mask < rtable[i].mask){
				best = &rtable[i];
			}
		}
	}
	return best;
}

//functia converteste o adresa ip in int
uint32_t convert(char *ip) {

	unsigned int b3, b2, b1, b0;
	sscanf(ip, "%u.%u.%u.%u", &b3, &b2, &b1, &b0);
	uint32_t rez = (b3 << 24) + (b2 << 16) + (b1 << 8) + b0;
	return rez;
}

//functia creaza pachetul de tip arp request si il trimite
void arp_request(struct route_table_entry* best_route){
	
	packet m;

	struct ether_header * eth_hdr = (struct ether_header *)m.payload;
	struct ether_arp *arp_pkt = (struct ether_arp *)(m.payload + sizeof(struct ether_header)); 
	
	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	m.interface = best_route->interface;

	//completez ether header
	uint8_t *aux = malloc(6*sizeof(uint8_t));
	get_interface_mac(m.interface, aux);
	memcpy(eth_hdr->ether_shost, aux, 6);
	memset(eth_hdr->ether_dhost, 0xff, 6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	
	//completez header - ul de arp
	arp_pkt->arp_hrd = htons(ARPHRD_ETHER);
	arp_pkt->arp_pro = htons(ETHERTYPE_IP);
	arp_pkt->arp_hln = 6;
	arp_pkt->arp_pln = 4;
	arp_pkt->arp_op = htons(1);

	memcpy(arp_pkt->arp_sha, eth_hdr->ether_shost, 6);
	memset(arp_pkt->arp_tha, 0, 6);

	uint32_t aux_ip = best_route->next_hop;
	memcpy(arp_pkt->arp_tpa, &aux_ip, 4);
	
	aux_ip = htonl(convert(get_interface_ip(m.interface)));
	memcpy(arp_pkt->arp_spa, &aux_ip, 4);

	send_packet(m.interface, &m);
}

//functia creaza pachetul de tip arp reply si il trimite
void arp_reply(packet m_p){
	
	packet m;

	struct ether_header *eth_hdr0 = (struct ether_header *)m_p.payload;
	struct ether_arp *arp_hdr0 = (struct ether_arp *)(m_p.payload + sizeof(struct ether_header)); 
	
	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));

	//completez ether header
	uint8_t *aux = malloc(6*sizeof(uint8_t));
	get_interface_mac(m_p.interface, aux);
	memcpy(eth_hdr->ether_shost, aux, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr0->ether_shost, 6);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	//completez header - ul de arp
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETHERTYPE_IP);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(2);
	

	uint8_t *aux_mac = malloc(sizeof(char) * 6);
	get_interface_mac(m_p.interface, aux_mac);
	memcpy(arp_hdr->arp_sha, aux_mac, 6);
	memcpy(arp_hdr->arp_tha, eth_hdr0->ether_shost, 6);

	u_long aux_ip = (u_long) htonl(convert(get_interface_ip(m_p.interface)));
	memcpy(arp_hdr->arp_spa, &aux_ip, 4);
	memcpy(arp_hdr->arp_tpa, arp_hdr0->arp_spa, 4);

	m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	m.interface = m_p.interface;

	send_packet(m.interface, &m);
}
/*
void icmp(packet m){

	m.len = sizeof(struct ether_header) + sizeof(struct iphdr)
			+ sizeof(struct icmphdr);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);

	icmp_hdr->type = 8;
	icmp_hdr->code = 0;
	icmp_hdr->un.echo.sequence = htons(0);
	icmp_hdr->un.echo.id = htons(getpid());
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));

}*/

struct arp_entry *get_arp_entry(struct arp_entry *arptable, int arptable_size, uint32_t ip) {
	struct arp_entry *aux = NULL;
	int i = 0;
	for(i = 0; i < arptable_size; i++)
		if(ip == arptable[i].ip)
			aux = &arptable[i];
	return aux;
}

//functia de citire/parsare a lui rtable
int read_rtable(struct route_table_entry *rtable){
	char* filenamein = "rtable.txt";
	char line[256], *p;
	int cnt = 0;

	p = malloc(100 * sizeof(char));
	if(!p) {
		return 0;
	}

	FILE *fin = fopen(filenamein, "r");
	if (fin == NULL) {
        fprintf(stderr, "ERROR: Can't open file %s", filenamein);
        free(p);
        return -1;
    }

	while(fgets(line, sizeof(line), fin)) {
		p = strtok(line, " ");
		rtable[cnt].prefix = htonl(convert(p));
		
		p = strtok(NULL, " ");
		rtable[cnt].next_hop = htonl(convert(p));
		
		p = strtok(NULL, " ");
		rtable[cnt].mask = htonl(convert(p));
		
		p = strtok(NULL, " ");
		rtable[cnt].interface = atoi(p);
		
		cnt++;
	}

	return cnt;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init();

	rtable = malloc(sizeof(struct route_table_entry) * 65000);
	arp_table = malloc(sizeof(struct  arp_entry) * 10);
	DIE(rtable == NULL, "memory");
	rtable_size = read_rtable(rtable);
	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header)); 
		struct ether_arp *arphdr = (struct ether_arp*)(m.payload + sizeof(struct ether_header));
		
		if(eth_hdr->ether_type == htons(0x806)){ 
			
			if(arphdr->arp_op == htons(1)){
				arp_reply(m);
			}
			
			else{
				//se adauga in vector o noua intrare
				struct arp_entry arp;
				memcpy(&arp.ip, arphdr->arp_spa, 4);
				memcpy(arp.mac, arphdr->arp_sha, 6);
					
				arp_table[arp_table_len] = arp;
	 			arp_table_len++;
					
				queue q_aux = queue_create();
				while(queue_empty(q) != 1){
					//extrag pachetul din coada
					packet m1 = *(packet*)queue_deq(q);
					struct iphdr *ip_hdr1 = (struct iphdr *)(m1.payload + sizeof(struct ether_header)); 	
					struct arp_entry *find_mac = get_arp_entry(arp_table, arp_table_len, ip_hdr1->daddr);
					
					//daca se gaseste o intrare in arp_table specifica ip ului dat ca parametru 
					//se completeaza campul de mac destination din ether header si este trimis 
					//pachetul la interfata corespunzatoare
					if(find_mac != NULL){		
						struct ether_header *eth_hdr1 = (struct ether_header *)m1.payload;
						memcpy(eth_hdr1->ether_dhost, find_mac, 6);
						send_packet(m1.interface, &m1);
					}	
					
					// in caz contrar se retine pachetul in continuare in coada
					else{
						queue_enq(q_aux, &m1);
					}
				}
				q = q_aux;

			}
		}		
		
		if(eth_hdr->ether_type == htons(0x800)){

			__u16 check_copy = ip_hdr->check;
			ip_hdr->check = 0;
			__u16 saved_sum = ip_checksum(ip_hdr, sizeof(struct iphdr));

			if(saved_sum != check_copy){
				continue;
			}

			if(ip_hdr->ttl <= 1){
				continue;
			}

			(ip_hdr->ttl)--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);
			if(best_route == NULL){
				continue;
			}
				
			struct arp_entry *arp = get_arp_entry(arp_table, arp_table_len, ip_hdr->daddr);

			if(arp == NULL){
				packet *p = calloc(sizeof(packet), 1);
				memcpy(p, &m, sizeof(packet));
				p->interface = best_route->interface;
				queue_enq(q, p);
				arp_request(best_route);
			}
				
			else{
					
				memcpy(eth_hdr->ether_dhost, arp->mac, 6);
				
				send_packet(best_route->interface, &m);
			}
		}
	}
}
