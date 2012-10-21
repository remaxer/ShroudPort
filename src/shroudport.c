/*
    ShroudPort - Defends your computer from SYN Stealth scanning
    Copyright (C) 2012  REmaxer <remaxer@hotmail.it>
   
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <time.h>
#include <netinet/ether.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#define MAX_EXISTING_PORTS 30

void caught_packet(u_char *,const struct pcap_pkthdr *,const u_char *);
int set_packet_filter(pcap_t *,struct in_addr *,u_short *);
unsigned short csum(unsigned short *ptr,int nbytes);
int random_number(int);
void fatal(char *);

int main(int argc,char *argv[]){
	//Pcap header
	struct pcap_pkthdr cap_header;
	//Packet Char pointer
	const u_char *packet;
	//Pcap Handle
	pcap_t *pcap_handle;
	//Pcap error Buffer
	char errbuf[PCAP_ERRBUF_SIZE];
	//Sniffing Device
	char *device;
	//Socket Descriptor
	int sockfd;
	int i,yes=1;
	//sockaddr_in to check validity of IP
	struct sockaddr_in sa;
	//Array of available ports
	u_short existing_ports[MAX_EXISTING_PORTS];

	if((argc < 2) || ( argc > MAX_EXISTING_PORTS+2)){
		if(argc >2)
			printf("Limited to tracking %d existing ports.\n",MAX_EXISTING_PORTS);
		else
			printf("Usage: %s <IP to shroud> [existing ports...]\n",argv[0]);
		exit(0);
	}
 	if(geteuid()!=0)
		fatal("you must run this program as root ");
	//Check target ip
	if(inet_pton(AF_INET,argv[1],&(sa.sin_addr)) == 0)
		fatal("Invalid target address");
	if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) == -1)
		fatal("Making socket");
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) < 0)
		fatal("Setting IP_HDRINCL");
	//Iterate command line arguments saving them to existing_ports[]
	for(i=2;i< argc;i++)
		existing_ports[i-2] = (u_short) atoi(argv[i]);

	existing_ports[argc-2] = 0;
	//Initialize Pcap Device
	device = pcap_lookupdev(errbuf);
	if(device == NULL)
		fatal(errbuf);
	printf("Sniffing on device %s \n",device);
	//Initialize Pcap Handle in promiscous mode
	pcap_handle = pcap_open_live(device,128,1,0,errbuf);
	if(pcap_handle == NULL)
		fatal(errbuf);
	//Call set_packet_filter() function
	set_packet_filter(pcap_handle,(struct in_addr *)&sa.sin_addr,existing_ports);
	//Call pcap_loop() function and use callback function caught_packet
	pcap_loop(pcap_handle,-1,caught_packet,(u_char *)&sockfd);
	//Close pcap handler
	pcap_close(pcap_handle);
	//Close socket descriptor
	close(sockfd);
	return(0);
}

void fatal(char *msg){
	printf("%s",msg);
	exit(1);

}

int random_number(int nt){
	struct timeval tv;
	gettimeofday(&tv,NULL);
	unsigned int seed = (unsigned int)tv.tv_usec;
	srand(seed);
	switch(nt){
	//1 <--> Unsigned 8-Bit
		case 1:
			return(rand()%UCHAR_MAX);
			break;
	//2 <--> Signed 8-Bit
		case 2:
			return(rand()%SCHAR_MAX);
			break;
	//3 <--> Unsigned Short
		case 3:
			return(rand()%USHRT_MAX);
			break;
	//4 <--> Signed Short
		case 4:
			return(rand()%SHRT_MAX);
			break;
	//5 <--> Unsigned Int
		case 5:
			return(rand()%UINT_MAX);
			break;
	//6 <--> Signed Int
		case 6: 
			return(rand()%INT_MAX);
			break;
	//7 <--> Unsigned Long
		case 7:
			return(rand()%ULONG_MAX);
			break;
	//8 <--> Signed Long
		case 8:
			return(rand()%LONG_MAX);
			break;
	// Default value
		default:
			return(0);
			break;
	}
}


int set_packet_filter(pcap_t *pcap_hdl,struct in_addr *target_ip,u_short *ports){
	//Bpf Filter
	struct bpf_program filter;
	char *str_ptr,filter_string[90+(25 * MAX_EXISTING_PORTS)];
	int i=0;
	//Set dst host rule
	sprintf(filter_string,"dst host %s and ",inet_ntoa(*target_ip));
	//Set flag rule
	strcat(filter_string,"tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0");
	//Set ports rules
	if(ports[0] != 0){
		str_ptr = filter_string + strlen(filter_string);
		if(ports[1] == 0)
			sprintf(str_ptr," and not dst port %hu",ports[i]);
		else{
			sprintf(str_ptr," and not (dst port %hu",ports[i++]);
			while(ports[i] != 0){
				str_ptr= filter_string + strlen(filter_string);
				sprintf(str_ptr," or dst port %hu",ports[i++]);
			}
			strcat(filter_string,")");
		}
	}
	//Print final filter string
	printf("DEBUG: filter string is \' %s \' \n ",filter_string);
	//Try to compile filter string into bpf filter
	if(pcap_compile(pcap_hdl,&filter,filter_string,0,0) == -1)
		fatal("pcap_compile failed");
	//Assign bpf filter to pcap handler
	if(pcap_setfilter(pcap_hdl,&filter) == -1)
		fatal("pcap_setfilter failed");
}


void caught_packet(u_char *user_args,const struct pcap_pkthdr *cap_header,const u_char *packet){
	//Bytes written and Socket Descriptor
	int bcount,sockfd;
	//IP Header
	struct iphdr *iphdr_old,*iphdr;
	//TCP Header
	struct tcphdr *tcphdr_old,*tcphdr;
	//Retrieve sockfd
	sockfd = *((int *)user_args);
	//Packet Buffer
	char pkt_buffer[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	//Structuring old packet
	iphdr_old = (struct iphdr *)(packet + sizeof(struct ethhdr));
	tcphdr_old = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	//Structuring new headers
	iphdr = (struct iphdr *)(pkt_buffer);
	tcphdr = (struct tcphdr *)(pkt_buffer + sizeof(struct iphdr));
	//Sin address to send packet
	struct sockaddr_in sin;
	//initialize buffer
	memset(pkt_buffer,0,(sizeof(struct iphdr) + sizeof(struct tcphdr)));
	//initialize sin addr
	sin.sin_family = AF_INET;
	sin.sin_port = tcphdr_old->source;
	sin.sin_addr = *((struct in_addr *)&iphdr_old->saddr);
	//Create Packet
	//Ip Header
	
	iphdr->ihl       = 5;
	iphdr->version   = 4;
	iphdr->tos       = IPTOS_LOWDELAY;
	iphdr->tot_len   = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	iphdr->id        = htons(random_number(3));;
	iphdr->frag_off  = 0;
	iphdr->ttl       = MAXTTL;
	iphdr->protocol  = IPPROTO_TCP;
	iphdr->check     = 0;//Done by Kernel
	//Reverse IPs
	iphdr->saddr     = iphdr_old->daddr;
	iphdr->daddr     = iphdr_old->saddr;


	//Tcp Header
	//Reverse Ports
	tcphdr->source = tcphdr_old->dest;
	tcphdr->dest   = tcphdr_old->source;
	tcphdr->seq    = htonl(random_number(5));
	tcphdr->ack_seq= htons(ntohs(tcphdr_old->seq)+1);
	tcphdr->doff   = 5;
	tcphdr->syn    = 1;
	tcphdr->ack    = 1;
	tcphdr->fin    = 0;
	tcphdr->rst    = 0;
	tcphdr->psh    = 0;
	tcphdr->urg    = 0;
	tcphdr->window = htons(random_number(3));
	tcphdr->check  = 0;//Done by Kernel
	tcphdr->urg_ptr= 0;

	//Send packet
	bcount = sendto(sockfd,pkt_buffer,ntohs(iphdr->tot_len),0,(struct sockaddr *)&sin,(socklen_t)sizeof(sin));
	//Check if the packet has been sent and how much bytes have been sent
	if(bcount < 0 )
		printf("Couldn't send packet: %s  \n",strerror(errno));
	else
		printf("(%d) bytes sent ! \n",bcount);

}
		
