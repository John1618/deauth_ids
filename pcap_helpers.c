/*
 * pcap_helpers.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */
#include "pcap_helpers.h"


attacked_client *head = NULL;
//prepare a list of all devices
pcap_if_t * get_devs( )
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;

	// Prepare a list of all the devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

  return alldevs;
}

int select_wlan_dev(pcap_if_t *alldevs)
{
	pcap_if_t *d ;
	int i = 1 ; //used to order device

	for(d=alldevs; d; d=d->next,i++)
	{
		if(strstr(d->name,"wlan"))
			return i;
	}
	return 0;
}
//print all devices in an ordered fashion

void print_devs(pcap_if_t * alldevs)
{
	pcap_if_t *d ;
	int i = 0 ; //used to order device
	printf("Here are the available interfaces to listen to:\n");
	for(d=alldevs; d; d=d->next)
	{
		printf("[%d] %s", ++i, d->name);
		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (Sorry, No description available for this device)\n");
		}
	}
}

pcap_if_t * return_dev(pcap_if_t *alldevs, int index)
{
	pcap_if_t *d ;
	int i = 0 ; //used to order device
	for(d=alldevs; d; d=d->next)
	{
		if(++i == index)
		{
			return d;
		}
	}

   return NULL;
}




void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    printf("In callback...\n");
    //static int count = 0 ;
    //char * temp;
    //char ssid[32];
    struct mac_header *p= (struct mac_header *)(packet + RADIOTAP_HEADER_SIZE);
    struct frame_control *control = (struct frame_control *) p->fc;
    
    if ((control->protocol == 0) && (control->type == 0) && (control->subtype == 12) )  // deauth frame
    {     
		char * destAddr = (char *) malloc (30 * sizeof(char));
		char * srcAddr = (char *) malloc (30 * sizeof(char));
		char * bssidAddr = (char *) malloc (30 * sizeof(char));

		strcpy(destAddr, ether_ntoa ( &p->destAddr ) );
		strcpy(srcAddr, ether_ntoa ( &p->srcAddr ) );
		strcpy(bssidAddr, ether_ntoa ( &p->addr ) );
 

		if ( strcmp( srcAddr, bssidAddr) == 0 )		// srcAddr eq BSSID
		{
			printf("increment rcv packets...");
			head = add_client(head, destAddr, 0, 1);
			}
		else										// dstAddr eq BSSID
		{
			printf("increment sent packets...");
			head = add_client(head, srcAddr, 1, 0);
		}
	
    }	
    //printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
    //print_attacked_clients(head);
}

void start_listening(pcap_if_t *dev, char* AP_ADDRESS)
{
	//this will capture all deauthentication packets
	//char filter[60]="wlan type mgt subtype deauth";
	char filter[60]="wlan type mgt subtype deauth and ether host ";
	strcat(filter,AP_ADDRESS);

	pcap_t* descr;
	struct bpf_program fp;        /* to hold compiled program */
	bpf_u_int32 pMask;            /* subnet mask */
	bpf_u_int32 pNet;
	//fetch the network address and network mask
	pcap_lookupnet(dev, &pNet, &pMask, errbuf);
	
	struct in_addr tmp;
	tmp.s_addr = pNet;
	printf( "IP=%s\n", inet_ntoa(tmp) ); 
	
	// Now, open device for sniffing
	descr = pcap_open_live(dev->name, BUFSIZ, 0, -1, errbuf);
	if(descr == NULL)
	{ 
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		exit(1);
	}

	// Compile the filter expression
	if(pcap_compile(descr, &fp, filter, 0, pNet) == -1)
	{
		printf("\npcap_compile() failed\n");
		//exit(1);
	}

	// Set the filter compiled above
	if(pcap_setfilter(descr, &fp) == -1)
	{
		printf("\npcap_setfilter() failed\n");
		exit(1);
	}
		
	pcap_loop(descr, 64, callback, NULL);
    	
}





