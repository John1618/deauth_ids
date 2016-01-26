/*
 * pcap_helpers.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */
#include "pcap_helpers.h"

//prepare a list of all devices

pcap_if_t * get_devs()
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


//print all devices in a ordered fashion
void print_devs(pcap_if_t * alldevs)
{
	pcap_if_t *d ;
	int i = 0 ; //used to order device
	printf("Here are the available interfaces to listen to:\n");
	for(d=alldevs; d; d=d->next)
	{
		printf("[%d] %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Sorry, No description available for this device)\n");
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

//private function
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	  static int count = 0 ;
	  //do packet processing here
	  //the insert in clients
	  //use mutex for that
	  printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}

void start_listening(pcap_if_t *dev)
{
	//this will capture all deauthentication packets
	char filter[]="wlan type mgt subtype deauth";
	pcap_t* descr;
	struct bpf_program fp;        /* to hold compiled program */
	bpf_u_int32 pMask;            /* subnet mask */
	bpf_u_int32 pNet;
	//fetch the network address and network mask
	pcap_lookupnet(dev, &pNet, &pMask, errbuf);

	// Now, open device for sniffing
	descr = pcap_open_live(dev->name, BUFSIZ, 0,-1, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		exit(1);
	}

	// Compile the filter expression
	if(pcap_compile(descr, &fp,filter, 0, pNet) == -1)
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

	pcap_loop(descr,5, callback, NULL);
}





