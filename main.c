/*
 * main.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */

#include "pcap_helpers.h"

char errbuf[PCAP_ERRBUF_SIZE];

int main ()
{
	pcap_if_t * alldevs, *dev;

	int choice;
	alldevs = get_devs();
	print_devs(alldevs);
	printf("Insert the number of the device to inspect:\n");
	printf("=====>");
	scanf("%d",&choice);
	dev = return_dev(alldevs,choice);
	printf("You have chosen %s\n",dev->name);
	printf("Starting...\n");

	//set the dev in monitor
	//hopefully it is a wlan

	pcap_t *handler = pcap_create(dev->name,errbuf);
	if(pcap_set_rfmon(handler,1)==0 )
	{
		printf("%s is in monitor mode...\n",dev->name);
	}


	start_listening(dev);


	return 0;
}


