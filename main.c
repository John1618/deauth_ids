/*
 * main.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */
#include "deauthentication.h"
#include "pcap_helpers.h"


char errbuf[PCAP_ERRBUF_SIZE];
//list of clients that are suspected of being attacked
//maybe replace list with a hashy - vector of some sort???
//in order to optimize for speed
wlan_client *head = 0,*final =0;


int main ()
{
	pcap_if_t * alldevs, *dev;
	pthread_t checker;
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

	//start thread to monitor the list of clients
	pthread_create(&checker,NULL,check_clients,NULL);
	start_listening(dev);
	pthread_join(checker,NULL);
	return 0;
}


