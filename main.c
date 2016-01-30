/*
 * main.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */
#include "deauthentication.h"
#include "pcap_helpers.h"

char errbuf[PCAP_ERRBUF_SIZE];

int main ()
{
	//------------ Declaration area ------------	
	pcap_if_t * alldevs, *dev;
	pthread_t checker;
	int choice = 0;
        //------------------------------------------
	alldevs = get_devs( );
	print_devs( alldevs );
	printf("Insert the number of the device to inspect:\n");
	scanf("%d", &choice);

	if ( choice != 0 )
	{	
		dev = return_dev(alldevs, choice);
		printf("You have chosen %s\n", dev->name);
		printf("Starting...\n");
                // put interface to monitor mode // 
		pcap_t *handler = pcap_create(dev->name, errbuf);
		if(pcap_set_rfmon(handler, 1) == 0 )
		{
			printf("%s is in monitor mode...\n",dev->name);
		}
		pcap_activate(handler); // activate Monitor mode
		
		//start thread to monitor the list of clients
		pthread_create(&checker, NULL, check_clients, NULL);
		start_listening(dev);
		pthread_join(checker,NULL);
	}
return 0;
}


