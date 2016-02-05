/*
 * main.c
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */
#include "deauthentication.h"
#include "pcap_helpers.h"

char errbuf[PCAP_ERRBUF_SIZE];
int deauth_packets_limit;
char mac_ap[30];
char log_file_name[60];

#define AP_MAC_INDEX 1
#define DEAUTH_LIMIT_INDEX 2
#define LOG_FILE_NAME_INDEX 3
#define PARAMETERS_NUMBER 4


int main (int argc, char** argv)
{
	//run process in background
	daemonize();
	if(argc!=PARAMETERS_NUMBER)
	{
		printf("Something wrong with parameters!!!\n");
		exit(-1);
	}


	strcpy(mac_ap,argv[AP_MAC_INDEX]);
	strcpy(log_file_name,argv[LOG_FILE_NAME_INDEX]);
	deauth_packets_limit = atoi(argv[DEAUTH_LIMIT_INDEX]);

	pcap_if_t * alldevs, *dev;
	pthread_t checker;
	int choice = 0;

	alldevs = get_devs( );
	choice = select_wlan_dev(alldevs);
	dev = return_dev(alldevs, choice);

	printf("Starting...\n");

	// put interface to monitor mode //
	while(1)
	{
		sleep(1000);
	}
	pcap_t *handler = pcap_create(dev->name, errbuf);
	if(pcap_set_rfmon(handler, 1) == 0 )
	{
		printf("%s is in monitor mode...\n",dev->name);
	}
	pcap_activate(handler); // activate Monitor mode

	//start thread to monitor the list of clients
	pthread_create(&checker, NULL, check_clients, NULL);
	start_listening(dev, mac_ap);
	pthread_join(checker,NULL);

	return 0;
}


