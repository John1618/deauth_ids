/*
 * pcap_helpers.h
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */

#ifndef PCAP_HELPERS_H_
#define PCAP_HELPERS_H_

#include "includes.h"
#include "deauthentication.h"

//structure to help with mac reading
typedef struct mac_header{
unsigned char fc[2];
unsigned char id[2];
struct ether_addr destAddr;
struct ether_addr srcAddr;
struct ether_addr addr;
unsigned char sc[2];
}mac_header;

typedef struct frame_control{
unsigned protocol:2;
unsigned type:2;
unsigned subtype:4;
unsigned to_ds:1;
unsigned from_ds:1;
unsigned more_frag:1;
unsigned retry:1;
unsigned pwr_mgt:1;
unsigned more_data:1;
unsigned wep:1;
unsigned order:1;
}frame_control;

//constant for radio tap header
#define RADIOTAP_HEADER_SIZE 18

//external variabled to use
extern char errbuf[PCAP_ERRBUF_SIZE];

extern attacked_client *head;

extern int deauth_packets_limit;
extern char mac_ap[30];

//lists available devices
pcap_if_t * get_devs();

void print_devs(pcap_if_t * alldevs );

int select_wlan_dev(pcap_if_t *alldevs);

pcap_if_t * return_dev(pcap_if_t *alldevs, int index);

void start_listening(pcap_if_t *dev,char* ap_address);

//added by John
void daemonize();
void insert_into_db(char * db_user, char* db_password, char* mac_user, char* mac_ap);


#endif /* PCAP_HELPERS_H_ */
