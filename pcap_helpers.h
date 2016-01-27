/*
 * pcap_helpers.h
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */

#ifndef PCAP_HELPERS_H_
#define PCAP_HELPERS_H_

#include "includes.h"

//structure to help with mac reading
typedef struct mac_header{
unsigned char fc[2];
unsigned char id[2];
unsigned char add1[6];
unsigned char add2[6];
unsigned char add3[6];
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

typedef struct beacon_header{
unsigned char timestamp[8];

unsigned char beacon_interval[2];
unsigned char cap_info[2];
}beacon_header;



//external variabled to use
extern char errbuf[PCAP_ERRBUF_SIZE];





//lists available devices
pcap_if_t * get_devs();

void print_devs(pcap_if_t * alldevs);

pcap_if_t * return_dev(pcap_if_t *alldevs, int index);

void start_listening(pcap_if_t *dev);


#endif /* PCAP_HELPERS_H_ */
