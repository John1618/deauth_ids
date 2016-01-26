/*
 * pcap_helpers.h
 *
 *  Created on: Jan 19, 2016
 *      Author: john
 */

#ifndef PCAP_HELPERS_H_
#define PCAP_HELPERS_H_

#include "includes.h"

//external variabled to use
extern char errbuf[PCAP_ERRBUF_SIZE];


//lists available devices
pcap_if_t * get_devs();

void print_devs(pcap_if_t * alldevs);

pcap_if_t * return_dev(pcap_if_t *alldevs, int index);

void start_listening(pcap_if_t *dev);


#endif /* PCAP_HELPERS_H_ */
