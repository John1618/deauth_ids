/*
 * deauthentication.h
 *
 *  Created on: Jan 26, 2016
 *      Author: john
 */

#ifndef DEAUTHENTICATION_H_
#define DEAUTHENTICATION_H_

#include"includes.h"

#define CHECK_INTERVAL 3


typedef struct wlan_client
{
	char mac[100];
	//sent by the client to the router
	int packets_sent;
	//packets received from the router
	int packets_received;
	//last updated
	//if too long ago free memory
	struct timespec timestamp;
	struct wlan_client * next;
}wlan_client;



void *check_clients(void *arg);


#endif /* DEAUTHENTICATION_H_ */
