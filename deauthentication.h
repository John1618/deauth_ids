/*
 * deauthentication.h
 *
 *  Created on: Jan 26, 2016
 *      Author: john
 */

#ifndef DEAUTHENTICATION_H_
#define DEAUTHENTICATION_H_

#include "includes.h"

#define CHECK_INTERVAL 3

typedef struct attacked_client
{
struct ether_addr addr;	      		// client who is attacked
int deauth_packets_sent;	        // total no of deauth packets sent by client to ap in response to a request of deauth from ap
int deauth_packets_rcvd; 		// total no of deauth packets received from ap
//struct timespec timestamp; 		// last update
//add some needed variables for the smart mechanism
double sn;
struct attacked_client *next;
}attacked_client;

extern attacked_client *head;
extern int deauth_packets_limit;
extern char mac_ap[30];
extern char log_file_name[60];
extern void (*detect_attack)(attacked_client *);

void *check_clients(void *arg);
attacked_client * add_client(attacked_client *head, char *clientAddr, int inc_sent, int inc_rcvd);
void print_attacked_clients(attacked_client *head);
int max( int n1, int n2);
//implementation of smart, learning ids
void smart_checking(attacked_client * client);

#endif /* DEAUTHENTICATION_H_ */
