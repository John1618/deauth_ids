/*
 * deauthentication.c
 *
 *  Created on: Jan 26, 2016
 *      Author: john
 */
#include "deauthentication.h"

int max(int n1, int n2);

void write_alert(char* filename, char* mac_ap, char* mac_user)
{
	FILE* f=fopen(filename,"a+");
	//insert here ciob's insert function
	fprintf(f,"MAC %s has been deauthenticated from %s\n",mac_user,mac_ap);
	insert_into_db("root","root",mac_user,mac_ap);
	fclose(f);
}

/* this function is run by the second thread */
void * check_clients(void *arg)
{
	while (1)
	{
		attacked_client *aux = head;
		attacked_client *ant = head;
		while ( aux != NULL )
		{

			//this has to be replaced with the smart function
			//maybe turn this into a smart function pointer
			//so the user gets to choose
			detect_attack(aux);
			//add some auxiliary checks here
			//after timestamp logic is reintroduced
			//if time has expired the client should be deleted
			//in a humane, mercyful way
      ant = aux;
			aux = aux->next;  // ant->next is aux
		}

		sleep(CHECK_INTERVAL);
	}
	return NULL;
}

attacked_client * add_client(attacked_client *head, char* clientAddr, int inc_sent, int inc_rcvd) //, timespec timestamp)
{
	print_attacked_clients(head);
	if ( head == NULL )
	{
		//printf("list is empty\n");
		attacked_client *client = (attacked_client *) malloc( sizeof(attacked_client) );
   		client->addr = *ether_aton( clientAddr );
		client->deauth_packets_sent = inc_sent;
		client->deauth_packets_rcvd = inc_rcvd;

		head = client;
		head->next = NULL;
	}
	else
	{
		attacked_client *aux = head;
		char *auxAddr = (char*)malloc(sizeof(char)*30);
		strcpy(auxAddr, ether_ntoa( &aux->addr) );

		while ( aux != NULL )
		{
		     if ( strcmp( auxAddr, clientAddr ) == 0)
			break;

 		   aux = aux->next;
		}
		// if the client is already in list
		if (aux == head || aux == NULL)
		{
			aux->deauth_packets_sent += inc_sent;
			aux->deauth_packets_rcvd += inc_rcvd;
		}
		else
		{
			attacked_client *newClient = (attacked_client *) malloc( sizeof( attacked_client) );
			newClient->addr = *ether_aton( clientAddr );
			newClient->deauth_packets_sent = inc_sent;
    			newClient->deauth_packets_rcvd = inc_rcvd;
			newClient->next = NULL;
			aux->next = newClient;
		}
	}
return head;
}

void print_attacked_clients(attacked_client *head)
{
	attacked_client *aux = head;
	printf("Attacked clients till now ...\n");
	while ( aux != NULL )
	{
		printf("Client MAC Address: %s\n", ether_ntoa( &aux->addr) );
		printf("Client deauth packets sent: %d\n", aux->deauth_packets_sent );
		printf("Client deauth packets received: %d\n", aux->deauth_packets_rcvd );
		aux = aux->next;
	}
	printf("-----------------------------------\n");
}

int max(int n1, int n2)
{
	if (n1 >= n2)
		return n1;

return n2;
}

//implementation of function needed to run for learning
void smart_checking(attacked_client * client)
{
	double sn_new; // new value of Sn
	//counter represents number of deauth packets received
	//as last counter use the max out sent / received
	//hardcode mu epsilon and theta
	double mu = 0 , epsilon = 0 , theta = 0 ;
	//same thing for threshold
	//determine appropiate size after documentation process completed
	long threshold = 10;
	long last_counter = max( client->deauth_packets_sent, client->deauth_packets_rcvd); // former value of counter

	//reset value to determine if the client is attacked or not
	client->deauth_packets_sent = client->deauth_packets_rcvd = 0 ;
	//important questions:
	//who the f*ck are mu, epsilon and theta ???
	sn_new= client->sn + last_counter - mu - epsilon * theta;
	if (sn_new < 0)
	{
		sn_new= 0;
	}
	client->sn = sn_new;
	if (sn_new > threshold)
	{
	 	printf("Attack on client:%s\n", ether_ntoa( &client->addr ) );
	}

}


//this should be rethinked a little bit
//just a tiny tinsy bit
void simple_checking(attacked_client * aux)
{
	if( max ( aux->deauth_packets_sent, aux->deauth_packets_rcvd) >= deauth_packets_limit )
	{
		write_alert(log_file_name, mac_ap ,ether_ntoa( &aux->addr));
		//reinitialize counters
		//do it right this time
		aux->deauth_packets_sent = aux->deauth_packets_rcvd = 0 ;
		printf("Attack on client:%s\n", ether_ntoa( &aux->addr ) );
	}
}
