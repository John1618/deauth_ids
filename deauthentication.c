/*
 * deauthentication.c
 *
 *  Created on: Jan 26, 2016
 *      Author: john
 */
#include "deauthentication.h"


void write_alert(char* filename, char* mac_ap, char* mac_user)
{
	FILE* f=fopen(filename,"a+");

	fprintf(f,"%s %s\n",mac_user,mac_ap);

	fclose(f);
}

/* this function is run by the second thread */
void * check_clients(void *arg)
{
	while (1)
	{
			attacked_client *aux = head;

			while ( aux != NULL )
			{
				if(aux->deauth_packets_sent+ aux->deauth_packets_rcvd>3)
				{
						write_alert(log_file_name, mac_ap ,ether_ntoa( &aux->addr));
						attacked_client *nod = aux;
						aux=aux->next;
						free(nod);
						if(!aux)
							break;
						printf("bingo!!! l-am prins pe fraier!!!\n");
				}

				aux = aux->next;
			}
			sleep(1);
	}
	return NULL;

};

attacked_client * add_client(attacked_client *head, char* clientAddr, int inc_sent, int inc_rcvd) //, timespec timestamp)
{
	print_attacked_clients(head);
	if ( head == NULL )
	{
		printf("list is empty\n");
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
			//client->timestamp = timestamp;
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

