/*
 * deauthentication.c
 *
 *  Created on: Jan 26, 2016
 *      Author: john
 */
#include"includes.h"
#include"deauthentication.h"


/* this function is run by the second thread */
void * check_clients(void *arg)
{
	while (1)
	{
		//parse list to spot deauth attacks
		printf("I am testing this\n");
		sleep(CHECK_INTERVAL);
	}
	return NULL;

};

