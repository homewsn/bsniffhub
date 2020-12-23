/*
* Copyright (c) 2020 Vladimir Alemasov
* All rights reserved
*
* This program and the accompanying materials are distributed under 
* the terms of GNU General Public License version 2 
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/

#include <stdint.h>     /* uint8_t ... uint64_t */
#include <stdlib.h>		/* malloc */
#include <string.h>		/* memcpy, memset, memcmp */
#include <assert.h>		/* assert */
#include "list_adv.h"


//--------------------------------------------
list_adv_t *list_adv_new(uint8_t *adv_addr, uint8_t csa, uint8_t tx_addr)
{
	list_adv_t *item;

	assert(adv_addr != NULL);

	if ((item = (list_adv_t *)malloc(sizeof(list_adv_t))) == NULL)
	{
		return NULL;
	}
	memset(item, 0, sizeof(list_adv_t));
	memcpy(item->adv_addr, adv_addr, DEVICE_ADDRESS_LENGTH);
	item->csa = csa;
	item->tx_addr = tx_addr;
	return item;
}

//--------------------------------------------
list_adv_t *list_adv_find_addr(list_adv_t **list, uint8_t *adv_addr)
{
	list_adv_t *item;

	assert(list != NULL);
	assert(adv_addr != NULL);

	item = *list;
	while (item != NULL)
	{
		if (memcmp(item->adv_addr, adv_addr, sizeof(item->adv_addr)) == 0)
		{
			return item;
		}
		item = list_adv_next(item);
	}
	return NULL;
}

//--------------------------------------------
void list_adv_remove(list_adv_t **list, list_adv_t *item)
{
	assert(list != NULL);
	assert(item != NULL);

	list_remove((list_t **)list, (list_t *)item);
	free(item);
}

//--------------------------------------------
void list_adv_remove_all(list_adv_t **list)
{
	list_adv_t *next;
	list_adv_t *item;

	assert(list != NULL);

	item = *list;
	while (item != NULL)
	{
		next = list_adv_next(item);
		free(item);
		item = next;
	}
	*list = NULL;
}

//--------------------------------------------
list_adv_t *list_adv_add_replace(list_adv_t **list, uint8_t *adv_addr, uint8_t csa, uint8_t tx_addr)
{
	list_adv_t *item;

	assert(list != NULL);
	assert(adv_addr != NULL);

	item = list_adv_find_addr(list, adv_addr);
	if (item == NULL)
	{
		item = list_adv_add(list, adv_addr, csa, tx_addr);
	}
	else
	{
		if (item->csa != csa)
		{
			item->csa = csa;
		}
		if (item->tx_addr != tx_addr)
		{
			item->tx_addr = tx_addr;
		}
	}
	return item;
}
