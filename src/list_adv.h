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

#ifndef LIST_ADV_H_
#define LIST_ADV_H_

#include "list.h"
#include "ble.h"


//--------------------------------------------
typedef struct list_adv
{
	list_t next;
	uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];
	uint8_t csa;
	uint8_t tx_addr;
} list_adv_t;

//--------------------------------------------
list_adv_t *list_adv_new(uint8_t *adv_addr, uint8_t csa, uint8_t tx_addr);
list_adv_t *list_adv_find_addr(list_adv_t **list, uint8_t *adv_addr);
void list_adv_remove(list_adv_t **list, list_adv_t *item);
void list_adv_remove_all(list_adv_t **list);
#define list_adv_next(a) (list_adv_t *)list_next((list_t *)a)
#define list_adv_add(a, b, c, d) (list_adv_t *)list_add_item((list_t **)a, (list_t *)list_adv_new(b, c, d))
list_adv_t *list_adv_add_replace(list_adv_t **list, uint8_t *adv_addr, uint8_t csa, uint8_t tx_addr);

#endif /* LIST_ADV_H_ */
