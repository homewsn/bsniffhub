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

#ifndef LIST_IFACE_H_
#define LIST_IFACE_H_

#include "list.h"

#define DEVNAME_MAX_LEN 255
#define SCRNAME_MAX_LEN 255

//--------------------------------------------
typedef struct list_lstbox
{
	list_t next;
	int id;
	char devname[DEVNAME_MAX_LEN + 1];
	char scrname[SCRNAME_MAX_LEN + 1];
} list_lstbox_t;

//--------------------------------------------
#define list_lstbox_init(a) list_init((list_t **)a)
#define list_lstbox_head(a) (list_lstbox_t *)list_head((list_t **)a)
#define list_lstbox_remove(a, b) (list_lstbox_t *)list_remove((list_t **)a, (list_t *)b)
#define list_lstbox_add_item(a, b) (list_lstbox_t *)list_add_item((list_t **)a, (list_t *)b)
#define list_lstbox_get_length(a) list_get_length((list_t **)a)
#define list_lstbox_next(a) (list_lstbox_t *)list_next((list_t *)a)
list_lstbox_t *list_lstbox_add(list_lstbox_t **list, const char *devname, const char *scrname);
char *list_lstbox_find_devname_by_id(list_lstbox_t **list, int id);
char *list_lstbox_find_scrname_by_id(list_lstbox_t **list, int id);
int list_lstbox_find_id_by_devname(list_lstbox_t **list, char *devname);
void list_lstbox_remove_all(list_lstbox_t **list);

#endif /* LIST_IFACE_H_ */
