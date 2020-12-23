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
#include "list_lstbox.h"

//--------------------------------------------
list_lstbox_t *list_lstbox_add(list_lstbox_t **list, const char *devname, const char *scrname)
{
	list_lstbox_t *item;

	assert(devname != NULL);
	assert(scrname != NULL);

	if ((item = (list_lstbox_t *)malloc(sizeof(list_lstbox_t))) == NULL)
	{
		return NULL;
	}
	memset(item, 0, sizeof(list_lstbox_t));
	item->id = (int)list_lstbox_get_length(list) + 1;
	strncpy(item->devname, devname, DEVNAME_MAX_LEN);
	strncpy(item->scrname, scrname, SCRNAME_MAX_LEN);
	list_lstbox_add_item(list, item);
	return item;
}

//--------------------------------------------
char *list_lstbox_find_devname_by_id(list_lstbox_t **list, int id)
{
	list_lstbox_t *item;

	assert(list != NULL);

	item = *list;
	while (item != NULL)
	{
		if (item->id == id)
		{
			return item->devname;
		}
		item = list_lstbox_next(item);
	}
	return NULL;
}

//--------------------------------------------
char *list_lstbox_find_scrname_by_id(list_lstbox_t **list, int id)
{
	list_lstbox_t *item;

	assert(list != NULL);

	item = *list;
	while (item != NULL)
	{
		if (item->id == id)
		{
			return item->scrname;
		}
		item = list_lstbox_next(item);
	}
	return NULL;
}

//--------------------------------------------
int list_lstbox_find_id_by_devname(list_lstbox_t **list, char *devname)
{
	list_lstbox_t *item;

	assert(list != NULL);

	item = *list;
	while (item != NULL)
	{
		if (!strcmp(item->devname, devname))
		{
			return item->id;
		}
		item = list_lstbox_next(item);
	}
	return -1;
}

//--------------------------------------------
void list_lstbox_remove_all(list_lstbox_t **list)
{
	list_lstbox_t *next;
	list_lstbox_t *item;

	assert(list != NULL);

	item = *list;
	while (item != NULL)
	{
		next = list_lstbox_next(item);
		free(item);
		item = next;
	}
	*list = NULL;
}
