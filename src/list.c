/*
* Copyright (c) 2013-2020 Vladimir Alemasov
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

#include <assert.h>		/* assert */
#include <stddef.h>		/* NULL, size_t */
#include "list.h"


//--------------------------------------------
void list_init(list_t **list)
{
	assert(list != NULL);

	*list = NULL;
}

//--------------------------------------------
list_t *list_head(list_t **list)
{
	assert(list != NULL);

	return *list;
}

//--------------------------------------------
list_t *list_remove(list_t **list, list_t *item)
{
	list_t *find;
	list_t *prev;
	list_t *next;

	assert(list != NULL);
	assert(item != NULL);

	if (*list == NULL)
	{
		return NULL;
	}
	prev = NULL;
	for (find = *list; find != NULL; find = find->next)
	{
		if (find == item)
		{
			next = find->next;
			if (prev == NULL)
			{
				*list = next;
			}
			else
			{
				prev->next = next;
			}
			find->next = NULL;
			return next;
		}
		prev = find;
	}
	return NULL;
}

//--------------------------------------------
list_t *list_add_item(list_t **list, list_t *item)
{
	list_t *last;

	assert(list != NULL);
	assert(item != NULL);

	item->next = NULL;

	if (*list == NULL)
	{
		*list = item;
	}
	else
	{
		for (last = *list; last->next != NULL; last = last->next);
		last->next = item;
	}

	return item;
}

//--------------------------------------------
size_t list_get_length(list_t **list)
{
	list_t *item;
	size_t cnt = 0;

	assert(list != NULL);

	for (item = *list, cnt = 0; item != NULL; item = item->next, ++cnt);
	return cnt;
}

//--------------------------------------------
list_t *list_next(list_t *item)
{
	return item == NULL ? NULL : item->next;
}
