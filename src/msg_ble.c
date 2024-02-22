/*
* Copyright (c) 2020, 2024 Vladimir Alemasov
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
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memset */
#include <assert.h>     /* assert */
#include "msg_ble.h"

//--------------------------------------------
static void msg_ble_free(msg_ble_t *ms)
{
	if (ms->info != NULL)
	{
		if (ms->info->buf != NULL)
		{
			free(ms->info->buf);
		}
		free(ms->info);
	}
	free(ms);
}

//--------------------------------------------
msg_ble_t *msg_ble_new(void)
{
	msg_ble_t *ms;

	if ((ms = (msg_ble_t *)malloc(sizeof(msg_ble_t))) == NULL)
	{
		return NULL;
	}
	memset(ms, 0, sizeof(msg_ble_t));
	return ms;
}

//--------------------------------------------
int msg_ble_remove(msgqueue_cond_t *queue, msg_ble_t *ms)
{
	if (msg_cond_remove(queue, (msg_t *)ms) < 0)
	{
		return -1;
	}
	msg_ble_free(ms);
	return 0;
}

//--------------------------------------------
int msg_ble_remove_cover(msgqueue_cond_t *queue, msg_ble_t *ms)
{
	if (msg_cond_remove(queue, (msg_t *)ms) < 0)
	{
		return -1;
	}
	free(ms);
	return 0;
}

//--------------------------------------------
void msg_ble_remove_all(msgqueue_cond_t *queue)
{
	msg_ble_t *ms;

	while ((ms = msg_ble_get_first(queue)))
	{
		msg_ble_remove(queue, ms);
	}
}

//--------------------------------------------
void msg_ble_destroy(msgqueue_cond_t *queue)
{
	msg_ble_remove_all(queue);
	msg_cond_destroy(queue);
}

//--------------------------------------------
int msg_ble_add_packet(msgqueue_cond_t *queue, ble_info_t *info)
{
	msg_ble_t *ms;

	if (info)
	{
		assert(info->buf);
		assert(info->size);
	}
	if ((ms = msg_ble_new()) == NULL)
	{
		return -1;
	}
	ms->info = info;
	if (msg_ble_add(queue, ms) < 0)
	{
		msg_ble_free(ms);
		return -1;
	}
	return 0;
}
