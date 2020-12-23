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

#include "msgs.h"

//--------------------------------------------
static void add(msg_t **msglist, msg_t *msg)
{
	msg->next = *msglist;
	*msglist = msg;
}

//--------------------------------------------
static void remove(msg_t **msglist, msg_t *msg)
{
	msg_t *item;

	if (msg == *msglist)
	{
		*msglist = (*msglist)->next;
	}
	else
	{
		for (item = *msglist; item != NULL && item->next != msg; item = item->next);
		if (item != NULL)
		{
			item->next = msg->next;
		}
	}
	msg->next = NULL;
}

//--------------------------------------------
static msg_t* get_first(msg_t **msglist)
{
	msg_t *m;

	if (*msglist == NULL)
	{
		return NULL;
	}
	for (m = *msglist; m->next != NULL; m = m->next);
	return m;
}



//--------------------------------------------
//** msgqueue_t functions

//--------------------------------------------
int msg_init(msgqueue_t *queue)
{
	if (queue->valid)
	{
		return -1;
	}
	if (pthread_mutex_init(&queue->mutex, NULL) < 0)
	{
		return -1;
	}
	queue->valid = 1;
	return 0;
}

//--------------------------------------------
int msg_add(msgqueue_t *queue, msg_t *msg)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&queue->mutex);
	add(&queue->msglist, msg);
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

//--------------------------------------------
int msg_remove(msgqueue_t *queue, msg_t *msg)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&queue->mutex);
	remove(&queue->msglist, msg);
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

//--------------------------------------------
msg_t *msg_get_first(msgqueue_t *queue)
{
	msg_t* msg;

	if (!queue->valid)
	{
		return NULL;
	}
	pthread_mutex_lock(&queue->mutex);
	msg = get_first(&queue->msglist);
	pthread_mutex_unlock(&queue->mutex);
	return msg;
}

//--------------------------------------------
int msg_destroy(msgqueue_t *queue)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_mutex_destroy(&queue->mutex);
	queue->valid = 0;
	return 0;
}



//--------------------------------------------
//** msgqueue_cond_t functions

//--------------------------------------------
int msg_cond_init(msgqueue_cond_t *queue)
{
	if (queue->valid)
	{
		return -1;
	}
	if (pthread_mutex_init(&queue->mutex, NULL) < 0)
	{
		return -1;
	}
	if (pthread_cond_init(&queue->cond, NULL) < 0)
	{
		pthread_mutex_destroy(&queue->mutex);
		return -1;
	}
	queue->valid = 1;
	return 0;
}

//--------------------------------------------
int msg_cond_add(msgqueue_cond_t *queue, msg_t *msg)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&queue->mutex);
	add(&queue->msglist, msg);
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

//--------------------------------------------
int msg_cond_remove(msgqueue_cond_t *queue, msg_t *msg)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&queue->mutex);
	remove(&queue->msglist, msg);
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

//--------------------------------------------
msg_t *msg_cond_get_first(msgqueue_cond_t *queue)
{
	msg_t *msg;

	if (!queue->valid)
	{
		return NULL;
	}
	pthread_mutex_lock(&queue->mutex);
	msg = get_first(&queue->msglist);
	if (msg == NULL)
	{
		pthread_cond_wait(&queue->cond, &queue->mutex);
	}
	pthread_mutex_unlock(&queue->mutex);
	return msg;
}

//--------------------------------------------
int msg_cond_close(msgqueue_cond_t *queue)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_cond_signal(&queue->cond);
	return 0;
}

//--------------------------------------------
int msg_cond_destroy(msgqueue_cond_t *queue)
{
	if (!queue->valid)
	{
		return -1;
	}
	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->mutex);
	queue->valid = 0;
	return 0;
}



//--------------------------------------------
//** msggap_t functions

//--------------------------------------------
int msggap_init(msggap_t *gap)
{
	if (gap->valid)
	{
		return -1;
	}
	if (pthread_mutex_init(&gap->mutex, NULL) < 0)
	{
		return -1;
	}
	if (pthread_cond_init(&gap->cond, NULL) < 0)
	{
		pthread_mutex_destroy(&gap->mutex);
		return -1;
	}
	gap->request = 0;
	gap->valid = 1;
	return 0;
}

//--------------------------------------------
int msggap_request(msggap_t *gap)
{
	if (!gap->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&gap->mutex);
	gap->request = 1;
	while (gap->request == 1)
	{
		pthread_cond_wait(&gap->cond, &gap->mutex);
	}
	pthread_mutex_unlock(&gap->mutex);
	return 0;
}

//--------------------------------------------
int msggap_get_request(msggap_t *gap)
{
	int request;

	if (!gap->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&gap->mutex);
	request = gap->request;
	pthread_mutex_unlock(&gap->mutex);
	return request;
}

//--------------------------------------------
int msggap_reply(msggap_t *gap)
{
	if (!gap->valid)
	{
		return -1;
	}
	pthread_mutex_lock(&gap->mutex);
	gap->request = 0;
	pthread_cond_signal(&gap->cond);
	pthread_mutex_unlock(&gap->mutex);
	return 0;
}

//--------------------------------------------
int msggap_close(msggap_t *gap)
{
	if (!gap->valid)
	{
		return -1;
	}
	gap->request = 0;
	pthread_cond_signal(&gap->cond);
	return 0;
}

//--------------------------------------------
int msggap_destroy(msggap_t *gap)
{
	if (!gap->valid)
	{
		return -1;
	}
	pthread_cond_destroy(&gap->cond);
	pthread_mutex_destroy(&gap->mutex);
	gap->valid = 0;
	return 0;
}
