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

#ifndef MSGS_H_
#define MSGS_H_

#include "thread.h"

//--------------------------------------------
typedef struct msg
{
	struct msg *next;
} msg_t;


//--------------------------------------------
typedef struct msgqueue
{
	msg_t *msglist;
	int valid;
	pthread_mutex_t mutex;
} msgqueue_t;

int msg_init(msgqueue_t *queue);
int msg_add(msgqueue_t *queue, msg_t *msg);
int msg_remove(msgqueue_t *queue, msg_t *msg);
msg_t* msg_get_first(msgqueue_t *queue);
#define msg_close(a)
int msg_destroy(msgqueue_t *queue);


//--------------------------------------------
typedef struct msgqueue_cond
{
	msg_t *msglist;
	int valid;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} msgqueue_cond_t;

int msg_cond_init(msgqueue_cond_t *queue);
int msg_cond_add(msgqueue_cond_t *queue, msg_t *msg);
int msg_cond_remove(msgqueue_cond_t *queue, msg_t *msg);
msg_t* msg_cond_get_first(msgqueue_cond_t *queue);
int msg_cond_close(msgqueue_cond_t *queue);
int msg_cond_destroy(msgqueue_cond_t *queue);


//--------------------------------------------
typedef struct msggap
{
	void *msg;
	int valid;
	int request;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} msggap_t;

int msggap_init(msggap_t *gap);
int msggap_request(msggap_t *gap);
int msggap_get_request(msggap_t *gap);
int msggap_reply(msggap_t *gap);
int msggap_close(msggap_t *gap);
int msggap_destroy(msggap_t *gap);

#endif /* MSGS_H_ */
