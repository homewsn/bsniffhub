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

#ifndef MSG_BLE_H_
#define MSG_BLE_H_

#include "msgs.h"
#include "ble_info.h"

//--------------------------------------------
typedef struct msg_ble
{
	msg_t msg;
	ble_info_t *info;
} msg_ble_t;

//--------------------------------------------
#define msg_ble_init(a) msg_cond_init(a)
msg_ble_t *msg_ble_new(void);
#define msg_ble_add(a, b) msg_cond_add(a, (msg_t *)b)
int msg_ble_remove(msgqueue_cond_t *queue, msg_ble_t *ms);
int msg_ble_remove_cover(msgqueue_cond_t *queue, msg_ble_t *ms);
#define msg_ble_get_first(a) (msg_ble_t *)msg_cond_get_first(a)
void msg_ble_remove_all(msgqueue_cond_t *queue);
void msg_ble_destroy(msgqueue_cond_t *queue);
int msg_ble_add_packet(msgqueue_cond_t *queue, ble_info_t *info);

#endif /* MSG_BLE_H_ */
