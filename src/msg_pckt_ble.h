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

#ifndef MSG_PCKT_BLE_H_
#define MSG_PCKT_BLE_H_

#include "msg_ble.h"

//--------------------------------------------
int msg_pckt_ble_init(void);
#define msg_pckt_ble_new() msg_ble_new()
int msg_pckt_ble_add(msg_ble_t *ms);
int msg_pckt_ble_remove(msg_ble_t *ms);
int msg_pckt_ble_remove_cover(msg_ble_t *ms);
msg_ble_t *msg_pckt_ble_get_first(void);
void msg_pckt_ble_remove_all(void);
#define msg_pckt_ble_close() msg_close(a)
void msg_pckt_ble_destroy(void);
int msg_pckt_ble_add_packet(ble_info_t *info);

#endif /* MSG_PCKT_BLE_H_ */
