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

#ifndef MSG_BLE_PCAP_H_
#define MSG_BLE_PCAP_H_

#include "msg_ble.h"

//--------------------------------------------
int msg_ble_pcap_init(void);
#define msg_ble_pcap_new() msg_ble_new()
int msg_ble_pcap_add(msg_ble_t *ms);
int msg_ble_pcap_remove(msg_ble_t *ms);
msg_ble_t *msg_ble_pcap_get_first(void);
void msg_ble_pcap_remove_all(void);
#define msg_ble_pcap_close() msg_close(a)
void msg_ble_pcap_destroy(void);
int msg_ble_pcap_add_packet(ble_info_t *info);

#endif /* MSG_BLE_PCAP_H_ */
