/*
* Copyright (c) 2020 - 2025 Vladimir Alemasov
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

#ifndef SNIFFERS_H_
#define SNIFFERS_H_

//--------------------------------------------
#define MAX_ID_LENGTH        10

//--------------------------------------------
typedef struct sniffer
{
	char id[MAX_ID_LENGTH];
	port_settings_t sets;
	void(*init)(HANDLE hndl);
	void(*reset)(void);
	int(*decode)(uint8_t *buf, size_t len, ble_info_t **pkt_info);
	void(*follow_device)(uint8_t *buf, size_t size);
	void(*passkey_set)(uint8_t *buf, size_t size);
	void(*oob_key_set)(uint8_t *buf, size_t size);
	void(*ltk_set)(uint8_t *buf, size_t size, bool send);
	void(*min_rssi_set)(int8_t rssi);
	void(*adv_channel_set)(uint8_t *hop_map, uint8_t hop_map_size);
	void(*mac_addr_set)(uint8_t *buf, uint8_t addr_type);
	void(*follow_aux_connect)(uint8_t follow);
	void(*follow_filter_set)(uint8_t modes);
	void(*close)(void);
} sniffer_t;

//--------------------------------------------
#define SNIFFER(name, id, baudrate, flow_control, init, reset, decode, follow_device, passkey_set, oob_key_set, ltk_set,\
                min_rssi_set, adv_channel_set, mac_addr_set, follow_aux_connect, follow_filter_set, close) \
	const sniffer_t name = { id, baudrate, flow_control, init, reset, decode, follow_device, passkey_set, oob_key_set, ltk_set,\
                             min_rssi_set, adv_channel_set, mac_addr_set, follow_aux_connect, follow_filter_set, close }

//--------------------------------------------
#define SNIFFERS(...) \
	const sniffer_t *sniffers[] = { __VA_ARGS__, NULL }

//--------------------------------------------
const sniffer_t *get_sniffer(char *id);

#endif /* SNIFFERS_H_ */
