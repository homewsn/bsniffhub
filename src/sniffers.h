/*
* Copyright (c) 2020, 2021, 2024 Vladimir Alemasov
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
	int(*decode)(uint8_t *buf, size_t len, ble_info_t **pkt_info);
	void(*follow)(uint8_t *buf, size_t size);
	void(*passkey_set)(uint8_t *buf, size_t size);
	void(*oob_key_set)(uint8_t *buf, size_t size);
	void(*ltk_set)(uint8_t *buf, size_t size);
	void(*min_rssi_set)(int8_t rssi);
	void(*close)(void);
} sniffer_t;

//--------------------------------------------
#define SNIFFER(name, id, baudrate, flow_control, init, decode, follow, passkey_set, oob_key_set, ltk_set, min_rssi_set, close) \
	const sniffer_t name = { id, baudrate, flow_control, init, decode, follow, passkey_set, oob_key_set, ltk_set, min_rssi_set, close }

//--------------------------------------------
#define SNIFFERS(...) \
	const sniffer_t *sniffers[] = { __VA_ARGS__, NULL }

//--------------------------------------------
const sniffer_t *get_sniffer(char *id);

#endif /* SNIFFERS_H_ */
