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

#ifndef BLE_DECODER_H_
#define BLE_DECODER_H_

//--------------------------------------------
typedef enum
{
	PACKET_PROCESSED,
	PACKET_NOT_PROCESSED,
	PACKET_PROCESSED_WAIT_CLI_MSG
} ble_packet_decode_res_t;

//--------------------------------------------
ble_packet_decode_res_t ble_packet_decode(ble_info_t *info);
void brute_force_use(uint8_t mode);
void legacy_pairing_passkey_set(uint8_t *buf, size_t size);
void legacy_pairing_oob_key_set(uint8_t *buf, size_t size);
void ltk_set(uint8_t *buf, size_t size);
void ble_decoder_close(void);

#endif /* BLE_DECODER_H_ */
