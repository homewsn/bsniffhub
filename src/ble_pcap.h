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

#ifndef BLE_PCAP_H_
#define BLE_PCAP_H_

//--------------------------------------------
#define LINKTYPE_BLUETOOTH_LE_LL                251
#define LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR      256
#define LINKTYPE_NORDIC_BLE                     272

#pragma pack(push,1)

//--------------------------------------------
typedef struct pcap_bluetooth_le_ll_header
{
	uint8_t rf_channel;
	int8_t signal_power;
	int8_t noise_power;
	uint8_t access_address_offenses;
	uint32_t ref_access_address;
	uint16_t flags;
} pcap_bluetooth_le_ll_header_t;

//--------------------------------------------
typedef struct pcap_nordic_ble_type2_header
{
	uint8_t board;
	uint16_t payload_length;
	uint8_t protocol_version;
	uint16_t packet_counter;
	uint8_t packet_id;
	uint8_t packet_length;
	uint8_t flags;
	uint8_t channel;
	int8_t rssi;
	uint16_t event_counter;
	uint32_t delta_time;
} pcap_nordic_ble_type2_header_t;

#pragma pack(pop)

#endif /* BLE_PCAP_H_ */
