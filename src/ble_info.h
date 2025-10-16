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

#ifndef BLE_INFO_H_
#define BLE_INFO_H_

#ifdef _WIN32
#include <windows.h>      /* struct timeval */
#else
#include <sys/time.h>     /* struct timeval */
#endif

//--------------------------------------------
typedef enum
{
	PHY_1M = 0,
	PHY_2M = 1,
	PHY_CODED = 2
} ble_phy_t;

typedef enum
{
	CI_S8 = 0,
	CI_S2 = 1
} ble_ci_t;

typedef enum
{
	DIR_UNKNOWN = 0,
	DIR_MASTER_SLAVE,
	DIR_SLAVE_MASTER
} pkt_dir_t;

typedef enum
{
	PDU_ADV,
	PDU_AUX,
	PDU_ACL,
	PDU_ISO_CIG,
	PDU_ISO_BIG,
	PDU_UNKNOWN
} pdu_type_t;

typedef enum
{
	PKT_AUX_ADV_IND,
	PKT_AUX_CHAIN_IND,
	PKT_AUX_SYNC_IND,
	PKT_AUX_SCAN_RSP,
	PKT_AUX_SYNC_SUBEVENT_IND,
	PKT_AUX_SYNC_SUBEVENT_RSP
} pkt_aux_t;

typedef enum
{
	CHECK_UNKNOWN = 0,
	CHECK_OK,
	CHECK_FAIL
} check_status_t;

typedef enum
{
	ENC_UNKNOWN = 0,
	ENC_UNENCRYPTED,
	ENC_DECRYPTED,
	ENC_ENCRYPTED
} enc_status_t;

//--------------------------------------------
typedef struct ble_info
{
	uint8_t *buf;                 // BLE packet buffer
	size_t size;                  // BLE packet size in bytes
	struct timeval ts;            // The timestamp that appears in the Wireshark Time column 
	                              // and is contained in the header of each packet of the pcap file.
	                              // In the case of loading from the pcap file, it is transferred to the output as is.
	                              // In the case of using sniffer, it is calculated based on the
	                              // UTC time of the first BLE packet arrival to PC and timestamps from the sniffer.
	uint64_t timestamp;           // The actual UTC timestamp of the packet in microseconds,
	                              // by which BLE air traffic can be analyzed.
	                              // In the case of loading from a pcap file, it is taken from the packet timestamp,
	                              // except for files with the LINKTYPE_NORDIC_BLE header. For such files, only delta time is reliable,
	                              // therefore, the recalculation of the timestamp for each packet is necessary.
	                              // In the case of using the sniffer, this value is calculated in the same way as the previous one.
	uint32_t delta_time;          // It is the time in microseconds between the end of the previous packet and the beginning of the current one.
	                              // If loading the pcap file with the LINKTYPE_NORDIC_BLE header or using nRF Sniffer, a value already exists.
	                              // Otherwise, it is calculated based on the packet timestamps, size and phy.
	ble_phy_t phy;                // BLE phy
	ble_ci_t ci;                  // Coding Indicator for the LE Coded PHY
	int8_t rssi;                  // RSSI
	int8_t channel;               // BLE channel number
	pkt_dir_t dir;                // BLE packet direction
	uint16_t counter_total;       // total packet counter
	uint16_t counter_conn;        // connection event counter
	check_status_t status_crc;    // CRC status
	check_status_t status_mic;    // MIC status
	enc_status_t status_enc;      // packet encryption status
	pdu_type_t pdu;               // packet PDU type (advertising or data)
	pkt_aux_t aux_pdu;            // PDU name for Advertising physical channel PDU header’s PDU Type field = 0b0111
} ble_info_t;


//--------------------------------------------
uint64_t ble_packet_transmission_time_us_calc(ble_info_t *info);

#endif /* BLE_INFO_H_ */
