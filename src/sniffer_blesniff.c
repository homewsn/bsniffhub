/*
* Copyright (c) 2025 Vladimir Alemasov
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

#include <stdint.h>     /* uint8_t ... uint64_t */
#include <assert.h>     /* assert */
#include <stdlib.h>     /* malloc */
#include <stdio.h>      /* sscanf */
#include <stdbool.h>    /* bool */
#include <string.h>     /* memset */
#include "msg_pckt_ble.h"
#include "msg_to_cli.h"
#include "serial.h"
#include "ble.h"
#include "list_adv.h"
#include "tstamp.h"
#include "sniffers.h"

//--------------------------------------------
// Homewsn BLE sniffer
// Homewsn BLE sniffer is a sniffer for Bluetooth LE using nRF5340 hardware
// Homewsn BLE sniffer v1.0 firmware
//--------------------------------------------
// Layout of the messages:
//  0   |  1   |      2      |   3   |   4   | ...  | n + 4 |
// 0x40 | 0x53 |             |       n       |              |
//     SOF     | Packet Type | Packet Length | Packet Data  |
//--------------------------------------------
// Layout of the BLE packet:
//   0  |  1  |  2  |  3  |   4   |   5   |    6    |  7   |   8   |     9     | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |  19 | ...  | n + 19 |
//   5  |  6  |  7  |  8  |   9   |   10  |    11   |  12  |   13  |     14    | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 |  24 | ...  | n + 24 |
//                        |               |         |      |       |           |                   |                   |     n    |               |
//      Timestamp, us     | Event Counter | Channel | RSSI | Flags | PDU Types |  Access Address   |      CRC Init     | PDU Size |      PDU      |

//--------------------------------------------
#define TS_WRAP_PERIOD          (0x100000000)
#define MSG_HEADER_SIZE         5
#define MIN_MSG_SIZE            MSG_HEADER_SIZE
#define MAX_MSG_SIZE            SERIAL_BUF_SIZE
//--------------------------------------------
#define SYNC_BYTE0              0x55
#define SYNC_BYTE1              0xAA
//--------------------------------------------
#define CMD_RESET               0x01
#define CMD_START               0x02
#define CMD_STOP                0x03
#define CMD_SET_HOP_MAP         0x04
#define CMD_SET_FOLLOW_FILTER   0x05
#define CMD_SET_LTK             0x06
#define CMD_RESET_LTK           0x07
#define CMD_SET_MAC_FILTER      0x08
#define CMD_RESET_MAC_FILTER    0x09
#define CMD_SET_RSSI_FILTER     0x0A
#define CMD_RESET_RSSI_FILTER   0x0B
//--------------------------------------------
#define MSG_BLE_PACKET          0x80
#define MSG_INFO                0x81

//--------------------------------------------
#define CMD_ARRAY_RESET               { SYNC_BYTE0, SYNC_BYTE1, CMD_RESET, 0x00, 0x00 }
#define CMD_ARRAY_START               { SYNC_BYTE0, SYNC_BYTE1, CMD_START, 0x00, 0x00 }
#define CMD_ARRAY_STOP                { SYNC_BYTE0, SYNC_BYTE1, CMD_STOP, 0x00, 0x00 }
#define CMD_ARRAY_SET_HOP_MAP         { SYNC_BYTE0, SYNC_BYTE1, CMD_SET_HOP_MAP, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define CMD_ARRAY_SET_FOLLOW_FILTER   { SYNC_BYTE0, SYNC_BYTE1, CMD_SET_FOLLOW_FILTER, 0x01, 0x00, 0x00 }
#define CMD_ARRAY_SET_LTK             { SYNC_BYTE0, SYNC_BYTE1, CMD_SET_LTK, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define CMD_ARRAY_RESET_LTK           { SYNC_BYTE0, SYNC_BYTE1, CMD_RESET_LTK, 0x00, 0x00 }
#define CMD_ARRAY_SET_MAC_FILTER      { SYNC_BYTE0, SYNC_BYTE1, CMD_SET_MAC_FILTER, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define CMD_ARRAY_RESET_MAC_FILTER    { SYNC_BYTE0, SYNC_BYTE1, CMD_RESET_MAC_FILTER, 0x00, 0x00 }
#define CMD_ARRAY_SET_RSSI_FILTER     { SYNC_BYTE0, SYNC_BYTE1, CMD_SET_RSSI_FILTER, 0x01, 0x00, 0x00 }
#define CMD_ARRAY_RESET_RSSI_FILTER   { SYNC_BYTE0, SYNC_BYTE1, CMD_RESET_RSSI_FILTER, 0x00, 0x00 }

//--------------------------------------------
static const uint8_t cmd_reset[] = CMD_ARRAY_RESET;
static const uint8_t cmd_start[] = CMD_ARRAY_START;
static const uint8_t cmd_stop[] = CMD_ARRAY_STOP;
static uint8_t cmd_set_hop_map[] = CMD_ARRAY_SET_HOP_MAP;
static uint8_t cmd_set_follow_filter[] = CMD_ARRAY_SET_FOLLOW_FILTER;
static uint8_t cmd_set_ltk[] = CMD_ARRAY_SET_LTK;
static const uint8_t cmd_reset_ltk[] = CMD_ARRAY_RESET_LTK;
static uint8_t cmd_set_mac_filter[] = CMD_ARRAY_SET_MAC_FILTER;
static const uint8_t cmd_reset_mac_filter[] = CMD_ARRAY_RESET_MAC_FILTER;
static uint8_t cmd_set_rssi_filter[] = CMD_ARRAY_SET_RSSI_FILTER;
static const uint8_t cmd_reset_rssi_filter[] = CMD_ARRAY_RESET_RSSI_FILTER;

//--------------------------------------------
static HANDLE dev;
static int8_t ble_phy;
static list_adv_t *adv_devs;
static uint64_t timestamp_initial_us;
static uint8_t hello;
static uint8_t ltk[AES128_BLOCK_LENGTH];
static bool decrypt_packet;
static int8_t min_rssi = -128;
static uint8_t adv_channel_map[3];
static uint8_t adv_channel_map_size = 0;
static uint8_t mac_addr[DEVICE_ADDRESS_LENGTH];
static uint8_t mac_filt;
static uint8_t follow_filter;

//--------------------------------------------
static int ble_packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	static uint32_t timestamp_previous_us;
	static size_t timestamp_wraps;
	uint32_t timestamp_us;
	uint32_t crc_init;
	uint16_t pdu_size;

	pdu_size = *(buf + 23) | (*(buf + 24) << 8);
	if (pdu_size != len - 25)
	{
		return -1;
	}

	if ((*info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return -1;
	}
	memset(*info, 0, sizeof(ble_info_t));

	timestamp_us = (uint32_t)buf[5] | ((uint32_t)buf[6] << 8) | ((uint32_t)buf[7] << 16) | ((uint32_t)buf[8] << 24);

	if (!timestamp_initial_us)
	{
		timestamp_initial_us = get_usec_since_epoch() - timestamp_us;
		timestamp_previous_us = 0;
		timestamp_wraps = 0;
		msg_to_cli_add_print_command("%s", "Blesniff hardware detected and started.\n");
	}
	if (timestamp_us < timestamp_previous_us)
	{
		timestamp_wraps++;
	}
	timestamp_previous_us = timestamp_us;

#if 1
	(*info)->timestamp = timestamp_initial_us + timestamp_us + (timestamp_wraps * TS_WRAP_PERIOD);
#else
	(*info)->timestamp = /*timestamp_initial_us + */timestamp_us + (timestamp_wraps * TS_WRAP_PERIOD);
#endif

	(*info)->ts.tv_sec = (long)(((*info)->timestamp) / 1000000);
	(*info)->ts.tv_usec = (long)(((*info)->timestamp) - (uint64_t)((*info)->ts.tv_sec) * 1000000);

	(*info)->channel = *(buf + 11);
	(*info)->rssi = *(buf + 12); // RSSI value with a minus sign
	(*info)->dir = ((*(buf + 13) >> 4) & 0x03) ? DIR_SLAVE_MASTER : DIR_MASTER_SLAVE;
	(*info)->size = pdu_size + ACCESS_ADDRESS_LENGTH + CRC_LENGTH;
	(*info)->status_crc = (*(buf + 13) & 0x01) ? CHECK_OK : CHECK_FAIL;
	(*info)->status_mic = ((*(buf + 13) >> 1) & 0x01) ? CHECK_OK : CHECK_UNKNOWN;
#if 0
	switch ((*(buf + 13) >> 2) & 0x03)
	{
	case 0:
		(*info)->status_enc = ENC_UNENCRYPTED;
		break;
	case 1:
		(*info)->status_enc = ENC_ENCRYPTED;
		break;
	case 2:
		(*info)->status_enc = ENC_DECRYPTED;
		break;
	}
#else
	// The packet will be decrypted if the following conditions are met: see ble_decoder.c line 1226
	(*info)->status_enc = ENC_UNKNOWN;
#endif
	switch ((*(buf + 13) >> 6) & 0x03)
	{
	case 0:
		(*info)->phy = PHY_1M;
		break;
	case 1:
		(*info)->phy = PHY_2M;
		break;
	case 2:
		(*info)->phy = PHY_CODED;
		(*info)->ci = CI_S8;
		break;
	case 3:
		(*info)->phy = PHY_CODED;
		(*info)->ci = CI_S2;
		break;
	}
	(*info)->pdu = (*(buf + 14) >> 4) & 0x0F;
	(*info)->aux_pdu = (*(buf + 14) & 0x0F);
	crc_init = (uint32_t)buf[19] | ((uint32_t)buf[20] << 8) | ((uint32_t)buf[21] << 16) | ((uint32_t)buf[22] << 24);
	(*info)->counter_conn = (uint64_t)buf[9] | ((uint64_t)buf[10] << 8);

	if (((*info)->buf = (uint8_t *)malloc((*info)->size)) == NULL)
	{
		free(*info);
		return -1;
	}
	memcpy((*info)->buf, buf + 15, ACCESS_ADDRESS_LENGTH);
	memcpy((*info)->buf + ACCESS_ADDRESS_LENGTH, buf + 25, (*info)->size - ACCESS_ADDRESS_LENGTH - CRC_LENGTH);

	if ((*info)->channel >= 37)
	{
		// advertising channel packet
		uint8_t header_flags;
		uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];
		header_flags = ((*info)->buf)[ACCESS_ADDRESS_LENGTH];

		if (!mac_filt)
		{
			bool res = false;
			switch (header_flags & PDU_TYPE_MASK)
			{
			case ADV_IND:
			case ADV_DIRECT_IND:
			case ADV_NONCONN_IND:
			case ADV_SCAN_IND:
				memcpy_reverse(adv_addr, &((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH], DEVICE_ADDRESS_LENGTH);
				res = true;
				break;
			case ADV_EXT_IND:
				if (!(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + 1] & EXTENDED_HEADER_ADVERTISING_ADDRESS_Msk))
				{
					break;
				}
				memcpy_reverse(adv_addr, &((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + 2], DEVICE_ADDRESS_LENGTH);
				res = true;
				break;
			default:
				break;
			}
			if (res && !list_adv_find_addr(&adv_devs, adv_addr))
			{
				list_adv_add(&adv_devs, adv_addr, header_flags & CSA_MASK ? 1 : 0, header_flags & TXADD_MASK ? 1 : 0);
				msg_to_cli_add_follow_device_command(adv_addr, (*info)->rssi, header_flags & TXADD_MASK ? 1 : 0);
			}
		}
	}

	if ((*info)->status_crc)
	{
		uint32_t crc;
		uint8_t *crc_buf;
		crc = ble_crc_gen(bits_reverse(crc_init) >> 8, (*info)->buf + ACCESS_ADDRESS_LENGTH, (*info)->size - ACCESS_ADDRESS_LENGTH - CRC_LENGTH);
		crc_buf = (*info)->buf + (*info)->size - CRC_LENGTH;
		*crc_buf++ = (uint8_t)crc;
		*crc_buf++ = (uint8_t)(crc >> 8);
		*crc_buf = (uint8_t)(crc >> 16);
	}
	return (int)(*info)->size;
}

//--------------------------------------------
static void init(HANDLE hndl)
{
	list_adv_remove_all(&adv_devs);
	timestamp_initial_us = 0;
	hello = 0;
	dev = hndl;

	serial_write(dev, cmd_reset, sizeof(cmd_reset));
	sleep(1);
	if (min_rssi != -128)
	{
		cmd_set_rssi_filter[5] = (uint8_t)min_rssi;
		serial_write(dev, cmd_set_rssi_filter, sizeof(cmd_set_rssi_filter));
		sleep(1);
	}
	if (adv_channel_map_size > 0)
	{
		cmd_set_hop_map[5] = adv_channel_map_size;
		for (size_t cnt = 0; cnt < adv_channel_map_size; cnt++)
		{
			cmd_set_hop_map[6 + cnt] = adv_channel_map[cnt];
		}
		serial_write(dev, cmd_set_hop_map, sizeof(cmd_set_hop_map));
		sleep(1);
	}
	if (decrypt_packet)
	{
		memcpy(&cmd_set_ltk[5], ltk, sizeof(ltk));
		serial_write(dev, cmd_set_ltk, sizeof(cmd_set_ltk));
		sleep(1);
	}
	if (mac_filt)
	{
		memcpy(&cmd_set_mac_filter[5], mac_addr, sizeof(mac_addr));
		serial_write(dev, cmd_set_mac_filter, sizeof(cmd_set_mac_filter));
		sleep(1);
	}
	if (follow_filter)
	{
		cmd_set_follow_filter[5] = follow_filter;
		serial_write(dev, cmd_set_follow_filter, sizeof(cmd_set_follow_filter));
		sleep(1);
	}
	serial_write(dev, cmd_start, sizeof(cmd_start));
}

//--------------------------------------------
static void reset(void)
{
	min_rssi = -128;
	adv_channel_map_size = 0;
	decrypt_packet = false;
	mac_filt = false;
	follow_filter = false;
}

//--------------------------------------------
static int serial_packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	uint16_t pkt_length;

	*info = NULL;

	if (!len || buf[0] != SYNC_BYTE0)
	{
		return -1;
	}
	if (len < MIN_MSG_SIZE)
	{
		return 0;
	}
	if (buf[1] != SYNC_BYTE1)
	{
		return -1;
	}
	pkt_length = buf[3] | (buf[4] << 8);

	if (pkt_length > MAX_MSG_SIZE - MSG_HEADER_SIZE)
	{
		return -1;
	}
	if (len < pkt_length + MSG_HEADER_SIZE)
	{
		return 0;
	}

	switch (buf[2])
	{
	case MSG_BLE_PACKET:
		if (ble_packet_decode(buf, pkt_length + MSG_HEADER_SIZE, info) < 0)
		{
			return -1;
		}
		break;
	default:
		assert(0);
		return -1;
	}

	return (pkt_length + MSG_HEADER_SIZE);
}

//--------------------------------------------
static void follow_device(uint8_t *buf, size_t size)
{
	list_adv_t *item;

	assert(size == DEVICE_ADDRESS_LENGTH);

	item = list_adv_find_addr(&adv_devs, buf);
	if (item)
	{
		memcpy_reverse(&cmd_set_mac_filter[5], buf, DEVICE_ADDRESS_LENGTH);
		serial_write(dev, cmd_set_mac_filter, sizeof(cmd_set_mac_filter));
		mac_filt = 1;
	}
	else
	{
		serial_write(dev, cmd_reset_mac_filter, sizeof(cmd_reset_mac_filter));
		mac_filt = 0;
	}
}

//--------------------------------------------
static void ltk_set(uint8_t *buf, size_t size, bool send)
{
	size_t cnt;

	assert(size == 32 || size == 33);

	for (cnt = 0; cnt < size / 2; cnt++, buf += 2)
	{
		sscanf(buf, "%2hhx", &ltk[cnt]);
	}
	decrypt_packet = true;
	if (send)
	{
		memcpy(&cmd_set_ltk[5], ltk, sizeof(ltk));
		serial_write(dev, cmd_set_ltk, sizeof(cmd_set_ltk));
	}
}

//--------------------------------------------
static void min_rssi_set(int8_t rssi)
{
	min_rssi = rssi;
}

//--------------------------------------------
static void adv_channel_set(uint8_t *hop_map, uint8_t hop_map_size)
{
	memcpy(adv_channel_map, hop_map, hop_map_size);
	adv_channel_map_size = hop_map_size;
}

//--------------------------------------------
static void mac_addr_set(uint8_t *buf, uint8_t addr_type)
{
	memcpy_reverse(mac_addr, buf, DEVICE_ADDRESS_LENGTH);
	mac_filt = 1;
}

//--------------------------------------------
void follow_filter_set(uint8_t filter)
{
	follow_filter = filter;
}

//--------------------------------------------
static void close_free(void)
{
	list_adv_remove_all(&adv_devs);
}

//--------------------------------------------
SNIFFER(sniffer_blesniff, "B", 1000000, 0, init, reset, serial_packet_decode, follow_device, NULL, NULL, ltk_set,\
	    min_rssi_set, adv_channel_set, mac_addr_set, NULL, follow_filter_set, close_free);
