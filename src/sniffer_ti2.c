/*
* Copyright (c) 2020, 2021 Vladimir Alemasov
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
#include <string.h>     /* memset */
#include "msg_pckt_ble.h"
#include "msg_to_cli.h"
#include "serial.h"
#include "ble.h"
#include "list_adv.h"
#include "tstamp.h"
#include "sniffers.h"

//--------------------------------------------
// TI SmartRF Packet Sniffer 2
// SmartRF Packet Sniffer 2 is a sniffer for Bluetooth 4.x (LE) using TI CC13xx/CC26xx hardware
// http://www.ti.com/tool/PACKET-SNIFFER
// Decryption of encrypted packets is not supported.
// TI SmartRF Packet Sniffer 2 v1.9.0/v1.10.0 firmware.
//--------------------------------------------
// Layout of the Command and Command Response messages:
//  0   |  1   |      2      |   3   |   4   | ...  | n + 4 | n + 5 | n + 6 | n + 7 |
// 0x40 | 0x53 |             |   n <= 255    |              |       | 0x40  |  0x45 |
//     SOF     | Packet Info | Packet Length | Command Data |  FSC  |      EOF      |
//--------------------------------------------
// Layout of the Data Streaming messages:
//  0   |  1   |      2      |   3   |   4   |  5 | ... |  10 | ... |  n + 2 |  n + 3 | n + 4  | n + 5  | n + 6  |
// 0x40 | 0x53 |     0xC0    | 8 < n <= 2049 |                |              |        |        |  0x40  |  0x45  |
//     SOF     | Packet Info | Packet Length | Timestamp (us) | Payload Data |  RSSI  | Status |       EOF       |
//--------------------------------------------
// For BLE packets, the first 8 bytes of the Payload field consists of BLE meta information :
//    0    |     1      |      2      |   3  | 4 | 5 | 6 |  7 |
//         |                          |      |                |
// Channel | Connection Event Counter | Info | Access Address |
//--------------------------------------------
// Layout of the Error messages:
//  0   |  1   |      2      |   3   |   4   |   5   |   6  |  7   |
// 0x40 | 0x53 |     0xC1    |  0x01 |  0x00 |  0x01 | 0x40 | 0x45 |
//     SOF     | Packet Info | Packet Length | Error |     EOF     |

//--------------------------------------------
#define MIN_MSG_SIZE                    8
#define MAX_MSG_SIZE                    SERIAL_BUF_SIZE
#define ERROR_PACKET_SIZE               8
#define CMD_RESP_PACKET_INFO            0x80
#define DATA_PACKET_INFO                0xC0
#define ERROR_PACKET_INFO               0xC1
#define CMD_PING                        { 0x40, 0x53, 0x40, 0x00, 0x00, 0x40, 0x40, 0x45 }
#define CMD_STOP                        { 0x40, 0x53, 0x42, 0x00, 0x00, 0x42, 0x40, 0x45 }
#define CMD_CFG_PHY                     { 0x40, 0x53, 0x47, 0x01, 0x00, 0xFF, 0xFC, 0x40, 0x45 }
#define CMD_CFG_FREQUENCY               { 0x40, 0x53, 0x45, 0x04, 0x00, 0x62, 0x09, 0x00, 0x00, 0xB4, 0x40, 0x45 }
#define CMD_CFG_BLE_INITIATOR_ADDRESS   { 0x40, 0x53, 0x70, 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x40, 0x45 }
#define CMD_START                       { 0x40, 0x53, 0x41, 0x00, 0x00, 0x41, 0x40, 0x45 }

#define CC26X2R                         0x21
#define CC1352R                         0x30
#define CC1352P                         0x50
#define CC26X2R_BLE_PHY_V1_9            0x01
#define CC1352R_BLE_PHY_V1_9            0x0E
#define CC1352P_BLE_PHY_V1_9            0x12
#define CC26X2R_BLE_PHY_V1_10           0x01
#define CC1352R_BLE_PHY_V1_10           0x0F
#define CC1352P_BLE_PHY_V1_10           0x13

//--------------------------------------------
static const uint8_t cmd_ping[] = CMD_PING;
static const uint8_t cmd_stop[] = CMD_STOP;
static uint8_t cmd_cfg_phy[] = CMD_CFG_PHY;
static const uint8_t cmd_cfg_frequency[] = CMD_CFG_FREQUENCY;
static uint8_t cmd_cfg_ble_initiator_address[] = CMD_CFG_BLE_INITIATOR_ADDRESS;
static const uint8_t cmd_start[] = CMD_START;

//--------------------------------------------
typedef enum
{
	SENT_CMD_STOP,
	SENT_CMD_PING,
	SENT_CMD_CFG_PHY,
	SENT_CMD_CFG_FREQUENCY,
	SENT_CMD_CFG_BLE_INITIATOR_ADDRESS,
	SENT_CMD_START
} sniff_last_cmd_t;

//--------------------------------------------
static sniff_last_cmd_t last_cmd = SENT_CMD_STOP;
static HANDLE dev;
static int8_t ble_phy;
static uint8_t initiator_address[DEVICE_ADDRESS_LENGTH] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static list_adv_t *adv_devs;
static uint64_t timestamp_initial_us;
static uint8_t hello;

//--------------------------------------------
static uint8_t fcs_calc(uint8_t *buf, size_t len)
{
	size_t cnt;
	uint8_t fcs;

	for (cnt = 0, fcs = 0; cnt < len; cnt++)
	{
		fcs += buf[cnt];
	}
	return fcs;
}

//--------------------------------------------
static void command_send(uint8_t *buf, size_t len)
{
	switch (last_cmd)
	{
	case SENT_CMD_STOP:
		assert(len == 9);
		serial_write(dev, cmd_ping, sizeof(cmd_ping));
		last_cmd = SENT_CMD_PING;
		break;
	case SENT_CMD_PING:
		assert(len == 15);
		if (buf[10] == 0x9 && buf[11] == 0x1)
		{
			// Version 1.9
			switch (buf[9])
			{
			case CC26X2R:
				ble_phy = CC26X2R_BLE_PHY_V1_9;
				break;
			case CC1352R:
				ble_phy = CC1352R_BLE_PHY_V1_9;
				break;
			case CC1352P:
				ble_phy = CC1352P_BLE_PHY_V1_9;
				break;
			default:
				ble_phy = -1;
				break;
			}
		}
		else if (buf[10] == 0xA && buf[11] == 0x1)
		{
			// Version 1.10
			switch (buf[9])
			{
			case CC26X2R:
				ble_phy = CC26X2R_BLE_PHY_V1_10;
				break;
			case CC1352R:
				ble_phy = CC1352R_BLE_PHY_V1_10;
				break;
			case CC1352P:
				ble_phy = CC1352P_BLE_PHY_V1_10;
				break;
			default:
				ble_phy = -1;
				break;
			}
		}
		else
		{
			// Unknown version
			ble_phy = -1;
		}
		if (ble_phy != -1)
		{
			if (!hello)
			{
				// msg to CLI thread => phy
				msg_to_cli_add_print_command("%s", "TI SmartRF Packet Sniffer 2 hardware detected.\n");
			}
			cmd_cfg_phy[5] = ble_phy;
			cmd_cfg_phy[6] = fcs_calc(&cmd_cfg_phy[2], 4);
			serial_write(dev, cmd_cfg_phy, sizeof(cmd_cfg_phy));
			last_cmd = SENT_CMD_CFG_PHY;
		}
		else
		{
			msg_to_cli_add_print_command("%s", "TI SmartRF Packet Sniffer 2 hardware is incompatible with BLE sniffing.\n");
		}
		break;
	case SENT_CMD_CFG_PHY:
		assert(len == 9);
		serial_write(dev, cmd_cfg_frequency, sizeof(cmd_cfg_frequency));
		last_cmd = SENT_CMD_CFG_FREQUENCY;
		break;
	case SENT_CMD_CFG_FREQUENCY:
		assert(len == 9);
		memcpy(&cmd_cfg_ble_initiator_address[5], &initiator_address[0], 6);
		cmd_cfg_ble_initiator_address[11] = fcs_calc(&cmd_cfg_ble_initiator_address[2], 9);
		serial_write(dev, cmd_cfg_ble_initiator_address, sizeof(cmd_cfg_ble_initiator_address));
		last_cmd = SENT_CMD_CFG_BLE_INITIATOR_ADDRESS;
		break;
	case SENT_CMD_CFG_BLE_INITIATOR_ADDRESS:
		assert(len == 9);
		if (!hello)
		{
			msg_to_cli_add_print_command("%s", "TI SmartRF Packet Sniffer 2 starts.\n");
			hello = 1;
		}
		serial_write(dev, cmd_start, sizeof(cmd_start));
		last_cmd = SENT_CMD_START;
		break;
	case SENT_CMD_START:
		break;
	}
}

//--------------------------------------------
static int packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	uint64_t timestamp_us;
	uint16_t pkt_length;

	// Timestamp(6) + Channel(1) + ConnectionEventCounter(2) + Info(1) + RSSI(1) + Status(1) = 12
	// SOF(2) + PacketInfo(1) + PacketLength(2) + EOF(2) = 7
	pkt_length = ((uint16_t)buf[3] | (uint16_t)(buf[4] << 8)) - 12;
	if (pkt_length != len - 12 - 7)
	{
		return -1;
	}

	if ((*info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return -1;
	}
	memset(*info, 0, sizeof(ble_info_t));

	(*info)->size = pkt_length;
	(*info)->phy = PHY_1M;
	(*info)->channel = buf[11];
	switch (buf[14] & 0x03)
	{
	case 0:
	case 3:
		(*info)->dir = DIR_UNKNOWN;
		break;
	case 1:
		(*info)->dir = DIR_MASTER_SLAVE;
		break;
	case 2:
		(*info)->dir = DIR_SLAVE_MASTER;
		break;
	}
	(*info)->rssi = *(buf + 15 + pkt_length); // RSSI value with a minus sign
	if ((*(buf + 16 + pkt_length)) & 0x80)
	{
		(*info)->status_crc = CHECK_OK;
	}
	else
	{
		(*info)->status_crc = CHECK_FAIL;
	}
	(*info)->status_mic = CHECK_UNKNOWN;
	(*info)->status_enc = ENC_UNKNOWN;

	timestamp_us = (uint64_t)buf[5] | ((uint64_t)buf[6] << 8) | ((uint64_t)buf[7] << 16) |
		((uint64_t)buf[8] << 24) | ((uint64_t)buf[9] << 32) | ((uint64_t)buf[10] << 40);

	if (!timestamp_initial_us)
	{
		timestamp_initial_us = get_usec_since_epoch() - timestamp_us;
	}

	(*info)->timestamp = timestamp_initial_us + timestamp_us;
	(*info)->ts.tv_sec = (long)(((*info)->timestamp) / 1000000);
	(*info)->ts.tv_usec = (long)(((*info)->timestamp) - (uint64_t)((*info)->ts.tv_sec) * 1000000);

	if (((*info)->buf = (uint8_t *)malloc(pkt_length)) == NULL)
	{
		free(*info);
		return -1;
	}
	memcpy((*info)->buf, (buf + 15), pkt_length);

	if (!memcmp(buf + 15, &adv_channel_access_address[0], ACCESS_ADDRESS_LENGTH))
	{
		// advertising channel packet
		uint8_t header_flags;
		uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];

		header_flags = ((*info)->buf)[ACCESS_ADDRESS_LENGTH];
		if ((header_flags & PDU_TYPE_MASK) == ADV_IND)
		{
			memcpy_reverse(adv_addr, &((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH], DEVICE_ADDRESS_LENGTH);
			if (!list_adv_find_addr(&adv_devs, adv_addr))
			{
				list_adv_add(&adv_devs, adv_addr, header_flags & CSA_MASK ? 1 : 0, header_flags & TXADD_MASK ? 1 : 0);
				msg_to_cli_add_follow_device_command(adv_addr, (*info)->rssi, header_flags & TXADD_MASK ? 1 : 0);
			}
		}
	}
	return (int)pkt_length;
}

//--------------------------------------------
static void init(HANDLE hndl)
{
	list_adv_remove_all(&adv_devs);
	timestamp_initial_us = 0;
	hello = 0;
	dev = hndl;
	serial_write(dev, cmd_stop, sizeof(cmd_stop));
	last_cmd = SENT_CMD_STOP;
}

//--------------------------------------------
static int serial_packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	uint16_t pkt_length;
	uint8_t fcs_field;
	uint8_t fcs;

	*info = NULL;

	if (len < MIN_MSG_SIZE)
	{
		return 0;
	}
	if (buf[0] != 0x40 || buf[1] != 0x53)
	{
		return -1;
	}
	fcs_field = 0;
	if (buf[2] == CMD_RESP_PACKET_INFO)
	{
		fcs_field = 1;
	}
	pkt_length = buf[3] | (buf[4] << 8);

	if (pkt_length > MAX_MSG_SIZE - 7U - fcs_field)
	{
		return -1;
	}
	if (len < pkt_length + 7U + fcs_field)
	{
		return 0;
	}
	if (buf[pkt_length + 5 + fcs_field] != 0x40 || buf[pkt_length + 6 + fcs_field] != 0x45)
	{
		return -1;
	}

	switch (buf[2])
	{
	case CMD_RESP_PACKET_INFO:
		fcs = fcs_calc(&buf[2], pkt_length + 3);
		if (fcs != buf[pkt_length + 5])
		{
			break;
		}
		command_send(buf, pkt_length + 8);
		break;
	case DATA_PACKET_INFO:
		if (last_cmd == SENT_CMD_START)
		{
			if (packet_decode(buf, pkt_length + 7, info) < 0)
			{
				return -1;
			}
		}
		break;
	case ERROR_PACKET_INFO:
		break;
	default:
		assert(0);
		return -1;
	}

	return (pkt_length + 7 + fcs_field);
}

//--------------------------------------------
static void follow(uint8_t *buf, size_t size)
{
	list_adv_t *item;

	assert(size == DEVICE_ADDRESS_LENGTH);

	item = list_adv_find_addr(&adv_devs, buf);
	if (item)
	{
		memcpy_reverse(initiator_address, buf, DEVICE_ADDRESS_LENGTH);
	}
	else
	{
		memset(initiator_address, 0, DEVICE_ADDRESS_LENGTH);
	}
	serial_write(dev, cmd_stop, sizeof(cmd_stop));
	last_cmd = SENT_CMD_STOP;
}

//--------------------------------------------
static void close_free(void)
{
	list_adv_remove_all(&adv_devs);
}

//--------------------------------------------
SNIFFER(sniffer_ti2, "T", 3000000, 0, init, serial_packet_decode, follow, NULL, NULL, NULL, close_free);
