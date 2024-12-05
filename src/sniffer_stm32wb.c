/*
* Copyright (c) 2024 Vladimir Alemasov
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
#include <string.h>     /* memset */
#include "msg_pckt_ble.h"
#include "msg_to_cli.h"
#include "serial.h"
#include "ble.h"
#include "list_adv.h"
#include "tstamp.h"
#include "sniffers.h"

//--------------------------------------------
// STM32WB BLE Sniffer
// STM32WB BLE Sniffer is a sniffer for Bluetooth 5 and 4.x (LE) using STM32WB55 hardware
// https://github.com/stm32-hotspot/STM32WB-BLE-Sniffer
// Decryption of encrypted packets is supported (Passkey, OOB key or LTK is needed).
// STM32WB BLE Sniffer v1.0.0 firmware.
//--------------------------------------------

//--------------------------------------------
#define MIN_MSG_SIZE            5
#define MAX_MSG_SIZE            SERIAL_BUF_SIZE
#define TS_WRAP_PERIOD          (0x100000000 / 4)

//--------------------------------------------
#define DATA_PAYLOAD            0x0D01
#define MESSAGE_EVENT           0x0D02

//--------------------------------------------
static HANDLE dev;
static list_adv_t *adv_devs;
static uint64_t timestamp_initial_us;
static int8_t min_rssi = -128;
static uint8_t adv_channel = 39;

//--------------------------------------------
static int command_set_enable_send(uint8_t state, uint8_t channel)
{
	uint8_t buf[6];

	buf[0] = 0x01; // HCI command packet type
	buf[1] = 0x01; // Opcode (LSB)
	buf[2] = 0x1D;
	buf[3] = 0x02; // Parameters length
	buf[4] = state; // State
	buf[5] = channel; // Channel index
	return serial_write(dev, buf, 6);
}

//--------------------------------------------
static int command_set_sniffer_target_send(uint8_t *dev_addr)
{
	uint8_t buf[10];

	buf[0] = 0x01; // HCI command packet type
	buf[1] = 0x02; // Opcode (LSB)
	buf[2] = 0x1D;
	buf[3] = DEVICE_ADDRESS_LENGTH; // Parameters length
	memcpy(&buf[4], dev_addr, DEVICE_ADDRESS_LENGTH);
	return serial_write(dev, buf, DEVICE_ADDRESS_LENGTH + 4);
}

//--------------------------------------------
static int packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	static uint32_t timestamp_previous_us;
	static size_t timestamp_wraps;
	static uint32_t data_channel_crc_init;
	uint16_t opcode;
	uint32_t timestamp_us;

	opcode = ((uint16_t)buf[3] | ((uint16_t)buf[4] << 8));
	switch (opcode)
	{
	case DATA_PAYLOAD:
		break;
	case MESSAGE_EVENT:
		return 0;
	default:
		// unknown message
#if 1
		assert(0);
#endif
		return 0;
	}

	if ((*info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return -1;
	}
	memset(*info, 0, sizeof(ble_info_t));

	timestamp_us = (uint32_t)buf[10] | ((uint32_t)buf[11] << 8) | ((uint32_t)buf[12] << 16) | ((uint32_t)buf[13] << 24);

	if (!timestamp_initial_us)
	{
		timestamp_initial_us = get_usec_since_epoch() - timestamp_us;
		timestamp_previous_us = 0;
		timestamp_wraps = 0;
		msg_to_cli_add_print_command("%s", "STM32WB hardware detected and started.\n");
	}

	if (timestamp_us < timestamp_previous_us)
	{
		timestamp_wraps++;
	}
	timestamp_previous_us = timestamp_us;

	(*info)->timestamp = timestamp_initial_us + timestamp_us + (timestamp_wraps * TS_WRAP_PERIOD);
	(*info)->ts.tv_sec = (long)(((*info)->timestamp) / 1000000);
	(*info)->ts.tv_usec = (long)(((*info)->timestamp) - (uint64_t)((*info)->ts.tv_sec) * 1000000);

	(*info)->rssi = buf[5]; // RSSI value with a minus sign
	(*info)->channel = buf[6];
	(*info)->counter_conn = buf[7] | (buf[8] << 8);
	(*info)->status_crc = (buf[9] & 0x01) ? CHECK_OK : CHECK_FAIL;
	(*info)->dir = ((buf[9] & 0x02)/* >> 1*/) ? DIR_SLAVE_MASTER : DIR_MASTER_SLAVE;
	(*info)->phy = ((buf[9] & 0x04)/* >> 2*/) ? PHY_2M : PHY_1M;
	(*info)->status_enc = ((buf[9] & 0x08)/* >> 3*/) ? ENC_ENCRYPTED : ENC_UNENCRYPTED;

	if ((*info)->rssi < min_rssi)
	{
		free(*info);
		return -1;
	}

	(*info)->size = buf[15] + CRC_LENGTH;
	if (((*info)->buf = (uint8_t *)malloc((*info)->size)) == NULL)
	{
		free(*info);
		return -1;
	}
	memcpy((*info)->buf, buf + 16, (*info)->size - CRC_LENGTH);

	if ((*info)->channel >= 37)
	{
		// advertising channel packet
		uint8_t header_flags;
		uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];

		if (((((*info)->buf)[ACCESS_ADDRESS_LENGTH]) & PDU_TYPE_MASK) == CONNECT_IND)
		{
			data_channel_crc_init = (((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH]) |
				(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 1] << 8) |
				(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 2] << 16);
		}

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

	if ((*info)->status_crc == CHECK_OK)
	{
		uint32_t crc;
		uint8_t *crc_buf;
		uint32_t crc_init = ((*info)->channel >= 37) ? ADV_CHANNEL_CRC_INIT : data_channel_crc_init;
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
	dev = hndl;
	command_set_enable_send(0, 37);
	sleep(1);
	command_set_enable_send(1, adv_channel);
}

//--------------------------------------------
static int serial_packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	uint8_t length;
	int pkt_length;

	*info = NULL;

	if (len > MAX_MSG_SIZE)
	{
		assert(0);
		return -1;
	}

	if (len < MIN_MSG_SIZE)
	{
		return 0;
	}
	if (buf[0] != 0x04 || buf[1] != 0xFF)
	{
		return -1;
	}
	length = buf[2];
	pkt_length = length + 3;
	if (len < pkt_length)
	{
		return 0;
	}

	if (packet_decode(buf, pkt_length, info) < 0)
	{
		return -1;
	}

	return pkt_length;
}

//--------------------------------------------
static void follow(uint8_t *buf, size_t size)
{
	list_adv_t *item;
	uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];

	assert(size == DEVICE_ADDRESS_LENGTH);

	item = list_adv_find_addr(&adv_devs, buf);
	if (item)
	{
		memcpy_reverse(adv_addr, buf, DEVICE_ADDRESS_LENGTH);
	}
	else
	{
		memset(adv_addr, 0, DEVICE_ADDRESS_LENGTH);
	}

	command_set_sniffer_target_send(adv_addr);
}

//--------------------------------------------
static void min_rssi_set(int8_t rssi)
{
	min_rssi = rssi;
}

//--------------------------------------------
static void close_free(void)
{
	list_adv_remove_all(&adv_devs);
}

//--------------------------------------------
SNIFFER(sniffer_stm32wb, "WB", 921600, 0, init, serial_packet_decode, follow, NULL, NULL, NULL, min_rssi_set, NULL, close_free);
