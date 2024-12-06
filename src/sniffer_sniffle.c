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

#include <stdint.h>     /* uint8_t ... uint64_t */
#include <assert.h>     /* assert */
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memset */
#include "msg_pckt_ble.h"
#include "msg_to_cli.h"
#include "serial.h"
#include "ble.h"
#include "base64.h"
#include "list_adv.h"
#include "tstamp.h"
#include "sniffers.h"

//--------------------------------------------
// Sniffle
// Sniffle is a sniffer for Bluetooth 5 and 4.x (LE) using TI CC1352/CC26x2 hardware
// https://github.com/nccgroup/Sniffle
// Decryption of encrypted packets is not supported.
// Sniffle v1.6/v1.7 firmware.
//--------------------------------------------
// Layout of the decoded message:
//            0            |    1    | 2  | 3  | 4 | 5  |    6    |   7    |     8   |   9    |  10  |     11      | ... | n + 12 |
//                         |         |                  |         n        |                  |      |             |              |
// Number of 4-byte chunks | MsgType | Timestamp LE, us | Length/Direction | Conn event count | RSSI | Channel/Phy |     Data     |

//--------------------------------------------
#define MAX_MSG_SIZE            SERIAL_BUF_SIZE
#define TS_WRAP_PERIOD          (0x100000000 / 4)

//--------------------------------------------
#define COMMAND_SETCHANAAPHY    0x10
#define COMMAND_PAUSEDONE       0x11
#define COMMAND_RSSIFILT        0x12
#define COMMAND_MACFILT         0x13
#define COMMAND_ADVHOP          0x14
#define COMMAND_FOLLOW          0x15
#define COMMAND_AUXADV          0x16
#define COMMAND_RESET           0x17
#define COMMAND_MARKER          0x18

//--------------------------------------------
#define MESSAGE_BLEFRAME        0x10
#define MESSAGE_DEBUG           0x11
#define MESSAGE_MARKER          0x12
#define MESSAGE_STATE           0x13
#define MESSAGE_MEASURE         0x14

//--------------------------------------------
static HANDLE dev;
static uint8_t cmd_buf[MAX_MSG_SIZE];
static list_adv_t *adv_devs;
static uint64_t timestamp_initial_us;
static int8_t min_rssi = -128;
static uint8_t aux_adv;
static uint8_t adv_channel = 37;
static uint8_t mac_addr[DEVICE_ADDRESS_LENGTH];
static uint8_t mac_filt;

//--------------------------------------------
static int command_send(uint8_t *buf, size_t size)
{
	int res;

	assert(size < MAX_MSG_SIZE);
	buf[0] = (uint8_t)(((size - 1) + 3) / 3);
	res = (int)base64_encode(cmd_buf, buf, (unsigned long)size);
	assert(res + 2 < MAX_MSG_SIZE);
	cmd_buf[res] = '\r';
	cmd_buf[res + 1] = '\n';
	return serial_write(dev, cmd_buf, res + 2);
}

//--------------------------------------------
static int command_sync_send(void)
{
	char buf[] = "@@@@@@@@\r\n";

	return serial_write(dev, buf, strlen(buf));
}

//--------------------------------------------
// Set advertising channel, address, phy and crc_init to listen on
static int command_set_chan_aa_phy_send(uint8_t chan, uint8_t *adv_addr, ble_phy_t phy, uint32_t crc_init)
{
	uint8_t buf[12];

	assert(chan <= 39);
	assert(phy >= PHY_1M && phy <= PHY_CODED);
	buf[1] = COMMAND_SETCHANAAPHY;
	buf[2] = chan;
	memcpy(&buf[3], adv_addr, ACCESS_ADDRESS_LENGTH);
	buf[7] = phy;
	buf[8] = (crc_init & 0xFF);
	buf[9] = (crc_init & 0xFF00) >> 8;
	buf[10] = (crc_init & 0xFF0000) >> 16;
	buf[11] = (crc_init & 0xFF000000) >> 24;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Pause sniffer after disconnect
static int command_pause_done_send(uint8_t pause_when_done)
{
	uint8_t buf[3];

	buf[1] = COMMAND_PAUSEDONE;
	buf[2] = pause_when_done ? 1 : 0;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Filter packets by minimum RSSI
static int command_rssi_filt_send(uint8_t rssi)
{
	uint8_t buf[3];

	buf[1] = COMMAND_RSSIFILT;
	buf[2] = rssi;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Reset MAC filter
static int command_mac_filt_reset_send(void)
{
	uint8_t buf[2];

	buf[1] = COMMAND_MACFILT;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Filter packets by advertiser MAC
static int command_mac_filt_send(uint8_t *dev_addr)
{
	uint8_t buf[8];

	buf[1] = COMMAND_MACFILT;
	memcpy(&buf[2], dev_addr, DEVICE_ADDRESS_LENGTH);
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Sniff all advertisements on channels 37-39
static int command_adv_hop_send(void)
{
	uint8_t buf[2];

	buf[1] = COMMAND_ADVHOP;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Sniff advertisements, then follow connections or not
static int command_follow_send(uint8_t follow)
{
	uint8_t buf[3];

	buf[1] = COMMAND_FOLLOW;
	buf[2] = follow ? 1 : 0;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Capture BT5 extended (auxiliary) advertising or not
static int command_aux_adv_send(uint8_t aux_adv)
{
	uint8_t buf[3];

	buf[1] = COMMAND_AUXADV;
	buf[2] = aux_adv ? 1 : 0;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Reset CPU
static int command_reset_send(void)
{
	uint8_t buf[2];

	buf[1] = COMMAND_RESET;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
// Zero timestamps and flush old packets
static int command_mark_and_flash_send(void)
{
	uint8_t buf[2];

	buf[1] = COMMAND_MARKER;
	return command_send(buf, sizeof(buf));
}

//--------------------------------------------
static int packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	static uint8_t data_channel_access_address[ACCESS_ADDRESS_LENGTH];
	static uint32_t data_channel_crc_init;
	static uint32_t timestamp_previous_us;
	static size_t timestamp_wraps;
	static int data_pdu;
	uint32_t timestamp_us;
	uint16_t length;

	switch (buf[1])
	{
	case MESSAGE_BLEFRAME:
		break;
	case MESSAGE_DEBUG:
		return 0;
	case MESSAGE_MARKER:
		return 0;
	case MESSAGE_STATE:
		return 0;
	case MESSAGE_MEASURE:
		return 0;
	default:
		// unknown message
#if 0
		assert(0);
#endif
		return 0;
	}
	length = *(buf + 6) | (((*(buf + 7)) & 0x7F) << 8);
	if (length != len - 12)
	{
		return -1;
	}

	if ((*info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return -1;
	}
	memset(*info, 0, sizeof(ble_info_t));

	timestamp_us = (uint32_t)buf[2] | ((uint32_t)buf[3] << 8) | ((uint32_t)buf[4] << 16) | ((uint32_t)buf[5] << 24);

	if (!timestamp_initial_us)
	{
		timestamp_initial_us = get_usec_since_epoch() - timestamp_us;
		timestamp_previous_us = 0;
		timestamp_wraps = 0;
		msg_to_cli_add_print_command("%s", "Sniffle hardware detected and started.\n");
	}

	if (timestamp_us < timestamp_previous_us)
	{
		timestamp_wraps++;
	}
	timestamp_previous_us = timestamp_us;

	(*info)->timestamp = timestamp_initial_us + timestamp_us + (timestamp_wraps * TS_WRAP_PERIOD);
	(*info)->ts.tv_sec = (long)(((*info)->timestamp) / 1000000);
	(*info)->ts.tv_usec = (long)(((*info)->timestamp) - (uint64_t)((*info)->ts.tv_sec) * 1000000);

	(*info)->dir = ((*(buf + 7) & 0x80) >> 7) ? DIR_SLAVE_MASTER : DIR_MASTER_SLAVE;
	(*info)->size = length + ACCESS_ADDRESS_LENGTH + CRC_LENGTH;
	(*info)->rssi = *(buf + 10); // RSSI value with a minus sign
	(*info)->status_crc = CHECK_OK;
	(*info)->status_mic = CHECK_UNKNOWN;
	(*info)->status_enc = ENC_UNKNOWN;
	switch ((*(buf + 11) >> 6))
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
	(*info)->channel = (*(buf + 11) & 0x3F);

	if (((*info)->buf = (uint8_t *)malloc((*info)->size)) == NULL)
	{
		free(*info);
		return -1;
	}
	memcpy((*info)->buf + ACCESS_ADDRESS_LENGTH, buf + 12, (*info)->size - ACCESS_ADDRESS_LENGTH - CRC_LENGTH);

	if ((*info)->channel >= 37)
	{
		// advertising channel packet
		uint8_t header_flags;
		uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];

		memcpy((*info)->buf, adv_channel_access_address, ACCESS_ADDRESS_LENGTH);
		if (((((*info)->buf)[ACCESS_ADDRESS_LENGTH]) & PDU_TYPE_MASK) == CONNECT_IND)
		{
			data_pdu = 1;
			memcpy(&data_channel_access_address[0], (*info)->buf + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH, ACCESS_ADDRESS_LENGTH);
			data_channel_crc_init = (((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH]) |
				(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 1] << 8) |
				(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 2] << 16);
		}
		else
		{
			data_pdu = 0;
		}

		(*info)->dir = DIR_UNKNOWN;

		header_flags = ((*info)->buf)[ACCESS_ADDRESS_LENGTH];
		if (((header_flags & PDU_TYPE_MASK) == ADV_IND) && !mac_filt)
		{
			memcpy_reverse(adv_addr, &((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH], DEVICE_ADDRESS_LENGTH);
			if (!list_adv_find_addr(&adv_devs, adv_addr))
			{
				list_adv_add(&adv_devs, adv_addr, header_flags & CSA_MASK ? 1 : 0, header_flags & TXADD_MASK ? 1 : 0);
				msg_to_cli_add_follow_device_command(adv_addr, (*info)->rssi, header_flags & TXADD_MASK ? 1 : 0);
			}
		}
	}
	else
	{
		if (data_pdu)
		{
			memcpy((*info)->buf, data_channel_access_address, ACCESS_ADDRESS_LENGTH);
		}
		else
		{
			memcpy((*info)->buf, adv_channel_access_address, ACCESS_ADDRESS_LENGTH);
			if (((((*info)->buf)[ACCESS_ADDRESS_LENGTH]) & PDU_TYPE_MASK) == AUX_CONNECT_REQ)
			{
				memcpy(data_channel_access_address, (*info)->buf + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH, ACCESS_ADDRESS_LENGTH);
				data_channel_crc_init = (((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH]) |
					(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 1] << 8) |
					(((*info)->buf)[ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH + ACCESS_ADDRESS_LENGTH + 2] << 16);
			}
			else if (((((*info)->buf)[ACCESS_ADDRESS_LENGTH]) & PDU_TYPE_MASK) == AUX_CONNECT_RSP)
			{
				data_pdu = 1;
			}
		}
	}
	if ((*info)->status_crc)
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
	command_sync_send();
	command_set_chan_aa_phy_send(adv_channel, (uint8_t *)adv_channel_access_address, PHY_1M, ADV_CHANNEL_CRC_INIT);
	command_rssi_filt_send(min_rssi);
	command_pause_done_send(0);
	command_follow_send(1);
	if (mac_filt)
	{
		command_mac_filt_send(mac_addr);
	}
	else
	{
		command_mac_filt_reset_send();
	}
	command_aux_adv_send(aux_adv);
	command_mark_and_flash_send();
}

//--------------------------------------------
static int serial_packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	size_t cnt;
	long res;
	static uint8_t msg_buf[MAX_MSG_SIZE];

	if (len > MAX_MSG_SIZE)
	{
		assert(0);
		return -1;
	}

	*info = NULL;

	for (cnt = 0; cnt < len; cnt++)
	{
		if (*(buf + cnt) == '\n')
		{
			if ((res = base64_decode(&msg_buf[0], buf, (unsigned long)(cnt - 1))) < 0)
			{
				return -1;
			}
			if ((res = packet_decode(&msg_buf[0], (size_t)res, info)) < 0)
			{
				return -1;
			}
			return (int)(cnt + 1);
		}
	}
	return 0;
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
		command_set_chan_aa_phy_send(adv_channel, (uint8_t *)adv_channel_access_address, PHY_1M, ADV_CHANNEL_CRC_INIT);
		command_pause_done_send(0);
		command_follow_send(1);
		memcpy_reverse(adv_addr, buf, DEVICE_ADDRESS_LENGTH);
		command_mac_filt_send(adv_addr);
		command_adv_hop_send();
		command_aux_adv_send(aux_adv);
		command_mark_and_flash_send();
	}
	else
	{
		command_set_chan_aa_phy_send(adv_channel, (uint8_t *)adv_channel_access_address, PHY_1M, ADV_CHANNEL_CRC_INIT);
		command_rssi_filt_send(min_rssi);
		command_pause_done_send(0);
		command_follow_send(1);
		command_mac_filt_reset_send();
		command_aux_adv_send(aux_adv);
		command_mark_and_flash_send();
	}
}

//--------------------------------------------
static void min_rssi_set(int8_t rssi)
{
	min_rssi = rssi;
}

//--------------------------------------------
static void adv_channel_set(uint8_t channel)
{
	adv_channel = channel;
}

//--------------------------------------------
static void mac_addr_set(uint8_t *buf, uint8_t addr_type)
{
	memcpy_reverse(mac_addr, buf, DEVICE_ADDRESS_LENGTH);
	mac_filt = 1;
}

//--------------------------------------------
static void follow_aux_connect(uint8_t follow)
{
	aux_adv = follow;
}

//--------------------------------------------
static void close_free(void)
{
	list_adv_remove_all(&adv_devs);
}

//--------------------------------------------
SNIFFER(sniffer_sniffle, "S", 2000000, 0, init, serial_packet_decode, follow, NULL, NULL, NULL,\
	    min_rssi_set, adv_channel_set, mac_addr_set, follow_aux_connect, close_free);
