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
// nRF Sniffer for Bluetooth LE
// nRF Sniffer for Bluetooth LE is a sniffer for Bluetooth 5 and 4.x (LE) using nRF52840 hardware
// https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Sniffer-for-Bluetooth-LE
// Decryption of encrypted packets is supported (Passkey or OOB key is needed).
// nRF Sniffer for Bluetooth LE 3 firmware (UART protocol version 2).
//--------------------------------------------
// Layout of the decoded message:
//   0    |   1   |         2        |   3   |   4    |      5      | ...  | n + 5 |
//        n       |         2        |                |             |              |
// Payload Length | Protocol Version | Packet Counter | Packet Type |    Payload   |
//--------------------------------------------
// Layout of the BLE packet payload:
// [BLE packet header][BLE packet]
//--------------------------------------------
// Layout of the BLE packet header:
//       0       |   1   |    2    |  3   |   4   |   5   | 6 | 7 | 8 | 9 |
//      0x0A     |       |         |      |               |               |
// Header Length | Flags | Channel | RSSI | Event Counter |   Time Diff   |
//--------------------------------------------
// Layout of the BLE packet:
// {AA x 4}[HEADER][LEN][PADDING]{ PAYLOAD x LEN } {CRC x 3}
// Note: Padding byte is added by radio and is not received on air. It should be removed after reception on UART.

//--------------------------------------------
#define MAX_MSG_SIZE                    SERIAL_BUF_SIZE
#define MSG_HEADER_SIZE                 6

#define REQ_FOLLOW                      0x00
#define EVENT_FOLLOW                    0x01
#define EVENT_CONNECT                   0x05
#define EVENT_PACKET                    0x06
#define REQ_SCAN_CONT                   0x07
#define EVENT_DISCONNECT                0x09
#define SET_TEMPORARY_KEY               0x0C
#define PING_REQ                        0x0D
#define PING_RESP                       0x0E
#define SET_ADV_CHANNEL_HOP_SEQ         0x17

#define SLIP_START                      0xAB
#define SLIP_END                        0xBC
#define SLIP_ESC                        0xCD
#define SLIP_ESC_START                  0xAC
#define SLIP_ESC_END                    0xBD
#define SLIP_ESC_ESC                    0xCE

//--------------------------------------------
typedef enum
{
	SENT_CMD_PING_REQ,
	SENT_CMD_REQ_SCAN_CONT
} sniff_last_cmd_t;

//--------------------------------------------
static const uint8_t adv_channels[] = { 0x25, 0x26, 0x27 };
static const uint8_t tmp_key[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

//--------------------------------------------
static sniff_last_cmd_t last_cmd = SENT_CMD_PING_REQ;
static HANDLE dev;
static uint8_t cmd_buf[MAX_MSG_SIZE];
static uint16_t host_to_sniffer_msg_cnt;
static list_adv_t *adv_devs;
static uint64_t timestamp_us;
static int8_t min_rssi = -128;
static uint8_t adv_channel;
static uint8_t mac_addr[DEVICE_ADDRESS_LENGTH];
static uint8_t mac_addr_type;
static uint8_t mac_filt;

//--------------------------------------------
static int slip_encode(uint8_t *dst, const uint8_t *src, size_t src_len)
{
	size_t src_cnt, dst_cnt;

	// length verification
	if (src_len > MAX_MSG_SIZE)
	{
		assert(0);
	}
	for (src_cnt = 0, dst_cnt = 0; src_cnt < src_len; src_cnt++, dst_cnt++)
	{
		switch (src[src_cnt])
		{
		case SLIP_START:
		case SLIP_END:
		case SLIP_ESC:
			dst_cnt++;
			break;
		}
	}
	dst_cnt += 2;
	if (dst_cnt > MAX_MSG_SIZE)
	{
		assert(0);
	}

	// encoding
	dst_cnt = 0;
	dst[dst_cnt++] = SLIP_START;
	for (src_cnt = 0; src_cnt < src_len; src_cnt++, dst_cnt++)
	{
		switch (src[src_cnt])
		{
		case SLIP_START:
			dst[dst_cnt++] = SLIP_ESC;
			dst[dst_cnt] = SLIP_ESC_START;
			break;
		case SLIP_END:
			dst[dst_cnt++] = SLIP_ESC;
			dst[dst_cnt] = SLIP_ESC_END;
			break;
		case SLIP_ESC:
			dst[dst_cnt++] = SLIP_ESC;
			dst[dst_cnt] = SLIP_ESC_ESC;
			break;
		default:
			dst[dst_cnt] = src[src_cnt];
			break;
		}
	}
	dst[dst_cnt++] = SLIP_END;
	return (int)dst_cnt;
}

//--------------------------------------------
static int slip_decode(uint8_t *dst, const uint8_t *src, size_t src_len)
{
	size_t src_cnt, dst_cnt;

	if (src_len > MAX_MSG_SIZE)
	{
		assert(0);
	}

	for (src_cnt = 0, dst_cnt = 0; src_cnt < src_len; src_cnt++)
	{
		switch (src[src_cnt])
		{
		case SLIP_START:
		case SLIP_END:
			continue;
		case SLIP_ESC:
			switch (src[++src_cnt])
			{
			case SLIP_ESC_START:
				dst[dst_cnt++] = SLIP_START;
				break;
			case SLIP_ESC_END:
				dst[dst_cnt++] = SLIP_END;
				break;
			case SLIP_ESC_ESC:
				dst[dst_cnt++] = SLIP_ESC;
				break;
			default:
				assert(0);
				return -1;
			}
			break;
		default:
			dst[dst_cnt++] = src[src_cnt];
			break;
		}
	}
	return (int)src_len;
}

//--------------------------------------------
static int command_ping_req_v1_send(void)
{
	int res;
	uint8_t buf[6];

	buf[0] = 6; // Header length
	buf[1] = 0; // Payload length
	buf[2] = 1; // UART protocol version used
	buf[3] = host_to_sniffer_msg_cnt & 0xFF; // Packet Counter (LSB)
	buf[4] = host_to_sniffer_msg_cnt >> 8;
	buf[5] = PING_REQ; // Packet type
	res = slip_encode(cmd_buf, buf, sizeof(buf));
	host_to_sniffer_msg_cnt++;
	return serial_write(dev, cmd_buf, res);
}

//--------------------------------------------
static int command_set_adv_channel_hop_seq_v1_send(const uint8_t *adv_chans, uint8_t adv_chans_size)
{
	int res;
	uint8_t buf[10];

	assert(adv_chans);
	if (adv_chans_size > 3 || adv_chans_size < 1)
	{
		assert(0);
		return -1;
	}
	buf[0] = 6; // Header length
	buf[1] = 1 + adv_chans_size; // Payload length
	buf[2] = 1; // UART protocol version used
	buf[3] = host_to_sniffer_msg_cnt & 0xFF; // Packet Counter (LSB)
	buf[4] = host_to_sniffer_msg_cnt >> 8;
	buf[5] = SET_ADV_CHANNEL_HOP_SEQ; // Packet type
	buf[6] = adv_chans_size;
	memcpy(&buf[7], adv_chans, adv_chans_size);
	res = slip_encode(cmd_buf, buf, 7 + adv_chans_size);
	host_to_sniffer_msg_cnt++;
	return serial_write(dev, cmd_buf, res);
}

//--------------------------------------------
static int command_req_scan_cont_v1_send(void)
{
	int res;
	uint8_t buf[6];

	buf[0] = 6; // Header length
	buf[1] = 0; // Payload length
	buf[2] = 1; // UART protocol version used
	buf[3] = host_to_sniffer_msg_cnt & 0xFF; // Packet Counter (LSB)
	buf[4] = host_to_sniffer_msg_cnt >> 8;
	buf[5] = REQ_SCAN_CONT; // Packet type
	res = slip_encode(cmd_buf, buf, sizeof(buf));
	host_to_sniffer_msg_cnt++;
	return serial_write(dev, cmd_buf, res);
}

//--------------------------------------------
static int command_set_temporary_key_v1_send(const uint8_t *key, uint8_t key_size)
{
	int res;
	uint8_t buf[6 + 16];

	assert(key);
	if (key_size != 16)
	{
		assert(0);
		return -1;
	}
	buf[0] = 6; // Header length
	buf[1] = key_size; // Payload length
	buf[2] = 1; // UART protocol version used
	buf[3] = host_to_sniffer_msg_cnt & 0xFF; // Packet Counter (LSB)
	buf[4] = host_to_sniffer_msg_cnt >> 8;
	buf[5] = SET_TEMPORARY_KEY; // Packet type
	memcpy(&buf[6], key, key_size);
	res = slip_encode(cmd_buf, buf, 6 + key_size);
	host_to_sniffer_msg_cnt++;
	return serial_write(dev, cmd_buf, res);
}

//--------------------------------------------
static int command_req_follow_v1_send(const uint8_t *addr, uint8_t addr_type, uint8_t follow_only_advertisements)
{
	int res;
	uint8_t buf[6 + DEVICE_ADDRESS_LENGTH + 2];

	assert(addr);
	buf[0] = 6; // Header length
	buf[1] = DEVICE_ADDRESS_LENGTH + 2; // Payload length
	buf[2] = 1; // UART protocol version used
	buf[3] = host_to_sniffer_msg_cnt & 0xFF; // Packet Counter (LSB)
	buf[4] = host_to_sniffer_msg_cnt >> 8;
	buf[5] = REQ_FOLLOW; // Packet type
	memcpy(&buf[6], addr, DEVICE_ADDRESS_LENGTH);
	buf[6 + DEVICE_ADDRESS_LENGTH] = addr_type;
	buf[6 + DEVICE_ADDRESS_LENGTH + 1] = follow_only_advertisements;
	res = slip_encode(cmd_buf, buf, sizeof(buf));
	host_to_sniffer_msg_cnt++;
	return serial_write(dev, cmd_buf, res);
}

//--------------------------------------------
static void command_send(uint8_t *buf, size_t len)
{
	if (last_cmd == SENT_CMD_PING_REQ)
	{
		if (buf[5] == PING_RESP)
		{
			msg_to_cli_add_print_command("%s", "nRF Sniffer for Bluetooth LE detected.\n");
			if (adv_channel)
			{
				command_set_adv_channel_hop_seq_v1_send(&adv_channel, 1);
			}
			else
			{
				command_set_adv_channel_hop_seq_v1_send(adv_channels, sizeof(adv_channels));
			}
			if (mac_filt)
			{
				command_req_follow_v1_send(mac_addr, mac_addr_type, 0);
			}
			else
			{
				command_req_scan_cont_v1_send();
				command_set_temporary_key_v1_send(tmp_key, sizeof(tmp_key));
			}
			last_cmd = SENT_CMD_REQ_SCAN_CONT;
			msg_to_cli_add_print_command("%s", "nRF Sniffer for Bluetooth LE starts.\n");
		}
		else
		{
			command_ping_req_v1_send();
		}
	}
}

//--------------------------------------------
static int packet_decode(uint8_t *buf, size_t len, ble_info_t **info)
{
	uint16_t hdr_length;
	uint16_t pkt_length;
	static uint64_t current_packet_transmission_time;
	static uint64_t previous_packet_transmission_time;

	pkt_length = buf[0] | ((uint16_t)buf[1] << 8);
	if (pkt_length > len)
	{
		return -1;
	}
	hdr_length = buf[MSG_HEADER_SIZE];
	if (hdr_length >= len || hdr_length >= pkt_length)
	{
		return -1;
	}

	if ((*info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return -1;
	}
	memset(*info, 0, sizeof(ble_info_t));

	(*info)->size = pkt_length - hdr_length - 1;
	if (((*info)->buf = (uint8_t *)malloc((*info)->size)) == NULL)
	{
		free(*info);
		return -1;
	}

	switch ((buf[MSG_HEADER_SIZE + 1] & 0x70) >> 4)
	{
	case 0:
		(*info)->phy = PHY_1M;
		break;
	case 1:
		(*info)->phy = PHY_2M;
		break;
	case 2:
		// not yet supported by nRF sniffer
		assert(0);
		(*info)->phy = PHY_CODED;
		break;
	}
	current_packet_transmission_time = ble_packet_transmission_time_us_calc(*info);

	(*info)->status_enc = ((buf[MSG_HEADER_SIZE + 1] & 0x04) >> 2) ? ENC_ENCRYPTED : ENC_UNENCRYPTED;
	if ((*info)->status_enc == ENC_ENCRYPTED)
	{
		(*info)->status_mic = ((buf[MSG_HEADER_SIZE + 1] & 0x08) >> 3) ? CHECK_OK : CHECK_FAIL;
	}
	else
	{
		(*info)->status_mic = CHECK_UNKNOWN;
	}
	(*info)->dir = ((buf[MSG_HEADER_SIZE + 1] & 0x02) >> 1) ? DIR_MASTER_SLAVE : DIR_SLAVE_MASTER;
	(*info)->status_crc = (buf[MSG_HEADER_SIZE + 1] & 0x01) ? CHECK_OK : CHECK_FAIL;
	(*info)->channel = buf[MSG_HEADER_SIZE + 2];
	(*info)->rssi = - buf[MSG_HEADER_SIZE + 3]; // nRF sniffer prefers the RSSI value without a minus sign
	(*info)->counter_conn = buf[MSG_HEADER_SIZE + 4] | (buf[MSG_HEADER_SIZE + 5] << 8);

	if ((*info)->rssi < min_rssi)
	{
		free(*info);
		return -1;
	}

	if (!timestamp_us)
	{
		timestamp_us = get_usec_since_epoch();
		previous_packet_transmission_time = 0;
	}
	else
	{
		(*info)->delta_time = (uint32_t)buf[MSG_HEADER_SIZE + 6] | ((uint32_t)buf[MSG_HEADER_SIZE + 7] << 8) |
			((uint32_t)buf[MSG_HEADER_SIZE + 8] << 16) | ((uint32_t)buf[MSG_HEADER_SIZE + 9] << 24);
		timestamp_us += previous_packet_transmission_time + (*info)->delta_time;
	}
	(*info)->ts.tv_sec = (long)(timestamp_us / 1000000);
	(*info)->ts.tv_usec = (long)(timestamp_us - (uint64_t)((*info)->ts.tv_sec) * 1000000);
	(*info)->timestamp = timestamp_us;

	previous_packet_transmission_time = current_packet_transmission_time;

	if (!memcmp(buf + MSG_HEADER_SIZE + hdr_length, &adv_channel_access_address[0], ACCESS_ADDRESS_LENGTH))
	{
		// advertising channel packet
		uint8_t header_flags;
		uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];

		memcpy((*info)->buf,
			buf + MSG_HEADER_SIZE + hdr_length,
			ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH);
		// padding byte cutting
		memcpy((*info)->buf + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH,
			buf + MSG_HEADER_SIZE + hdr_length + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + 1,
			(*info)->size - ACCESS_ADDRESS_LENGTH - MINIMUM_HEADER_LENGTH);

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
		// data channel packet
		uint8_t cp_flag;

		if (MSG_HEADER_SIZE + hdr_length + ACCESS_ADDRESS_LENGTH > len)
		{
			free((*info)->buf);
			free(*info);
			return -1;
		}
		cp_flag = buf[MSG_HEADER_SIZE + hdr_length + ACCESS_ADDRESS_LENGTH] & CP_MASK ? 1 : 0;
		memcpy((*info)->buf,
			buf + MSG_HEADER_SIZE + hdr_length,
			ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + cp_flag);
		// padding byte cutting
		memcpy((*info)->buf + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + cp_flag,
			buf + MSG_HEADER_SIZE + hdr_length + ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + cp_flag + 1,
			(*info)->size - ACCESS_ADDRESS_LENGTH - MINIMUM_HEADER_LENGTH - cp_flag);
	}
	return (int)(*info)->size;
}

//--------------------------------------------
static void init(HANDLE hndl)
{
	list_adv_remove_all(&adv_devs);
	timestamp_us = 0;
	host_to_sniffer_msg_cnt = 0;
	dev = hndl;
	command_ping_req_v1_send();
	last_cmd = SENT_CMD_PING_REQ;
}

//--------------------------------------------
static int serial_packet_decode(uint8_t *buf, size_t len, ble_info_t **pkt_info)
{
	size_t cnt;
	int res;
	static uint8_t msg_buf[MAX_MSG_SIZE];

	if (len > MAX_MSG_SIZE)
	{
		assert(0);
		return -1;
	}
	if (buf[0] != SLIP_START)
	{
#if 0
		assert(0);
#endif
		return -1;
	}

	*pkt_info = NULL;

	for (cnt = 0; cnt < len; cnt++)
	{
		if (buf[cnt] == SLIP_END)
		{
			res = slip_decode(&msg_buf[0], buf, cnt);
			if (res < MSG_HEADER_SIZE)
			{
				return -1;
			}
			if (msg_buf[5] == EVENT_PACKET && last_cmd == SENT_CMD_REQ_SCAN_CONT)
			{
				if ((res = packet_decode(&msg_buf[0], (size_t)res, pkt_info)) < 0)
				{
					return -1;
				}
			}
			else
			{
				command_send(&msg_buf[0], (size_t)res);
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

	assert(size == DEVICE_ADDRESS_LENGTH);

	item = list_adv_find_addr(&adv_devs, buf);
	if (item)
	{
		command_req_follow_v1_send(buf, item->tx_addr, 0);
	}
	else
	{
		command_req_scan_cont_v1_send();
		command_set_temporary_key_v1_send(tmp_key, sizeof(tmp_key));
	}
}

//--------------------------------------------
static void passkey_set(uint8_t *buf, size_t size)
{
	unsigned long pass;
	uint8_t key[16];

	assert(size == 7);

	pass = strtoul((char *)buf, NULL, 10);
	memset(key, 0, sizeof(key));
	key[15] = (uint8_t)(pass);
	key[14] = (uint8_t)(pass >> 8);
	key[13] = (uint8_t)(pass >> 16);
	key[12] = (uint8_t)(pass >> 24);

	command_set_temporary_key_v1_send(key, sizeof(key));
}

//--------------------------------------------
static void oob_key_set(uint8_t *buf, size_t size)
{
	size_t cnt;
	uint8_t key[16];

	assert(size == 33);

	for (cnt = 0; cnt < size / 2; cnt++, buf += 2)
	{
		sscanf((char *)buf, "%2hhx", &key[cnt]);
	}

	command_set_temporary_key_v1_send(key, sizeof(key));
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
	mac_addr_type = addr_type;
	memcpy(mac_addr, buf, DEVICE_ADDRESS_LENGTH);
	mac_filt = 1;
}

//--------------------------------------------
static void close_free(void)
{
	list_adv_remove_all(&adv_devs);
}

//--------------------------------------------
SNIFFER(sniffer_nrf3, "N3", 1000000, 1, init, serial_packet_decode, follow, passkey_set, oob_key_set, NULL,\
	    min_rssi_set, adv_channel_set, mac_addr_set, NULL, close_free);
