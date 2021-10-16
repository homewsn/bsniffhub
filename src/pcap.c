/*
* Copyright (c) 2019 - 2021 Vladimir Alemasov
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
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memcpy, memset */
#include <assert.h>     /* assert */
#include <pcap/pcap.h>  /* pcap library stuff */
#include "msg_ble.h"
#include "ble_pcap.h"
#include "pcap.h"
#include "ble.h"


//--------------------------------------------
static int8_t ble2rf_channel(int8_t channel)
{
	if (channel == 37)
	{
		return 0;
	}
	else if (channel == 38)
	{
		return 12;
	}
	else if (channel == 39)
	{
		return 39;
	}
	else if (channel <= 10)
	{
		return channel + 1;
	}
	else
	{
		return channel + 2;
	}
}

//--------------------------------------------
static int8_t rf2ble_channel(int8_t channel)
{
	if (channel <= 39)
	{
		if (channel == 39)
		{
			return 39;
		}
		else if (channel >= 13)
		{
			return channel - 2;
		}
		else if (channel == 12)
		{
			return 38;
		}
		else if (channel >= 1)
		{
			return channel - 1;
		}
		else
		{
			return 37;
		}
	}
	return -1;
}

//--------------------------------------------
void pcap_file_header_create(uint32_t dlt, struct pcap_file_header *pcap_file_hdr)
{
	pcap_file_hdr->magic = 0xA1B2C3D4;
	pcap_file_hdr->version_major = 2;
	pcap_file_hdr->version_minor = 4;
	pcap_file_hdr->thiszone = 0;
	pcap_file_hdr->sigfigs = 0;
	pcap_file_hdr->snaplen = MAX_PCAP_MSG_SIZE;
	pcap_file_hdr->linktype = dlt;
}

//--------------------------------------------
void pcap_packet_header_pipe_create(uint32_t packet_len, ble_info_t *info, struct pcap_pipe_pkthdr *pcap_hdr)
{
	pcap_hdr->tv_sec = info->ts.tv_sec;
	pcap_hdr->tv_usec = info->ts.tv_usec;
	pcap_hdr->caplen = packet_len;
	pcap_hdr->len = packet_len;
}

//--------------------------------------------
void pcap_packet_header_create(uint32_t packet_len, ble_info_t *info, struct pcap_pkthdr *pcap_hdr)
{
	pcap_hdr->ts.tv_sec = info->ts.tv_sec;
	pcap_hdr->ts.tv_usec = info->ts.tv_usec;
	pcap_hdr->caplen = packet_len;
	pcap_hdr->len = packet_len;
}

//--------------------------------------------
size_t pcap_packet_create(uint32_t dlt, ble_info_t *info, uint8_t *packet)
{
	switch (dlt)
	{
	case LINKTYPE_BLUETOOTH_LE_LL:
		memcpy(packet, info->buf, info->size);
		return info->size;
	case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
	{
		pcap_bluetooth_le_ll_header_t ble_ll_hdr = { 0 };

		ble_ll_hdr.rf_channel = ble2rf_channel(info->channel);
		ble_ll_hdr.signal_power = info->rssi;
		ble_ll_hdr.access_address_offenses = 0;
		ble_ll_hdr.flags |= 0x0001;  // Dewhitened: True
		ble_ll_hdr.flags |= 0x0002;  // Signal Power Valid: True
		// Noise Power Valid: False
		ble_ll_hdr.flags |= (info->status_enc == ENC_DECRYPTED) ? 0x0008 : 0x0000; // Decrypted
		if (info->pdu == PDU_ADV)
		{
			ble_ll_hdr.ref_access_address = *(uint32_t *)adv_channel_access_address;
			ble_ll_hdr.flags |= 0x0010;  // Reference Access Address Valid: True
		}
		// Access Address Offenses Valid: False
		// Channel Aliased: False
		if (info->dir != DIR_UNKNOWN && info->pdu == PDU_DATA)
		{
			ble_ll_hdr.flags |= (info->dir == DIR_MASTER_SLAVE) ? 0x0100 : 0x0180; // PDU Type
		}
		// else { PDU Type: Advertising or Data (Unspecified Direction) (0) }
		if (info->status_crc != CHECK_UNKNOWN)
		{
			ble_ll_hdr.flags |= 0x0400;  // CRC Checked: True
			ble_ll_hdr.flags |= (info->status_crc == CHECK_OK) ? 0x0800 : 0x0000; // CRC Valid
		}
		// else { CRC Checked: False, CRC Valid: False }
		if (info->status_mic != CHECK_UNKNOWN)
		{
			ble_ll_hdr.flags |= 0x1000;  // MIC Checked: True
			ble_ll_hdr.flags |= (info->status_mic == CHECK_OK) ? 0x2000 : 0x0000; // MIC Valid
		}
		// else { MIC Checked: False, MIC Valid: False }
		if (info->status_enc == ENC_DECRYPTED)
		{
			ble_ll_hdr.flags |= 0x0008;  // Decrypted: True
		}
		// else { Decrypted: False}

		ble_ll_hdr.flags |= info->phy << 14;  // PHY

		memcpy(packet, &ble_ll_hdr, sizeof(pcap_bluetooth_le_ll_header_t));
		if (info->phy == PHY_CODED)
		{
			memcpy(packet + sizeof(pcap_bluetooth_le_ll_header_t), info->buf, ACCESS_ADDRESS_LENGTH);
			if (info->ci == CI_S2)
			{
				*(packet + sizeof(pcap_bluetooth_le_ll_header_t) + ACCESS_ADDRESS_LENGTH) = 0x01; // Coding Indicator = FEC Block 2 coded using S=2 (1)
			}
			else
			{
				*(packet + sizeof(pcap_bluetooth_le_ll_header_t) + ACCESS_ADDRESS_LENGTH) = 0x00; // Coding Indicator = FEC Block 2 coded using S=8 (0)
			}
			memcpy(packet + sizeof(pcap_bluetooth_le_ll_header_t) + ACCESS_ADDRESS_LENGTH + 1, info->buf + ACCESS_ADDRESS_LENGTH, info->size - ACCESS_ADDRESS_LENGTH);
			return (sizeof(pcap_bluetooth_le_ll_header_t) + info->size + 1);
		}
		else
		{
			memcpy(packet + sizeof(pcap_bluetooth_le_ll_header_t), info->buf, info->size);
			return (sizeof(pcap_bluetooth_le_ll_header_t) + info->size);
		}
	}
	case LINKTYPE_NORDIC_BLE:
	{
# if 0
		// nordic header version = 2
		pcap_nordic_ble_header_t nordic_hdr = { 0 };

		nordic_hdr.board = 0; //?
		nordic_hdr.channel = info->channel;
		nordic_hdr.type2_delta_time = info->delta_time;
		nordic_hdr.event_counter = info->counter_conn;
		nordic_hdr.packet_counter = info->counter_total;
		nordic_hdr.packet_id = 6;
		nordic_hdr.packet_length = 10;
		nordic_hdr.payload_length = info->phy == PHY_CODED ? (uint16_t)(info->size + 1 + 10) : (uint16_t)(info->size + 10);
		nordic_hdr.protocol_version = 2;
		nordic_hdr.rssi = -info->rssi; // Nordic prefers the RSSI value without a minus sign

		nordic_hdr.flags |= info->status_crc == CHECK_OK ? 0x01 : 0x00;
		nordic_hdr.flags |= info->dir == DIR_MASTER_SLAVE ? 0x02 : 0x00;
		nordic_hdr.flags |= (info->status_enc == ENC_ENCRYPTED || info->status_enc == ENC_DECRYPTED) ? 0x04 : 0x00;
		nordic_hdr.flags |= (info->status_mic == CHECK_OK) ? 0x08 : 0x00;
		switch (info->phy)
		{
		case PHY_1M:
		default:
			break;
		case PHY_2M:
			nordic_hdr.flags |= 0x10;
			break;
		case PHY_CODED:
			nordic_hdr.flags |= 0x20;
			break;
		}

		memcpy(packet, &nordic_hdr, sizeof(pcap_nordic_ble_header_t));
		if (info->phy == PHY_CODED)
		{
			memcpy(packet + sizeof(pcap_nordic_ble_header_t), info->buf, ACCESS_ADDRESS_LENGTH);
			if (info->ci == CI_S2)
			{
				*(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH) = 0x01; // Coding Indicator = FEC Block 2 coded using S=2 (1)
			}
			else
			{
				*(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH) = 0x00; // Coding Indicator = FEC Block 2 coded using S=8 (0)
			}
			memcpy(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH + 1, info->buf + ACCESS_ADDRESS_LENGTH, info->size - ACCESS_ADDRESS_LENGTH);
			return (sizeof(pcap_nordic_ble_header_t) + info->size + 1);
		}
		else
		{
			memcpy(packet + sizeof(pcap_nordic_ble_header_t), info->buf, info->size);
			return (sizeof(pcap_nordic_ble_header_t) + info->size);
		}
#else
		// nordic header version = 3
		pcap_nordic_ble_header_t nordic_hdr = { 0 };

		nordic_hdr.board = 0; //?
		nordic_hdr.channel = info->channel;
		nordic_hdr.type3_timestamp = (uint32_t)info->timestamp;
		nordic_hdr.event_counter = info->counter_conn;
		nordic_hdr.packet_counter = info->counter_total;
		if (info->pdu == PDU_DATA)
		{
			nordic_hdr.packet_id = 6;
		}
		else
		{
			nordic_hdr.packet_id = 2;
		}
		nordic_hdr.packet_length = 10;
		nordic_hdr.payload_length = info->phy == PHY_CODED ? (uint16_t)(info->size + 1 + 10) : (uint16_t)(info->size + 10);
		nordic_hdr.protocol_version = 3;
		nordic_hdr.rssi = -info->rssi; // Nordic prefers the RSSI value without a minus sign

		nordic_hdr.flags |= info->status_crc == CHECK_OK ? 0x01 : 0x00;
		nordic_hdr.flags |= info->dir == DIR_MASTER_SLAVE ? 0x02 : 0x00;
		nordic_hdr.flags |= (info->status_enc == ENC_ENCRYPTED || info->status_enc == ENC_DECRYPTED) ? 0x04 : 0x00;
		nordic_hdr.flags |= (info->status_mic == CHECK_OK) ? 0x08 : 0x00;
		switch (info->phy)
		{
		case PHY_1M:
		default:
			break;
		case PHY_2M:
			nordic_hdr.flags |= 0x10;
			break;
		case PHY_CODED:
			nordic_hdr.flags |= 0x20;
			break;
		}

		memcpy(packet, &nordic_hdr, sizeof(pcap_nordic_ble_header_t));
		if (info->phy == PHY_CODED)
		{
			memcpy(packet + sizeof(pcap_nordic_ble_header_t), info->buf, ACCESS_ADDRESS_LENGTH);
			if (info->ci == CI_S2)
			{
				*(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH) = 0x01; // Coding Indicator = FEC Block 2 coded using S=2 (1)
			}
			else
			{
				*(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH) = 0x00; // Coding Indicator = FEC Block 2 coded using S=8 (0)
			}
			memcpy(packet + sizeof(pcap_nordic_ble_header_t) + ACCESS_ADDRESS_LENGTH + 1, info->buf + ACCESS_ADDRESS_LENGTH, info->size - ACCESS_ADDRESS_LENGTH);
			return (sizeof(pcap_nordic_ble_header_t) + info->size + 1);
		}
		else
		{
			memcpy(packet + sizeof(pcap_nordic_ble_header_t), info->buf, info->size);
			return (sizeof(pcap_nordic_ble_header_t) + info->size);
		}
#endif
	}
	}
	assert(0);
	return 0;
}

//--------------------------------------------
ble_info_t *pcap_packet_parse(uint32_t dlt, const struct pcap_pkthdr *header, const u_char *packet, size_t packet_cnt)
{
	static uint64_t start_timestamp;
	uint64_t packet_timestamp;
	ble_info_t *info;
	size_t header_len;

	if ((info = (ble_info_t *)malloc(sizeof(ble_info_t))) == NULL)
	{
		return NULL;
	}
	memset(info, 0, sizeof(ble_info_t));
	info->ts.tv_sec = header->ts.tv_sec;
	info->ts.tv_usec = header->ts.tv_usec;
	if (packet_cnt == 1)
	{
		start_timestamp = (uint64_t)info->ts.tv_sec * 1000000 + (uint64_t)info->ts.tv_usec;
	}
	packet_timestamp = (uint64_t)info->ts.tv_sec * 1000000 + (uint64_t)info->ts.tv_usec;
	info->timestamp = packet_timestamp;
	info->counter_total = (uint16_t)packet_cnt;

	switch (dlt)
	{
	case LINKTYPE_BLUETOOTH_LE_LL:
		header_len = 0;
		info->channel = -1;
		info->size = header->caplen - header_len;
		break;
	case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
	{
		pcap_bluetooth_le_ll_header_t *ble_ll_hdr = (pcap_bluetooth_le_ll_header_t *)packet;

		header_len = sizeof(pcap_bluetooth_le_ll_header_t);
		info->channel = rf2ble_channel(ble_ll_hdr->rf_channel);
		info->rssi = ble_ll_hdr->signal_power;
		if (ble_ll_hdr->flags & 0x0380)
		{
			if ((ble_ll_hdr->flags & 0x0380) == 0x0100)
			{
				info->dir = DIR_MASTER_SLAVE;
			}
			if ((ble_ll_hdr->flags & 0x0380) == 0x0180)
			{
				info->dir = DIR_SLAVE_MASTER;
			}
		}
		if (ble_ll_hdr->flags & 0x0400)
		{
			info->status_crc = (ble_ll_hdr->flags & 0x0800) ? CHECK_OK : CHECK_FAIL;
		}
		if (ble_ll_hdr->flags & 0x1000)
		{
			info->status_mic = (ble_ll_hdr->flags & 0x2000) ? CHECK_OK : CHECK_FAIL;
		}
		info->status_enc = (ble_ll_hdr->flags & 0x0008) ? ENC_DECRYPTED : ENC_UNKNOWN;
		info->size = header->caplen - header_len;
		info->phy = ble_ll_hdr->flags >> 14;
		if (info->phy == PHY_CODED)
		{
			info->size -= 1;
			if ((info->buf = (uint8_t *)malloc(info->size)) == NULL)
			{
				free(info);
				return NULL;
			}
			memcpy(info->buf, packet + header_len, ACCESS_ADDRESS_LENGTH);
			info->ci = *(packet + header_len + ACCESS_ADDRESS_LENGTH);
			memcpy(info->buf + ACCESS_ADDRESS_LENGTH, packet + header_len + ACCESS_ADDRESS_LENGTH + 1, info->size - ACCESS_ADDRESS_LENGTH);
			return info;
		}
		break;
	}
	case LINKTYPE_NORDIC_BLE:
	{
		pcap_nordic_ble_header_t *nordic_hdr = (pcap_nordic_ble_header_t *)packet;

		header_len = sizeof(pcap_nordic_ble_header_t);
		info->status_crc = (nordic_hdr->flags & 0x01) ? CHECK_OK : CHECK_FAIL;
		info->dir = (nordic_hdr->flags & 0x02) ? DIR_MASTER_SLAVE : DIR_SLAVE_MASTER;
		info->status_enc = (nordic_hdr->flags & 0x04) ? ENC_DECRYPTED : ENC_UNKNOWN;
		info->status_mic = (nordic_hdr->flags & 0x08) ? CHECK_OK : CHECK_FAIL;
		if (info->status_enc == ENC_DECRYPTED && info->status_mic == CHECK_FAIL)
		{
			info->status_enc = ENC_ENCRYPTED;
		}
		info->rssi = nordic_hdr->rssi;
		info->channel = nordic_hdr->channel;
		info->counter_conn = nordic_hdr->event_counter;
		info->size = header->caplen - header_len;
		switch ((nordic_hdr->flags & 0x70) >> 4)
		{
		case 0:
			info->phy = PHY_1M;
			break;
		case 1:
			info->phy = PHY_2M;
			break;
		case 2:
			info->phy = PHY_CODED;
			info->size -= 1;
			break;
		}
		if (nordic_hdr->protocol_version <= 2)
		{
			static uint64_t timestamp_us;
			uint64_t current_packet_transmission_time;
			static uint64_t previous_packet_transmission_time;

			current_packet_transmission_time = ble_packet_transmission_time_us_calc(info);
			if (packet_cnt == 1)
			{
				timestamp_us = start_timestamp;
				previous_packet_transmission_time = 0;
			}
			else
			{
				info->delta_time = nordic_hdr->type2_delta_time;
			}
			timestamp_us += previous_packet_transmission_time + info->delta_time;
			info->timestamp = timestamp_us;
			previous_packet_transmission_time = current_packet_transmission_time;
		}
		if (info->phy == PHY_CODED)
		{
			if ((info->buf = (uint8_t *)malloc(info->size)) == NULL)
			{
				free(info);
				return NULL;
			}
			memcpy(info->buf, packet + header_len, ACCESS_ADDRESS_LENGTH);
			info->ci = *(packet + header_len + ACCESS_ADDRESS_LENGTH);
			memcpy(info->buf + ACCESS_ADDRESS_LENGTH, packet + header_len + ACCESS_ADDRESS_LENGTH + 1, info->size - ACCESS_ADDRESS_LENGTH);
			return info;
		}
		break;
	}
	default:
		free(info);
		assert(0);
		return NULL;
	}

	if ((info->buf = (uint8_t *)malloc(info->size)) == NULL)
	{
		free(info);
		return NULL;
	}
	memcpy(info->buf, packet + header_len, info->size);
	return info;
}
