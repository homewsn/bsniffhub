/*
* Copyright (c) 2019 Vladimir Alemasov
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

#ifndef PCAP_H_
#define PCAP_H_

//--------------------------------------------
#define MAX_PCAP_MSG_SIZE    1024

//--------------------------------------------
struct pcap_pipe_pkthdr
{
	uint32_t tv_sec;       /* seconds */
	uint32_t tv_usec;      /* microseconds */
	uint32_t caplen;       /* length of portion present */
	uint32_t len;          /* length of this packet (off wire) */
};

//--------------------------------------------
void pcap_file_header_create(uint32_t dlt, struct pcap_file_header *pcap_file_hdr);
void pcap_packet_header_pipe_create(uint32_t packet_len, ble_info_t *info, struct pcap_pipe_pkthdr *pcap_hdr);
void pcap_packet_header_create(uint32_t packet_len, ble_info_t *info, struct pcap_pkthdr *pcap_hdr);
size_t pcap_packet_create(uint32_t dlt, ble_info_t *info, uint8_t *packet);
ble_info_t *pcap_packet_parse(uint32_t dlt, const struct pcap_pkthdr *header, const u_char *packet, size_t packet_cnt);

#endif /* PCAP_H_ */

