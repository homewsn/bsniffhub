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

#ifndef MSG_CLI_PCAP_H_
#define MSG_CLI_PCAP_H_

#include "msg_cli.h"

//--------------------------------------------
int msg_cli_pcap_init(void);
#define msg_cli_pcap_new() msg_pcap_new()
int msg_cli_pcap_add(msg_cli_t *ms);
int msg_cli_pcap_remove(msg_cli_t *ms);
msg_cli_t *msg_cli_pcap_get_first(void);
void msg_cli_pcap_remove_all(void);
#define msg_cli_pcap_close() msg_close(a)
void msg_cli_pcap_destroy(void);
int msg_cli_pcap_add_command(cli_cmd_t cmd, uint8_t *buf, size_t size);

#endif /* MSG_CLI_PCAP_H_ */
