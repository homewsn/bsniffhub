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

#ifndef MSG_CLI_H_
#define MSG_CLI_H_

#include "msgs.h"

//--------------------------------------------
#define CLI_PRINT_MSG_MAX_SIZE 200

//--------------------------------------------
typedef enum
{
	CLI_APP_EXIT,
	CLI_PRINT_MSG_BUF,
	CLI_INPUT_PASSKEY,
	CLI_INPUT_OOB_KEY,
	CLI_INPUT_LTK,
	CLI_BLE_NO_PASSKEY,
	CLI_BLE_PASSKEY,
	CLI_BLE_NO_OOB_KEY,
	CLI_BLE_OOB_KEY,
	CLI_BLE_NO_LTK,
	CLI_BLE_LTK,
	CLI_PCAP_PARSE_FILE,
	CLI_PCAP_CLOSE_FILE,
	CLI_SNIF_FOLLOW_DEVICE,
	CLI_SNIF_PASSKEY,
	CLI_SNIF_OOB_KEY,
	CLI_SNIF_LTK
} cli_cmd_t;

//--------------------------------------------
typedef struct msg_cli
{
	msg_t msg;
	cli_cmd_t cmd;
	char *buf;
	size_t size;
} msg_cli_t;

//--------------------------------------------
#define msg_cli_init(a) msg_init(a)
msg_cli_t *msg_cli_new(void);
#define msg_cli_add(a, b) msg_add(a, (msg_t *)b)
int msg_cli_remove(msgqueue_t *queue, msg_cli_t *ms);
#define msg_cli_get_first(a) (msg_cli_t *)msg_get_first(a)
void msg_cli_remove_all(msgqueue_t *queue);
void msg_cli_destroy(msgqueue_t *queue);
int msg_cli_add_single_command(msgqueue_t *queue, cli_cmd_t cmd);
int msg_cli_add_command(msgqueue_t *queue, cli_cmd_t cmd, uint8_t *buf, size_t size);
int msg_cli_copybuf_add_command(msgqueue_t *queue, cli_cmd_t cmd, const uint8_t *buf, size_t size);

#endif /* MSG_CLI_H_ */
