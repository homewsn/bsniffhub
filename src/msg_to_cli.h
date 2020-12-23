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

#ifndef MSG_TO_CLI_H_
#define MSG_TO_CLI_H_

#include "msgs.h"
#include "msg_cli.h"

//--------------------------------------------
int msg_to_cli_init(void);
#define msg_to_cli_new() msg_snif_new()
int msg_to_cli_add(msg_cli_t *ms);
int msg_to_cli_remove(msg_cli_t *ms);
msg_cli_t *msg_to_cli_get_first(void);
void msg_to_cli_remove_all(void);
#define msg_to_cli_close() msg_close(a)
void msg_to_cli_destroy(void);
int msg_to_cli_add_single_command(cli_cmd_t cmd);
int msg_to_cli_add_print_command(const char *format, ...);
int msg_to_cli_add_follow_device_command(uint8_t *buf, uint8_t rssi, uint8_t addr_type);

#endif /* MSG_BLE_CLI_H_ */
