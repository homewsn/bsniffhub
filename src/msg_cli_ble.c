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

#include <stdint.h>     /* uint8_t ... uint64_t */
#include "msg_cli_ble.h"

//--------------------------------------------
static msgqueue_t queue;

//--------------------------------------------
int msg_cli_ble_init(void)
{
	return msg_cli_init(&queue);
}

//--------------------------------------------
int msg_cli_ble_add(msg_cli_t *ms)
{
	return msg_cli_add(&queue, (msg_t *)ms);
}

//--------------------------------------------
int msg_cli_ble_remove(msg_cli_t *ms)
{
	return msg_cli_remove(&queue, (msg_cli_t *)ms);
}

//--------------------------------------------
msg_cli_t* msg_cli_ble_get_first(void)
{
	return msg_cli_get_first(&queue);
}

//--------------------------------------------
void msg_cli_ble_remove_all(void)
{
	msg_cli_remove_all(&queue);
}

//--------------------------------------------
void msg_cli_ble_destroy(void)
{
	msg_cli_destroy(&queue);
}

//--------------------------------------------
int msg_cli_ble_add_single_command(cli_cmd_t cmd)
{
	return msg_cli_add_single_command(&queue, cmd);
}

//--------------------------------------------
int msg_cli_ble_copybuf_add_command(cli_cmd_t cmd, const uint8_t *buf, size_t size)
{
	return msg_cli_copybuf_add_command(&queue, cmd, buf, size);
}
