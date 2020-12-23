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
#include <stdlib.h>     /* malloc */
#include <string.h>     /* memset */
#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>     /* va_list */
#include "msg_cli.h"
#include "ble.h"

//--------------------------------------------
static msgqueue_t queue;

//--------------------------------------------
int msg_to_cli_init(void)
{
	return msg_cli_init(&queue);
}

//--------------------------------------------
int msg_to_cli_add(msg_cli_t *ms)
{
	return msg_cli_add(&queue, (msg_t *)ms);
}

//--------------------------------------------
int msg_to_cli_remove(msg_cli_t *ms)
{
	return msg_cli_remove(&queue, (msg_cli_t *)ms);
}

//--------------------------------------------
msg_cli_t* msg_to_cli_get_first(void)
{
	return msg_cli_get_first(&queue);
}

//--------------------------------------------
void msg_to_cli_remove_all(void)
{
	msg_cli_remove_all(&queue);
}

//--------------------------------------------
void msg_to_cli_destroy(void)
{
	msg_cli_destroy(&queue);
}

//--------------------------------------------
int msg_to_cli_add_single_command(cli_cmd_t cmd)
{
	return msg_cli_add_single_command(&queue, cmd);
}

//--------------------------------------------
int msg_to_cli_add_print_command(const char *format, ...)
{
	uint8_t *cli_msg_buf;
	va_list args;

	if ((cli_msg_buf = (uint8_t *)malloc(CLI_PRINT_MSG_MAX_SIZE)) == NULL)
	{
		return -1;
	}
	va_start(args, format);
	vsnprintf((char *)cli_msg_buf, CLI_PRINT_MSG_MAX_SIZE, format, args);
	va_end(args);
	return msg_cli_add_command(&queue, CLI_PRINT_MSG_BUF, cli_msg_buf, CLI_PRINT_MSG_MAX_SIZE);
}

//--------------------------------------------
int msg_to_cli_add_follow_device_command(uint8_t *buf, uint8_t rssi, uint8_t addr_type)
{
	uint8_t *cli_msg_buf;

	if ((cli_msg_buf = (uint8_t *)malloc(DEVICE_ADDRESS_LENGTH + 2)) == NULL)
	{
		return -1;
	}
	memcpy(cli_msg_buf, buf, DEVICE_ADDRESS_LENGTH);
	cli_msg_buf[DEVICE_ADDRESS_LENGTH] = rssi;
	cli_msg_buf[DEVICE_ADDRESS_LENGTH + 1] = addr_type;
	return msg_cli_add_command(&queue, CLI_SNIF_FOLLOW_DEVICE, cli_msg_buf, DEVICE_ADDRESS_LENGTH + 2);
}
