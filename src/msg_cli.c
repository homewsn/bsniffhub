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
#include <assert.h>     /* assert */
#include "msg_cli.h"

//--------------------------------------------
static void msg_cli_free(msg_cli_t *ms)
{
	if (ms->buf != NULL)
	{
		free(ms->buf);
	}
	free(ms);
}

//--------------------------------------------
msg_cli_t *msg_cli_new(void)
{
	msg_cli_t *ms;

	if ((ms = (msg_cli_t *)malloc(sizeof(msg_cli_t))) == NULL)
	{
		return NULL;
	}
	memset(ms, 0, sizeof(msg_cli_t));
	return ms;
}

//--------------------------------------------
int msg_cli_remove(msgqueue_t *queue, msg_cli_t *ms)
{
	if (msg_remove(queue, (msg_t *)ms) < 0)
	{
		return -1;
	}
	msg_cli_free(ms);
	return 0;
}

//--------------------------------------------
void msg_cli_remove_all(msgqueue_t *queue)
{
	msg_cli_t *ms;

	while ((ms = msg_cli_get_first(queue)))
	{
		msg_cli_remove(queue, ms);
	}
}

//--------------------------------------------
void msg_cli_destroy(msgqueue_t *queue)
{
	msg_cli_remove_all(queue);
	msg_destroy(queue);
}

//--------------------------------------------
int msg_cli_add_single_command(msgqueue_t *queue, cli_cmd_t cmd)
{
	msg_cli_t *ms;

	if ((ms = msg_cli_new()) == NULL)
	{
		return -1;
	}
	ms->cmd = cmd;
	ms->buf = NULL;
	ms->size = 0;
	if (msg_cli_add(queue, ms) < 0)
	{
		msg_cli_free(ms);
		return -1;
	}
	return 0;
}

//--------------------------------------------
int msg_cli_add_command(msgqueue_t *queue, cli_cmd_t cmd, uint8_t *buf, size_t size)
{
	msg_cli_t *ms;

	if ((ms = msg_cli_new()) == NULL)
	{
		return -1;
	}
	ms->cmd = cmd;
	ms->buf = (char *)buf;
	ms->size = size;
	if (msg_cli_add(queue, ms) < 0)
	{
		msg_cli_free(ms);
		return -1;
	}
	return 0;
}

//--------------------------------------------
int msg_cli_copybuf_add_command(msgqueue_t *queue, cli_cmd_t cmd, const uint8_t *buf, size_t size)
{
	uint8_t *cli_msg_buf;
	msg_cli_t *ms;

	if ((ms = msg_cli_new()) == NULL)
	{
		return -1;
	}
	if ((cli_msg_buf = (uint8_t *)malloc(size)) == NULL)
	{
		msg_cli_free(ms);
		return -1;
	}
	memcpy(cli_msg_buf, buf, size);
	ms->cmd = cmd;
	ms->buf = (char *)cli_msg_buf;
	ms->size = size;
	if (msg_cli_add(queue, ms) < 0)
	{
		msg_cli_free(ms);
		return -1;
	}
	return 0;
}
