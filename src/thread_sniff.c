/*
* Copyright (c) 2020 - 2025 Vladimir Alemasov
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
#ifndef _WIN32
#include <signal.h>     /* signal */
#endif
#include <assert.h>     /* assert */
#include <stdio.h>      /* printf */
#include <stdbool.h>    /* bool */
#include <string.h>     /* memmove */
#include "thread.h"
#include "thread_state.h"
#include "serial.h"
#include "msg_pckt_ble.h"
#include "msg_cli_snif.h"
#include "sniffers.h"
#include "task.h"


//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static const sniffer_t* sniffer;
static HANDLE dev;


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	size_t size = 0;
	int abort = 0;
	int res;
	msg_cli_t *cli_msg;
	ble_info_t *info;
	static uint8_t buf[SERIAL_BUF_SIZE];

	if (sniffer->init)
	{
		sniffer->init(dev);
	}

	for (;;)
	{
		assert(size < SERIAL_BUF_SIZE);
		if (size == SERIAL_BUF_SIZE)
		{
			size = 0;
		}
		if (!abort)
		{
			res = serial_read(dev, &buf[size], SERIAL_BUF_SIZE - size);
		}
		if (res > 0 || size > 0)
		{
			if (size + (size_t)res > SERIAL_BUF_SIZE)
			{
				size = SERIAL_BUF_SIZE;
			}
			else
			{
				size += (size_t)res;
			}
			res = sniffer->decode(&buf[0], size, &info);
			if (res > 0)
			{
				assert(size >= (size_t)res);
				size -= (size_t)res;
				memmove(&buf[0], &buf[res], size);
				if (info)
				{
					msg_pckt_ble_add_packet(info);
				}
			}
			if (res < 0)
			{
				size = 0;
			}
		}
		else if (res < 0 && !abort)
		{
			printf("%s", "FATAL ERROR: Sniffer has been disconnected.\n");
#ifdef _WIN32
			GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
#else
			raise(SIGINT);
#endif
			abort = 1;
		}

		if ((cli_msg = msg_cli_snif_get_first()) != NULL)
		{
			switch (cli_msg->cmd)
			{
			case CLI_SNIF_FOLLOW_DEVICE:
				if (sniffer->follow_device)
				{
					sniffer->follow_device((uint8_t *)cli_msg->buf, cli_msg->size);
				}
				break;
			case CLI_SNIF_PASSKEY:
				if (sniffer->passkey_set)
				{
					sniffer->passkey_set((uint8_t *)cli_msg->buf, cli_msg->size);
				}
				break;
			case CLI_SNIF_OOB_KEY:
				if (sniffer->oob_key_set)
				{
					sniffer->oob_key_set((uint8_t *)cli_msg->buf, cli_msg->size);
				}
				break;
			case CLI_SNIF_LTK:
				if (sniffer->ltk_set)
				{
					sniffer->ltk_set((uint8_t *)cli_msg->buf, cli_msg->size, true);
				}
				break;
			default:
				break;
			}
			msg_cli_snif_remove(cli_msg);
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sched_yield();
	}

	serial_nonfreezing_close(dev);
	sniffer->close();
	thread_state = THREAD_STOPPED;
}

//--------------------------------------------
#ifdef _WIN32
static unsigned int __stdcall thread_launcher(void *param)
{
	thread_run(param);
	return 0;
}
#else
static void *thread_launcher(void *param)
{
	thread_run(param);
	return NULL;
}
#endif

//--------------------------------------------
int thread_sniff_init(const char *name, const sniffer_t* sniff, int baudr)
{
	port_settings_t set;

	assert(name);
	assert(sniff);

	memcpy(&set, &sniff->sets, sizeof(port_settings_t));
	if (baudr)
	{
		set.baudrate = baudr;
	}
	if (serial_open(name, &set, &dev) < 0)
	{
		printf("FATAL ERROR: Could not open device %s.\n", name);
		return TASK_ERROR_OPEN_DEVICE;
	}
	sniffer = sniff;
	return 0;
}

//--------------------------------------------
void thread_sniff_start(void)
{
	pthread_t thread;
	void *param = NULL;

	serial_flush(dev);

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_sniff_stop(void)
{
	if (thread_state == THREAD_RUNNING)
	{
		thread_state = THREAD_STAYING;
	}
	while (thread_state != THREAD_STOPPED)
	{
		sleep(10);
	}
}
