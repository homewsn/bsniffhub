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
#include <string.h>     /* memcpy, memset */
#include <assert.h>     /* assert */
#include <pcap/pcap.h>  /* pcap library stuff */
#include "thread.h"
#include "thread_state.h"
#include "ble.h"
#include "ble_pcap.h"
#include "msg_cli_pcap.h"
#include "msg_to_cli.h"
#include "msg_pckt_ble.h"
#include "ble_decoder.h"
#include "pcap.h"
#include "task.h"


//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static int cap_dlt;
static pcap_t *pd;
static char err_buf[PCAP_ERRBUF_SIZE];
static size_t packet_cnt;

//--------------------------------------------
void pcap_callback(u_char *ptr, const struct pcap_pkthdr *header, const u_char *packet)
{
	msg_cli_t *msg;
	ble_info_t *info;

	if ((msg = msg_cli_pcap_get_first()) != NULL)
	{
		if (msg->cmd == CLI_PCAP_CLOSE_FILE)
		{
			msg_cli_pcap_remove(msg);
			pcap_breakloop(pd);
			return;
		}
	}

	if ((info = pcap_packet_parse(cap_dlt, header, packet, ++packet_cnt)))
	{
		msg_pckt_ble_add_packet(info);
	}
}


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	msg_cli_t *msg;

	for (;;)
	{
		if ((msg = msg_cli_pcap_get_first()) != NULL)
		{
			switch (msg->cmd)
			{
			case CLI_PCAP_PARSE_FILE:
				packet_cnt = 0;
				cap_dlt = pcap_datalink(pd);
				pcap_loop(pd, 0, pcap_callback, NULL);
				pcap_close(pd);
				pd = NULL;
				msg_to_cli_add_print_command("%s", "File loading completed.\n");
				msg_pckt_ble_add_packet(NULL);
				break;
			default:
				break;
			}
			msg_cli_pcap_remove(msg);
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sleep(10);
	}

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
int thread_pcap_r_init(const char *name)
{
	int dlt;

	assert(name);

#ifdef _WIN32
	SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
	if (LoadLibrary("wpcap.dll") == NULL)
	{
		printf("FATAL ERROR: Could not find Npcap runtime libraries installed.\n");
		return TASK_ERROR_NPCAP_INSTALLED;
	}
#endif
	if ((pd = pcap_open_offline(name, err_buf)) == NULL)
	{
		printf("%s\n", err_buf);
		return TASK_ERROR_OPEN_PCAP_FILE_FOR_READING;
	}
	else
	{
		printf("%s is loading ...\n", name);
	}

	dlt = pcap_datalink(pd);
	switch (dlt)
	{
	case LINKTYPE_BLUETOOTH_LE_LL:
	case LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR:
	case LINKTYPE_NORDIC_BLE:
		break;
	default:
		printf("FATAL ERROR: Link-layer header type %d in %s is not supported\n", dlt, name);
		return TASK_ERROR_LL_NOT_SUPPORTED;
	}
	return 0;
}

//--------------------------------------------
void thread_pcap_r_start(void)
{
	pthread_t thread;
	void *param = NULL;

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_pcap_r_stop(void)
{
	if (pd)
	{
		pcap_breakloop(pd);
	}

	if (thread_state == THREAD_RUNNING)
	{
		thread_state = THREAD_STAYING;
	}
	while (thread_state != THREAD_STOPPED)
	{
		sleep(10);
	}
}
