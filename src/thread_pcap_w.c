/*
* Copyright (c) 2020, 2024 Vladimir Alemasov
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
#include "serial.h"
#include "msg_ble.h"
#include "pcap.h"
#include "ble_pcap.h"
#include "msg_ble_pcap.h"
#include "msg_to_cli.h"
#include "task.h"


//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static int pcap_dlt;
static pcap_t *pd;
static pcap_dumper_t *pdumper;


//--------------------------------------------
static int pcap_write_packet(ble_info_t *info)
{
	static uint8_t buf[MAX_PCAP_MSG_SIZE];
	struct pcap_pkthdr pcap_hdr = { 0 };
	size_t len;

	len = pcap_packet_create(pcap_dlt, info, buf);
	assert(len < MAX_PCAP_MSG_SIZE);
	pcap_packet_header_create((uint32_t)len, info, &pcap_hdr);
	pcap_dump((u_char*)pdumper, &pcap_hdr, (const u_char*)buf);
	return (int)(sizeof(pcap_hdr) + len);
}


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	msg_ble_t *msg;
	int res;

	for (;;)
	{
		if ((msg = msg_ble_pcap_get_first()) != NULL)
		{
			if (msg->info)
			{
				res = pcap_write_packet(msg->info);
			}
			else
			{
				// last packet from PCAP file input
				msg_to_cli_add_print_command("%s", "File processing completed.\n");
				msg_to_cli_add_single_command(CLI_APP_EXIT);
			}
			msg_ble_pcap_remove(msg);
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sched_yield();
	}

	if (pd)
	{
		pcap_close(pd);
		pd = NULL;
	}
	if (pdumper)
	{
		pcap_dump_close(pdumper);
		pdumper = NULL;
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
int thread_pcap_w_init(const char *name, int dlt)
{
	assert(name);
	assert(dlt);

#ifdef _WIN32
	SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
	if (LoadLibrary("wpcap.dll") == NULL)
	{
		printf("FATAL ERROR: Could not find Npcap runtime libraries installed.\n");
		return TASK_ERROR_NPCAP_INSTALLED;
	}
#endif
	pcap_dlt = dlt;
	if ((pd = pcap_open_dead(dlt, MAX_PCAP_MSG_SIZE)) == NULL)
	{
		printf("FATAL ERROR: Could not open pcap dead handler.\n");
		return TASK_ERROR_OPEN_PCAP_FILE_FOR_WRITING;
	}
	if ((pdumper = pcap_dump_open(pd, name)) == NULL)
	{
		printf("%s\n", pcap_geterr(pd));
		pd = NULL;
		return TASK_ERROR_OPEN_PCAP_FILE_FOR_WRITING;
	}
	else
	{
		printf("Creating the %s file ...\n", name);
	}
	return 0;
}

//--------------------------------------------
void thread_pcap_w_start(void)
{
	pthread_t thread;
	void *param = NULL;

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_pcap_w_stop(void)
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
