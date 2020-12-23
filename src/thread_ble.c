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
#include "thread.h"
#include "thread_state.h"
#include "msg_pckt_ble.h"
#include "msg_ble_pipe.h"
#include "msg_ble_pcap.h"
#include "msg_to_cli.h"
#include "msg_cli_ble.h"
#include "ble_decoder.h"

//--------------------------------------------
typedef enum
{
	THREAD_BLE_INPUT_PCKT_MSG,
	THREAD_BLE_WAIT_CLI_MSG
} thread_mode_t;

//--------------------------------------------
const char no_ltk[] = "00000000000000000000000000000000";

//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static thread_mode_t thread_mode = THREAD_BLE_INPUT_PCKT_MSG;
static int out_to_pipe;
static int no_decoding;


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	msg_ble_t *ble_msg;
	msg_cli_t *cli_msg;
	ble_packet_decode_res_t res;

	for (;;)
	{
		if (thread_mode == THREAD_BLE_INPUT_PCKT_MSG)
		{
			if ((ble_msg = msg_pckt_ble_get_first()) != NULL)
			{
				if (ble_msg->info)
				{
					if (no_decoding)
					{
						res = PACKET_NOT_PROCESSED;
					}
					else
					{
						res = ble_packet_decode(ble_msg->info);
					}
				}
				else
				{
					// last packet from PCAP file input
					res = PACKET_NOT_PROCESSED;
				}
				if (out_to_pipe)
				{
					msg_ble_pipe_add_packet(ble_msg->info);
				}
				else
				{
					msg_ble_pcap_add_packet(ble_msg->info);
				}
				msg_pckt_ble_remove_cover(ble_msg);
				if (res == PACKET_PROCESSED_WAIT_CLI_MSG)
				{
					thread_mode = THREAD_BLE_WAIT_CLI_MSG;
				}
			}
		}
		if (thread_mode == THREAD_BLE_WAIT_CLI_MSG)
		{
			if ((cli_msg = msg_cli_ble_get_first()) != NULL)
			{
				switch (cli_msg->cmd)
				{
				case CLI_BLE_NO_PASSKEY:
					brute_force_use(1);
					break;
				case CLI_BLE_NO_OOB_KEY:
				case CLI_BLE_NO_LTK:
					break;
				case CLI_BLE_PASSKEY:
					legacy_pairing_passkey_set((uint8_t *)cli_msg->buf, cli_msg->size);
					break;
				case CLI_BLE_OOB_KEY:
					legacy_pairing_oob_key_set((uint8_t *)cli_msg->buf, cli_msg->size);
					break;
				case CLI_BLE_LTK:
					ltk_set((uint8_t *)cli_msg->buf, cli_msg->size);
					break;
				default:
					break;
				}
				msg_cli_ble_remove(cli_msg);
				thread_mode = THREAD_BLE_INPUT_PCKT_MSG;
			}
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sleep(10);
	}

	ble_decoder_close();
	ltk_set((uint8_t *)no_ltk, sizeof(no_ltk));
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
void thread_ble_init(int to_pipe, int no_dec)
{
	out_to_pipe = to_pipe;
	no_decoding = no_dec;
}

//--------------------------------------------
void thread_ble_start(void)
{
	pthread_t thread;
	void *param = NULL;

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_ble_stop(void)
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
