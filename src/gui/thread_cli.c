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
#include <assert.h>     /* assert */
#include <stdio.h>      /* sprintf */
#include <string.h>		/* memcpy, memset */
#include "thread.h"
#include "thread_state.h"
#include "msg_to_cli.h"
#include "gui_iup.h"
#include "msg_cli_ble.h"
#include "ble.h"
#include "base64.h"

//--------------------------------------------
#define MSG_PRINT_DEVICE_RANDOM         "BLE device %d dBm %02x:%02x:%02x:%02x:%02x:%02x random detected.\n"
#define MSG_PRINT_DEVICE_PUBLIC         "BLE device %d dBm %02x:%02x:%02x:%02x:%02x:%02x public detected.\n"

//--------------------------------------------
#define SECONDS_QUESTION_PASSKEY        10
#define SECONDS_QUESTION_OOB_KEY        10
#define SECONDS_QUESTION_LTK            10

//--------------------------------------------
typedef enum
{
	THREAD_CLI_INPUT_THROUGH,
	THREAD_CLI_QUESTION_DEVICE,
	THREAD_CLI_QUESTION_PASSKEY,
	THREAD_CLI_INPUT_PASSKEY,
	THREAD_CLI_QUESTION_OOB_KEY,
	THREAD_CLI_INPUT_OOB_KEY,
	THREAD_CLI_QUESTION_LTK,
	THREAD_CLI_INPUT_LTK
} thread_mode_t;

//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static thread_mode_t thread_mode = THREAD_CLI_INPUT_THROUGH;
static int cancel_countdown;
static int key_entering;


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	for (;;)
	{
		static int count;
		static int seconds;
		static int seconds_left;
		static msg_cli_t *msg;
		static char str_buf[255];
		unsigned char adv_addr[DEVICE_ADDRESS_LENGTH];
		long res;

		switch (thread_mode)
		{
		case THREAD_CLI_INPUT_THROUGH:
			if ((msg = msg_to_cli_get_first()) != NULL)
			{
				switch (msg->cmd)
				{
				case CLI_PRINT_MSG_BUF:
					gui_log_append(msg->buf);
					break;
				case CLI_SNIF_FOLLOW_DEVICE:
					res = base64_encode(str_buf, msg->buf, DEVICE_ADDRESS_LENGTH + 2);
					assert(res <= sizeof(str_buf) + 1);
					str_buf[res] = '\0';
					gui_bledev_append(str_buf);
					memcpy(adv_addr, msg->buf, DEVICE_ADDRESS_LENGTH);
					if (msg->buf[DEVICE_ADDRESS_LENGTH + 1])
					{
						sprintf(str_buf, MSG_PRINT_DEVICE_RANDOM, msg->buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
					}
					else
					{
						sprintf(str_buf, MSG_PRINT_DEVICE_PUBLIC, msg->buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
					}
					gui_log_append(str_buf);
					break;
				case CLI_INPUT_PASSKEY:
					gui_ask_key(passkey_entering, SECONDS_QUESTION_PASSKEY);
					thread_mode = THREAD_CLI_QUESTION_PASSKEY;
					seconds_left = SECONDS_QUESTION_PASSKEY;
					count = 0;
					break;
				case CLI_INPUT_OOB_KEY:
					gui_ask_key(oob_key_entering, SECONDS_QUESTION_OOB_KEY);
					thread_mode = THREAD_CLI_QUESTION_OOB_KEY;
					seconds_left = SECONDS_QUESTION_OOB_KEY;
					count = 0;
					break;
				case CLI_INPUT_LTK:
					gui_ask_key(ltk_entering, SECONDS_QUESTION_LTK);
					thread_mode = THREAD_CLI_QUESTION_LTK;
					seconds_left = SECONDS_QUESTION_LTK;
					count = 0;
					break;
				case CLI_APP_EXIT:
					gui_stop();
					break;
				default:
					break;
				}
				msg_to_cli_remove(msg);
			}
			break;
		case THREAD_CLI_QUESTION_PASSKEY:
			seconds = SECONDS_QUESTION_PASSKEY - count / 100;
			if (!seconds || cancel_countdown)
			{
				gui_ask_key(passkey_entering, 0);
				cancel_countdown = 0;
				if (!key_entering)
				{
					msg_cli_ble_add_single_command(CLI_BLE_NO_PASSKEY);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
				}
				else
				{
					gui_enter_key(passkey_entering, 1);
					thread_mode = THREAD_CLI_INPUT_PASSKEY;
				}
			}
			else if (seconds_left != seconds || !count)
			{
				seconds_left = seconds;
				gui_ask_key(passkey_entering, seconds_left);
			}
			count++;
			break;
		case THREAD_CLI_QUESTION_OOB_KEY:
			seconds = SECONDS_QUESTION_OOB_KEY - count / 100;
			if (!seconds || cancel_countdown)
			{
				gui_ask_key(oob_key_entering, 0);
				cancel_countdown = 0;
				if (!key_entering)
				{
					msg_cli_ble_add_single_command(CLI_BLE_NO_OOB_KEY);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
				}
				else
				{
					gui_enter_key(oob_key_entering, 1);
					thread_mode = THREAD_CLI_INPUT_OOB_KEY;
				}
			}
			else if (seconds_left != seconds || !count)
			{
				seconds_left = seconds;
				gui_ask_key(oob_key_entering, seconds_left);
			}
			count++;
			break;
		case THREAD_CLI_QUESTION_LTK:
			seconds = SECONDS_QUESTION_LTK - count / 100;
			if (!seconds || cancel_countdown)
			{
				gui_ask_key(ltk_entering, 0);
				cancel_countdown = 0;
				if (!key_entering)
				{
					msg_cli_ble_add_single_command(CLI_BLE_NO_LTK);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
				}
				else
				{
					gui_enter_key(ltk_entering, 1);
					thread_mode = THREAD_CLI_INPUT_LTK;
				}
			}
			else if (seconds_left != seconds || !count)
			{
				seconds_left = seconds;
				gui_ask_key(ltk_entering, seconds_left);
			}
			count++;
			break;
		case THREAD_CLI_INPUT_PASSKEY:
		case THREAD_CLI_INPUT_OOB_KEY:
		case THREAD_CLI_INPUT_LTK:
			if (!key_entering)
			{
				thread_mode = THREAD_CLI_INPUT_THROUGH;
			}
			break;
		default:
			break;
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
void thread_cli_start(void)
{
	pthread_t thread;
	void *param = NULL;

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_cli_stop(void)
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

//--------------------------------------------
void thread_cli_cancel_countdown(int keyentering)
{
	cancel_countdown = 1;
	key_entering = keyentering;
}

//--------------------------------------------
void thread_cli_cancel_keyentering(void)
{
	key_entering = 0;
}
