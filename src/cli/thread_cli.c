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
#include <stdio.h>      /* getchar, printf */
#include <string.h>		/* memcpy, memset */
#include <ctype.h>		/* isdigit, toupper */
#include "thread.h"
#include "thread_state.h"
#include "msg_to_cli.h"
#include "msg_cli_ble.h"
#include "msg_cli_snif.h"
#include "ble.h"

//--------------------------------------------
extern unsigned int signal_exit;

//--------------------------------------------
#define MSG_PRINT_DEVICE_RANDOM         "BLE device %d dBm %02x:%02x:%02x:%02x:%02x:%02x random detected.\n"
#define MSG_PRINT_DEVICE_PUBLIC         "BLE device %d dBm %02x:%02x:%02x:%02x:%02x:%02x public detected.\n"
#define MSG_QUESTION_DEVICE_TIME        "\rDo you want to follow only this device? (%.2d seconds left) [y/N] %s"
#define MSG_QUESTION_DEVICE_TIME_CLEAR  "\rDo you want to follow only this device? (%.2d seconds left) [y/N] %s  "
#define MSG_QUESTION_DEVICE_YES         "\rDo you want to follow only this device? Yes                            \n"
#define MSG_QUESTION_DEVICE_NO          "\rDo you want to follow only this device? No                             \n"
#define MSG_QUESTION_PASSKEY_TIME       "\rDo you have the Passkey? (%.2d seconds left) [y/N] %s"
#define MSG_QUESTION_PASSKEY_TIME_CLEAR "\rDo you have the Passkey? (%.2d seconds left) [y/N] %s  "
#define MSG_QUESTION_PASSKEY_YES        "\rDo you have the Passkey? Yes                           \n"
#define MSG_QUESTION_PASSKEY_NO         "\rDo you have the Passkey? No                            \n"
#define MSG_INPUT_PASSKEY               "\rPlease enter the Passkey: [6 digits] %s"
#define MSG_INPUT_PASSKEY_CLEAR         "\rPlease enter the Passkey: [6 digits] %s      "
#define MSG_INPUT_PASSKEY_RESULT        "\rPlease enter the Passkey: %s                 \n"
#define MSG_INPUT_PASSKEY_INVALID       "\rPlease enter the Passkey: Invalid Passkey entered\n"
#define MSG_QUESTION_OOB_KEY_TIME       "\rDo you have the Out of Band (OOB) key? (%.2d seconds left) [y/N] %s"
#define MSG_QUESTION_OOB_KEY_TIME_CLEAR "\rDo you have the Out of Band (OOB) key? (%.2d seconds left) [y/N] %s  "
#define MSG_QUESTION_OOB_KEY_YES        "\rDo you have the Out of Band (OOB) key? Yes                           \n"
#define MSG_QUESTION_OOB_KEY_NO         "\rDo you have the Out of Band (OOB) key? No                            \n"
#define MSG_INPUT_OOB_KEY               "\rPlease enter the OOB key: [32 hex chars] %s"
#define MSG_INPUT_OOB_KEY_CLEAR         "\rPlease enter the OOB key: [32 hex chars] %s                              "
#define MSG_INPUT_OOB_KEY_RESULT        "\rPlease enter the OOB key: %s                                             \n"
#define MSG_INPUT_OOB_KEY_INVALID       "\rPlease enter the OOB key: Invalid OOB key entered                        \n"
#define MSG_QUESTION_LTK_TIME           "\rDo you have the Long Term Key (LTK)? (%.2d seconds left) [y/N] %s"
#define MSG_QUESTION_LTK_TIME_CLEAR     "\rDo you have the Long Term Key (LTK)? (%.2d seconds left) [y/N] %s  "
#define MSG_QUESTION_LTK_YES            "\rDo you have the Long Term Key (LTK)? Yes                            \n"
#define MSG_QUESTION_LTK_NO             "\rDo you have the Long Term Key (LTK)? No                             \n"
#define MSG_INPUT_LTK                   "\rPlease enter the LTK: [32 hex chars] %s"
#define MSG_INPUT_LTK_CLEAR             "\rPlease enter the LTK: [32 hex chars] %s                              "
#define MSG_INPUT_LTK_RESULT            "\rPlease enter the LTK: %s                                             \n"
#define MSG_INPUT_LTK_INVALID           "\rPlease enter the LTK: Invalid LTK entered                            \n"

//--------------------------------------------
#define SECONDS_QUESTION_DEVICE         10
#define SECONDS_QUESTION_PASSKEY        10
#define SECONDS_QUESTION_OOB_KEY        10
#define SECONDS_QUESTION_LTK            10

//--------------------------------------------
#define ishexchar(c)                    ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f')

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

#ifdef _WIN32
#include <conio.h>

#define console_setup()

#else
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>

//--------------------------------------------
void console_setup(void)
{
	static int initialized;
	static struct termios term;

	if (!initialized)
	{
		if (isatty(STDIN_FILENO))
		{
			struct termios term_kbhit;
			if (!tcgetattr(STDIN_FILENO, &term))
			{
				memcpy(&term_kbhit, &term, sizeof(struct termios));
				term_kbhit.c_lflag &= ~(ICANON | ECHO);
				tcsetattr(STDIN_FILENO, TCSANOW, &term_kbhit);
			}
		}
		initialized = 1;
		setvbuf(stdin, NULL, _IONBF, 0);
		setvbuf(stdout, NULL, _IONBF, 0);
	}
	else
	{
		if (isatty(STDIN_FILENO))
		{
			tcsetattr(STDIN_FILENO, TCSANOW, &term);
		}
		setvbuf(stdin, NULL, _IOLBF, 0);
		setvbuf(stdout, NULL, _IOLBF, 0);
	}
}

//--------------------------------------------
int _kbhit(void)
{
	int bytes_waiting;

	ioctl(STDIN_FILENO, FIONREAD, &bytes_waiting);
	return bytes_waiting;
}

#define _getch getchar
#endif


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	console_setup();

	for (;;)
	{
		static int res;
		static int count;
		static int seconds;
		static int seconds_left;
		static unsigned char adv_addr[DEVICE_ADDRESS_LENGTH];
		static char yesno[2];
		static char passkey[7];
		static char hexkey[33];
		static size_t yesno_count;
		static size_t passkey_count;
		static size_t hexkey_count;
		static msg_cli_t *msg;


		res = _kbhit();

		if (res)
		{
			res = _getch();
#ifdef _WIN32
			if (res == 0 || res == 0xE0)
			{
				// exclude function key or an arrow key
				res = _getch();
				res = 0;
			}
			else if (res <= ' ' && res != '\b' && res != '\r')
			{
				// exclude space and special characters other than backspace and carriage return
				res = 0;
			}
#else
			if (res == 0x1B)
			{
				// exclude escape sequences
				while (_kbhit())
				{
					_getch();
				}
				res = 0;
			}
			else if (res <= ' ' && res != '\b' && res != '\n')
			{
				// exclude space and special characters other than backspace and new line
				res = 0;
			}
#endif
		}

		if (res)
		{
			switch (thread_mode)
			{
			case THREAD_CLI_QUESTION_DEVICE:
				if (res == '\r' || res == '\n')
				{
					// enter
					switch (yesno[0])
					{
					case 'y':
					case 'Y':
						printf(MSG_QUESTION_DEVICE_YES);
						msg_cli_snif_copybuf_add_command(CLI_SNIF_FOLLOW_DEVICE, adv_addr, DEVICE_ADDRESS_LENGTH);
						break;
					default:
						printf(MSG_QUESTION_DEVICE_NO);
						break;
					}
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!yesno_count)
					{
						break;
					}
					yesno[--yesno_count] = '\0';
					printf(MSG_QUESTION_DEVICE_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_DEVICE_TIME, seconds_left, yesno);
					break;
				}
				if (!yesno_count)
				{
					// symbol
					yesno[yesno_count++] = (char)res;
					printf(MSG_QUESTION_DEVICE_TIME, seconds_left, yesno);
				}
				break;
			case THREAD_CLI_QUESTION_PASSKEY:
				if (res == '\r' || res == '\n')
				{
					// enter
					switch (yesno[0])
					{
					case 'y':
					case 'Y':
						printf(MSG_QUESTION_PASSKEY_YES);
						printf(MSG_INPUT_PASSKEY, passkey);
						thread_mode = THREAD_CLI_INPUT_PASSKEY;
						break;
					default:
						printf(MSG_QUESTION_PASSKEY_NO);
						msg_cli_ble_add_single_command(CLI_BLE_NO_PASSKEY);
						thread_mode = THREAD_CLI_INPUT_THROUGH;
						break;
					}
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!yesno_count)
					{
						break;
					}
					yesno[--yesno_count] = '\0';
					printf(MSG_QUESTION_PASSKEY_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_PASSKEY_TIME, seconds_left, yesno);
					break;
				}
				if (!yesno_count)
				{
					// symbol
					yesno[yesno_count++] = (char)res;
					printf(MSG_QUESTION_PASSKEY_TIME, seconds_left, yesno);
				}
				break;
			case THREAD_CLI_INPUT_PASSKEY:
				if (res == '\r' || res == '\n')
				{
					// enter
					if (passkey_count == sizeof(passkey) - 1)
					{
						printf(MSG_INPUT_PASSKEY_RESULT, passkey);
						msg_cli_ble_copybuf_add_command(CLI_BLE_PASSKEY, (const uint8_t*)passkey, sizeof(passkey));
						msg_cli_snif_copybuf_add_command(CLI_SNIF_PASSKEY, (const uint8_t*)passkey, sizeof(passkey));
					}
					else
					{
						printf(MSG_INPUT_PASSKEY_INVALID);
						msg_cli_ble_add_single_command(CLI_BLE_NO_PASSKEY);
					}
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					passkey_count = 0;
					memset(passkey, 0, sizeof(passkey));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!passkey_count)
					{
						break;
					}
					passkey[--passkey_count] = '\0';
					printf(MSG_INPUT_PASSKEY_CLEAR, passkey);
					printf(MSG_INPUT_PASSKEY, passkey);
					break;
				}
				if (passkey_count < (sizeof(passkey) - 1) && isdigit(res))
				{
					// digit
					passkey[passkey_count++] = (char)res;
					printf(MSG_INPUT_PASSKEY, passkey);
					break;
				}
				break;
			case THREAD_CLI_QUESTION_OOB_KEY:
				if (res == '\r' || res == '\n')
				{
					// enter
					switch (yesno[0])
					{
					case 'y':
					case 'Y':
						printf(MSG_QUESTION_OOB_KEY_YES);
						printf(MSG_INPUT_OOB_KEY, hexkey);
						thread_mode = THREAD_CLI_INPUT_OOB_KEY;
						break;
					default:
						printf(MSG_QUESTION_OOB_KEY_NO);
						msg_cli_ble_add_single_command(CLI_BLE_NO_OOB_KEY);
						thread_mode = THREAD_CLI_INPUT_THROUGH;
						break;
					}
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!yesno_count)
					{
						break;
					}
					yesno[--yesno_count] = '\0';
					printf(MSG_QUESTION_OOB_KEY_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_OOB_KEY_TIME, seconds_left, yesno);
					break;
				}
				if (!yesno_count)
				{
					// symbol
					yesno[yesno_count++] = (char)res;
					printf(MSG_QUESTION_OOB_KEY_TIME, seconds_left, yesno);
				}
				break;
			case THREAD_CLI_INPUT_OOB_KEY:
				if (res == '\r' || res == '\n')
				{
					// enter
					if (hexkey_count == sizeof(hexkey) - 1)
					{
						printf(MSG_INPUT_OOB_KEY_RESULT, hexkey);
						msg_cli_ble_copybuf_add_command(CLI_BLE_OOB_KEY, (const uint8_t*)hexkey, sizeof(hexkey));
						msg_cli_snif_copybuf_add_command(CLI_SNIF_OOB_KEY, (const uint8_t*)hexkey, sizeof(hexkey));
					}
					else
					{
						printf(MSG_INPUT_OOB_KEY_INVALID);
						msg_cli_ble_add_single_command(CLI_BLE_NO_OOB_KEY);
					}
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					hexkey_count = 0;
					memset(hexkey, 0, sizeof(hexkey));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!hexkey_count)
					{
						break;
					}
					hexkey[--hexkey_count] = '\0';
					printf(MSG_INPUT_OOB_KEY_CLEAR, hexkey);
					printf(MSG_INPUT_OOB_KEY, hexkey);
					break;
				}
				if (hexkey_count < (sizeof(hexkey) - 1) && (ishexchar(res) || isdigit(res)))
				{
					// hex symbol
					if (ishexchar(res))
					{
						hexkey[hexkey_count++] = (char)((isupper(res)) ? res : toupper(res));
					}
					else
					{
						hexkey[hexkey_count++] = (char)res;
					}
					printf(MSG_INPUT_OOB_KEY, hexkey);
					break;
				}
				break;
			case THREAD_CLI_QUESTION_LTK:
				if (res == '\r' || res == '\n')
				{
					// enter
					switch (yesno[0])
					{
					case 'y':
					case 'Y':
						printf(MSG_QUESTION_LTK_YES);
						printf(MSG_INPUT_LTK, hexkey);
						thread_mode = THREAD_CLI_INPUT_LTK;
						break;
					default:
						printf(MSG_QUESTION_LTK_NO);
						msg_cli_ble_add_single_command(CLI_BLE_NO_LTK);
						thread_mode = THREAD_CLI_INPUT_THROUGH;
						break;
					}
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!yesno_count)
					{
						break;
					}
					yesno[--yesno_count] = '\0';
					printf(MSG_QUESTION_LTK_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_LTK_TIME, seconds_left, yesno);
					break;
				}
				if (!yesno_count)
				{
					// symbol
					yesno[yesno_count++] = (char)res;
					printf(MSG_QUESTION_LTK_TIME, seconds_left, yesno);
				}
				break;
			case THREAD_CLI_INPUT_LTK:
				if (res == '\r' || res == '\n')
				{
					// enter
					if (hexkey_count == sizeof(hexkey) - 1)
					{
						printf(MSG_INPUT_LTK_RESULT, hexkey);
						msg_cli_ble_copybuf_add_command(CLI_BLE_LTK, (const uint8_t *)hexkey, sizeof(hexkey));
						msg_cli_snif_copybuf_add_command(CLI_SNIF_LTK, (const uint8_t *)hexkey, sizeof(hexkey));
					}
					else
					{
						printf(MSG_INPUT_LTK_INVALID);
						msg_cli_ble_add_single_command(CLI_BLE_NO_LTK);
					}
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					hexkey_count = 0;
					memset(hexkey, 0, sizeof(hexkey));
					break;
				}
				if (res == '\b' || res == 0x7F)
				{
					// backspace
					if (!hexkey_count)
					{
						break;
					}
					hexkey[--hexkey_count] = '\0';
					printf(MSG_INPUT_LTK_CLEAR, hexkey);
					printf(MSG_INPUT_LTK, hexkey);
					break;
				}
				if (hexkey_count < (sizeof(hexkey) - 1) && (ishexchar(res) || isdigit(res)))
				{
					// hex symbol
					if (ishexchar(res))
					{
						hexkey[hexkey_count++] = (char)((isupper(res)) ? res : toupper(res));
					}
					else
					{
						hexkey[hexkey_count++] = (char)res;
					}
					printf(MSG_INPUT_LTK, hexkey);
					break;
				}
				break;
			default:
				break;
			}
		}
		else
		{
			switch (thread_mode)
			{
			case THREAD_CLI_INPUT_THROUGH:
				if ((msg = msg_to_cli_get_first()) != NULL)
				{
					switch (msg->cmd)
					{
					case CLI_PRINT_MSG_BUF:
						printf("%s", msg->buf);
						break;
					case CLI_SNIF_FOLLOW_DEVICE:
						memcpy(adv_addr, msg->buf, DEVICE_ADDRESS_LENGTH);
						if (msg->buf[DEVICE_ADDRESS_LENGTH + 1])
						{
							printf(MSG_PRINT_DEVICE_RANDOM, msg->buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
						}
						else
						{
							printf(MSG_PRINT_DEVICE_PUBLIC, msg->buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
						}
						thread_mode = THREAD_CLI_QUESTION_DEVICE;
						seconds_left = SECONDS_QUESTION_DEVICE;
						count = 0;
						break;
					case CLI_INPUT_PASSKEY:
						thread_mode = THREAD_CLI_QUESTION_PASSKEY;
						seconds_left = SECONDS_QUESTION_PASSKEY;
						count = 0;
						break;
					case CLI_INPUT_OOB_KEY:
						thread_mode = THREAD_CLI_QUESTION_OOB_KEY;
						seconds_left = SECONDS_QUESTION_OOB_KEY;
						count = 0;
						break;
					case CLI_INPUT_LTK:
						thread_mode = THREAD_CLI_QUESTION_LTK;
						seconds_left = SECONDS_QUESTION_LTK;
						count = 0;
						break;
					case CLI_APP_EXIT:
						signal_exit = 1;
						break;
					default:
						break;
					}
					msg_to_cli_remove(msg);
				}
				break;
			case THREAD_CLI_QUESTION_DEVICE:
				seconds = SECONDS_QUESTION_DEVICE - count / 100;
				if (!seconds)
				{
					printf(MSG_QUESTION_DEVICE_NO);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
				}
				else if (seconds_left != seconds || !count)
				{
					seconds_left = seconds;
					printf(MSG_QUESTION_DEVICE_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_DEVICE_TIME, seconds_left, yesno);
				}
				count++;
				break;
			case THREAD_CLI_QUESTION_PASSKEY:
				seconds = SECONDS_QUESTION_PASSKEY - count / 100;
				if (!seconds)
				{
					printf(MSG_QUESTION_PASSKEY_NO);
					msg_cli_ble_add_single_command(CLI_BLE_NO_PASSKEY);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
				}
				else if (seconds_left != seconds || !count)
				{
					seconds_left = seconds;
					printf(MSG_QUESTION_PASSKEY_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_PASSKEY_TIME, seconds_left, yesno);
				}
				count++;
				break;
			case THREAD_CLI_QUESTION_OOB_KEY:
				seconds = SECONDS_QUESTION_OOB_KEY - count / 100;
				if (!seconds)
				{
					printf(MSG_QUESTION_OOB_KEY_NO);
					msg_cli_ble_add_single_command(CLI_BLE_NO_OOB_KEY);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
				}
				else if (seconds_left != seconds || !count)
				{
					seconds_left = seconds;
					printf(MSG_QUESTION_OOB_KEY_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_OOB_KEY_TIME, seconds_left, yesno);
				}
				count++;
				break;
			case THREAD_CLI_QUESTION_LTK:
				seconds = SECONDS_QUESTION_LTK - count / 100;
				if (!seconds)
				{
					printf(MSG_QUESTION_LTK_NO);
					msg_cli_ble_add_single_command(CLI_BLE_NO_LTK);
					thread_mode = THREAD_CLI_INPUT_THROUGH;
					yesno_count = 0;
					memset(yesno, 0, sizeof(yesno));
				}
				else if (seconds_left != seconds || !count)
				{
					seconds_left = seconds;
					printf(MSG_QUESTION_LTK_TIME_CLEAR, seconds_left, yesno);
					printf(MSG_QUESTION_LTK_TIME, seconds_left, yesno);
				}
				count++;
				break;
			default:
				break;
			}
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sleep(10);
	}

	console_setup();
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
