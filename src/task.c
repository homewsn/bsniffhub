/*
* Copyright (c) 2020, 2021, 2024 Vladimir Alemasov
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
#include <stdio.h>      /* printf */
#include <stdio.h>      /* sscanf */
#include <stdlib.h>     /* atoi */
#include <string.h>     /* strlen */
#include <ctype.h>      /* isdigit */
#include "thread.h"
#include "msg_to_cli.h"
#include "msg_ble_pcap.h"
#include "msg_ble_pipe.h"
#include "msg_pckt_ble.h"
#include "msg_cli_ble.h"
#include "msg_cli_pcap.h"
#include "msg_cli_snif.h"
#include "serial.h"
#include "sniffers.h"
#include "ble_pcap.h"
#include "ble_decoder.h"
#include "thread_cli.h"
#include "thread_pcap_r.h"
#include "thread_sniff.h"
#include "thread_ble.h"
#include "thread_pipe.h"
#include "thread_pcap_w.h"
#include "task.h"


//--------------------------------------------
#define ishexchar(c)                    ((c) >= 'A' && (c) <= 'F') || ((c) >= 'a' && (c) <= 'f')

//--------------------------------------------
void print_usage(void)
{
	printf("Usage:\n");
#ifdef WIN32
	printf("  bsniffhub -s <sniffer> -p <serport> [-b <baudrate>] [-c <channel>] [-R <RSSI>] [-m <MAC>] [-e] [-w <outfile>] [-l <link type>] [-n] [-L <LTK>] [-W <path to Wireshark>]\n");
	printf("  bsniffhub -r <infile> [-w <outfile>] [-l <link type>] [-n] [-L <LTK>] [-W <path to Wireshark>]\n\n");
#else
	printf("  bsniffhub -s <sniffer> -p <serport> [-b <baudrate>] [-c <channel>] [-R <RSSI>] [-m <MAC>] [-e] [-w <outfile>] [-l <link type>] [-n] [-L <LTK>]\n");
	printf("  bsniffhub -r <infile> [-w <outfile>] [-l <link type>] [-n] [-L <LTK>]\n\n");
#endif
	printf("Mandatory arguments for sniffer device input:\n");
	printf("  -s <sniffer>       Sniffer device:\n");
	printf("                     'N3' - nRF Sniffer v3.x.0\n");
	printf("                     'N4' - nRF Sniffer v4.x.x\n");
	printf("                     'T' - SmartRF Packet Sniffer 2 v1.9/v1.10\n");
	printf("                     'S' - Sniffle v1.10\n");
	printf("                     'WB' - STM32WB BLE Sniffer v1.1.0\n");
	printf("  -p <serport>       Serial port name\n\n");
	printf("Optional argument for sniffer device input:\n");
	printf("  -b <baudrate>      Serial port baudrate (def: from sniffer guide)\n");
	printf("  -c <channel>       Primary advertising channel to listen on: 37, 38 or 39\n");
	printf("                     (def: 37, 38 and 39 for nRF Sniffer, 37 for others)\n");
	printf("  -R <RSSI>          Filter sniffer packets by minimum RSSI\n");
	printf("  -m <MAC>           Filter sniffer packets by advertiser MAC\n");
	printf("  -e                 Sniffle follow connections on secondary advertising channels\n\n");
	printf("Mandatory argument for PCAP file input:\n");
	printf("  -r <infile>        PCAP input file name\n\n");
	printf("Optional arguments for output (def: output to Wireshark):\n");
	printf("  -w <outfile>       PCAP output file name\n");
	printf("  -l <link type>     Output link layer type number:\n");
	printf("                     '251' - LINKTYPE_BLUETOOTH_LE_LL\n");
	printf("                     '256' - LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (def)\n");
	printf("                     '272' - LINKTYPE_NORDIC_BLE\n");
	printf("  -n                 Don't try to decrypt\n");
	printf("  -L <LTK>           LTK key for decrypting packets\n\n");
#ifdef WIN32
	printf("  -W <path to Wireshark>   Path to Wireshark.exe\n");
	printf("\nExamples:\n");
	printf("  bsniffhub -s T -p COM5\n");
	printf("  bsniffhub -s S -p COM40 -b 1000000 -W D:\\Wireshark\\Wireshark.exe\n");
	printf("  bsniffhub -s N4 -p COM22 -l 251 -n -w C:\\PCAP files\\test.pcap\n");
	printf("  bsniffhub -r input.pcap\n");
	printf("  bsniffhub -r C:\\PCAP files\\input.pcap -l 272 -w C:\\PCAP files\\output.pcap\n");
#else
	printf("\nExamples:\n");
	printf("  ./bsniffhub -s T -p /dev/ttyUSB2\n");
	printf("  ./bsniffhub -s S -p /dev/ttyUSB0 -b 1000000\n");
	printf("  ./bsniffhub -s N4 -p /dev/ttyUSB2 -l 251 -n -w test.pcap\n");
	printf("  ./bsniffhub -r input.pcap\n");
	printf("  ./bsniffhub -r input/input.pcap -l 256 -w output/output.pcap\n");
#endif
}

//--------------------------------------------
int task_start(task_settings_t *ts, int gui)
{
	int dlt = 0;
	int res;

	// input options
	if (!ts->opt_s && !ts->opt_r)
	{
		printf("One of the options -s or -r is required.\n\n");
		print_usage();
		return TASK_ERROR_USAGE;
	}
	if (ts->opt_n && ts->opt_L)
	{
		printf("You cannot use options -n and -L at the same time.\n\n");
		print_usage();
		return TASK_ERROR_USAGE;
	}
	if (ts->opt_L)
	{
		if (strlen(ts->opt_L_arg) != 32)
		{
			printf("The LTK length must be 32 hexadecimal characters.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
		for (size_t cnt = 0; cnt < 32; cnt++)
		{
			if (!(ishexchar(ts->opt_L_arg[cnt])) && !(isdigit(ts->opt_L_arg[cnt])))
			{
				printf("LTK must consist of hexadecimal characters only.\n\n");
				print_usage();
				return TASK_ERROR_USAGE;
			}
		}
	}
	if (ts->opt_s)
	{
		// sniffer input
		if (ts->opt_r)
		{
			printf("The -s and -r options are mutually exclusive.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
		if (!ts->opt_p)
		{
			printf("The -p option is missed.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
		int baudr = 0;
		if (ts->opt_b)
		{
			baudr = atoi(ts->opt_b_arg);
		}
		const sniffer_t *sniffer = get_sniffer(ts->opt_s_arg);
		if (!sniffer)
		{
			printf("This -s option argument is not supported.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
		if (ts->opt_R)
		{
			int rssi;
			rssi = atoi(ts->opt_R_arg);
			if (sniffer->min_rssi_set)
			{
				sniffer->min_rssi_set((int8_t)rssi);
			}
		}
		if (ts->opt_e)
		{
			if (sniffer->follow_aux_connect)
			{
				sniffer->follow_aux_connect(ts->opt_e);
			}
			else
			{
				printf("Warning: The -e option is ignored for all sniffers except Sniffle.\n");
			}
		}
		if (ts->opt_c)
		{
			int channel;
			channel = atoi(ts->opt_c_arg);
			if (channel > 39 || channel < 37)
			{
				printf("This -c option argument is not supported.\n\n");
				print_usage();
				return TASK_ERROR_USAGE;
			}
			if (sniffer->adv_channel_set)
			{
				sniffer->adv_channel_set((uint8_t)channel);
			}
		}
		if (ts->opt_m)
		{
			uint8_t mac[6];
			uint8_t mac_addr_type = 0;
			int res;
			char *buf;

			buf = ts->opt_m_arg;
			if (strlen(ts->opt_m_arg) != 17 && strlen(ts->opt_m_arg) != 18)
			{
				printf("The MAC address must be specified in colon-separated format, such as 12:34:56:78:9A:BC.\n\n");
				printf("The MAC address may have an 'r' at the end if it is a random type, such as 12:34:56:78:9A:BCr.\n\n");
				print_usage();
				return TASK_ERROR_USAGE;
			}
			if (strlen(ts->opt_m_arg) == 18)
			{
				if (buf[17] == 'r')
				{
					mac_addr_type = 1;
				}
				else
				{
					printf("The MAC address may have an 'r' at the end if it is a random type, such as 12:34:56:78:9A:BCr.\n\n");
					print_usage();
					return TASK_ERROR_USAGE;
				}
			}
			for (size_t cnt = 0; cnt < sizeof(mac); cnt++, buf += 3)
			{
				res = sscanf((const char *)buf, "%2hhx", &mac[cnt]);
				if (!res)
				{
					printf("The MAC address must be specified in colon-separated format, such as 12:34:56:78:9A:BC.\n\n");
					print_usage();
					return TASK_ERROR_USAGE;
				}
			}
			if (sniffer->mac_addr_set)
			{
				sniffer->mac_addr_set(mac, mac_addr_type);
			}
		}
		if ((res = thread_sniff_init(ts->opt_p_arg, sniffer, baudr)) < 0)
		{
			return res;
		}
	}
	else
	{
		// PCAP file input
		if (ts->opt_p)
		{
			printf("Warning: The -p option is ignored with the -r option.\n");
		}
		if (ts->opt_b)
		{
			printf("Warning: The -b option is ignored with the -r option.\n");
		}
		if (ts->opt_R)
		{
			printf("Warning: The -R option is ignored with the -r option.\n");
		}
		if (ts->opt_e)
		{
			printf("Warning: The -e option is ignored with the -r option.\n");
		}
		if (ts->opt_c)
		{
			printf("Warning: The -c option is ignored with the -r option.\n");
		}
		if (ts->opt_m)
		{
			printf("Warning: The -m option is ignored with the -r option.\n");
		}
		if ((res = thread_pcap_r_init(ts->opt_r_arg)) < 0)
		{
			return res;
		}
	}

	// output options
	if (ts->opt_l)
	{
		dlt = atoi(ts->opt_l_arg);
		if (dlt != LINKTYPE_BLUETOOTH_LE_LL &&
			dlt != LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR &&
			dlt != LINKTYPE_NORDIC_BLE)
		{
			printf("This -l option argument is not supported.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
	}
	else
	{
		dlt = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR;
	}
	if (!ts->opt_w)
	{
		// Wireshark output
		if ((res = thread_pipe_init(ts->opt_W_arg, dlt)) < 0)
		{
			return res;
		}
		if (ts->opt_L)
		{
			thread_ble_init(1, ts->opt_n, ts->opt_L_arg);
		}
		else
		{
			thread_ble_init(1, ts->opt_n, NULL);
		}
	}
	else
	{
		// PCAP file output
		if ((res = thread_pcap_w_init(ts->opt_w_arg, dlt)) < 0)
		{
			return res;
		}
		if (ts->opt_L)
		{
			thread_ble_init(0, ts->opt_n, ts->opt_L_arg);
		}
		else
		{
			thread_ble_init(0, ts->opt_n, NULL);
		}
	}

	// init message queues
	if (!gui)
	{
		msg_to_cli_init();
	}
	msg_pckt_ble_init();
	msg_cli_ble_init();
	if (ts->opt_s)
	{
		// sniffer input
		msg_cli_snif_init();
	}
	else
	{
		// PCAP file input
		msg_cli_pcap_init();
	}
	if (!ts->opt_w)
	{
		// Wireshark output
		msg_ble_pipe_init();
	}
	else
	{
		// PCAP file output
		msg_ble_pcap_init();
	}

	// start threads
	if (!gui)
	{
		thread_cli_start();
	}
	thread_ble_start();
	if (ts->opt_s)
	{
		thread_sniff_start();
	}
	else
	{
		thread_pcap_r_start();
	}
	if (!ts->opt_w)
	{
		thread_pipe_start();
	}
	else
	{
		thread_pcap_w_start();
	}

	if (ts->opt_r)
	{
		// send CLI_PCAP_PARSE_FILE message to thread_pcap
		msg_cli_pcap_add_command(CLI_PCAP_PARSE_FILE, NULL, 0);
	}

	return 0;
}

//--------------------------------------------
void task_stop(int gui)
{
	msg_cli_snif_close();
	msg_cli_pcap_close();
	msg_pckt_ble_close();
	msg_ble_pipe_close();
	msg_ble_pcap_close();
	if (!gui)
	{
		msg_to_cli_close();
	}

	thread_pipe_stop();
	thread_sniff_stop();
	thread_pcap_r_stop();
	thread_pcap_w_stop();
	thread_ble_stop();
	if (!gui)
	{
		thread_cli_stop();
	}

	msg_cli_snif_destroy();
	msg_cli_pcap_destroy();
	msg_pckt_ble_destroy();
	msg_ble_pipe_destroy();
	msg_ble_pcap_destroy();
	if (!gui)
	{
		msg_to_cli_destroy();
	}
}
