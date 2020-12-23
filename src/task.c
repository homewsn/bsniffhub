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
#include <stdio.h>      /* printf */
#include <stdlib.h>     /* atoi */
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
void print_usage(void)
{
	printf("Usage:\n");
#ifdef WIN32
	printf("  bsniffhub -s <sniffer> -p <serport> [-b <baudrate>] [-w <outfile>] [-l <link type>] [-n] [-W <path to Wireshark>]\n");
	printf("  bsniffhub -r <infile> [-w <outfile>] [-l <link type>] [-n] [-W <path to Wireshark>]\n\n");
#else
	printf("  bsniffhub -s <sniffer> -p <serport> [-b <baudrate>] [-w <outfile>] [-l <link type>] [-n]\n");
	printf("  bsniffhub -r <infile> [-w <outfile>] [-l <link type>] [-n]\n\n");
#endif
	printf("Mandatory arguments for sniffer device input:\n");
	printf("  -s <sniffer>       Sniffer device:\n");
	printf("                     'N' - nRF Sniffer v3.x.x\n");
	printf("                     'T' - SmartRF Packet Sniffer 2 v1.8.0\n");
	printf("                     'S' - Sniffle v1.4\n");
	printf("  -p <serport>       Serial port name\n\n");
	printf("Optional argument for sniffer device input:\n");
	printf("  -b <baudrate>      Serial port baudrate (def: from sniffer guide)\n\n");
	printf("Mandatory argument for PCAP file input:\n");
	printf("  -r <infile>        PCAP input file name\n\n");
	printf("Optional arguments for output (def: output to Wireshark):\n");
	printf("  -w <outfile>       PCAP output file name\n");
	printf("  -l <link type>     Output link layer type number:\n");
	printf("                     '251' - LINKTYPE_BLUETOOTH_LE_LL\n");
	printf("                     '256' - LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (def)\n");
	printf("                     '272' - LINKTYPE_NORDIC_BLE\n");
	printf("  -n                 Don't try to decode\n");
#ifdef WIN32
	printf("  -W <path to Wireshark>   Path to Wireshark.exe\n");
	printf("\nExamples:\n");
	printf("  bsniffhub -s T -p COM5\n");
	printf("  bsniffhub -s S -p COM40 -b 1000000 -W D:\\Wireshark\\Wireshark.exe\n");
	printf("  bsniffhub -s N -p COM22 -l 251 -n -w C:\\PCAP files\\test.pcap\n");
	printf("  bsniffhub -r input.pcap\n");
	printf("  bsniffhub -r C:\\PCAP files\\input.pcap -l 272 -w C:\\PCAP files\\output.pcap\n");
#else
	printf("\nExamples:\n");
	printf("  ./bsniffhub -s T -p /dev/ttyUSB2\n");
	printf("  ./bsniffhub -s S -p /dev/ttyUSB0 -b 1000000\n");
	printf("  ./bsniffhub -s N -p /dev/ttyUSB2 -l 251 -n -w test.pcap\n");
	printf("  ./bsniffhub -r input.pcap\n");
	printf("  ./bsniffhub -r input/input.pcap -l 256 -w output/output.pcap\n");
#endif
}

//--------------------------------------------
static void printf_msg(char *msg, int out2log)
{
	if (out2log)
	{
		printf("One of the options -s or -r is required.\n\n");
	}
	else
	{
		printf("%s\n", msg);
	}
}

//--------------------------------------------
int task_start(task_settings_t *ts, int gui)
{
	int baudr = 0;
	int dlt = 0;
	int res;

	// input options
	if (!ts->opt_s && !ts->opt_r)
	{
		printf("One of the options -s or -r is required.\n\n");
		print_usage();
		return TASK_ERROR_USAGE;
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
		if (ts->opt_b)
		{
			baudr = atoi(ts->opt_b_arg);
		}
		if (!get_sniffer(*ts->opt_s_arg))
		{
			printf("This -s option argument is not supported.\n\n");
			print_usage();
			return TASK_ERROR_USAGE;
		}
		if ((res = thread_sniff_init(ts->opt_p_arg, get_sniffer(*ts->opt_s_arg), baudr)) < 0)
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
		thread_ble_init(1, ts->opt_n);
	}
	else
	{
		// PCAP file output
		if ((res = thread_pcap_w_init(ts->opt_w_arg, dlt)) < 0)
		{
			return res;
		}
		thread_ble_init(0, ts->opt_n);
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
