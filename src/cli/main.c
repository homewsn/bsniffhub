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

#include <stdlib.h>     /* exit */
#ifdef _WIN32
#include <windows.h>    /* Windows stuff */
#include "getopt.h"
#else
#include <signal.h>     /* signal */
#endif
#include "thread.h"
#include "task.h"

//--------------------------------------------
volatile unsigned int signal_exit = 0;

#ifdef _WIN32
//--------------------------------------------
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_BREAK_EVENT:
		signal_exit = 1;
		return TRUE;
	default:
		return FALSE;
	}
}
#else
//--------------------------------------------
void signal_handler(int sig)
{
	signal_exit = 1;
}
#endif

//--------------------------------------------
int main(int argc, char *argv[])
{
	int option;
	task_settings_t ts = { 0 };

#ifdef _WIN32
	SetConsoleCtrlHandler(CtrlHandler, TRUE);
#else
	sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
	signal(SIGINT, signal_handler);
#endif

	while ((option = getopt(argc, argv, "s:p:b:r:w:l:W:nL:")) != -1)
	{
		switch (option)
		{
		case 's':
			ts.opt_s = 1;
			ts.opt_s_arg = optarg;
			break;
		case 'p':
			ts.opt_p = 1;
			ts.opt_p_arg = optarg;
			break;
		case 'b':
			ts.opt_b = 1;
			ts.opt_b_arg = optarg;
			break;
		case 'r':
			ts.opt_r = 1;
			ts.opt_r_arg = optarg;
			break;
		case 'w':
			ts.opt_w = 1;
			ts.opt_w_arg = optarg;
			break;
		case 'W':
			ts.opt_W = 1;
			ts.opt_W_arg = optarg;
			break;
		case 'l':
			ts.opt_l = 1;
			ts.opt_l_arg = optarg;
			break;
		case 'n':
			ts.opt_n = 1;
			break;
		case 'L':
			ts.opt_L = 1;
			ts.opt_L_arg = optarg;
			break;
		default: // '?'
			print_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (task_start(&ts, 0) < 0)
	{
		exit(EXIT_FAILURE);
	}

	while (!signal_exit)
	{
		sleep(10);
	}

	task_stop(0);

	exit(EXIT_SUCCESS);
}
