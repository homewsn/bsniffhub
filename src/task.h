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

#ifndef TASK_H_
#define TASK_H_

//--------------------------------------------
typedef struct task_settings
{
	int opt_s;
	int opt_p;
	int opt_b;
	int opt_r;
	int opt_w;
	int opt_l;
	int opt_n;
	int opt_W;
	int opt_L;
	int opt_R;
	int opt_e;
	char *opt_s_arg;
	char *opt_p_arg;
	char *opt_b_arg;
	char *opt_r_arg;
	char *opt_w_arg;
	char *opt_l_arg;
	char *opt_W_arg;
	char *opt_L_arg;
	char *opt_R_arg;
} task_settings_t;

#define TASK_ERROR_USAGE                         -1
#define TASK_ERROR_OPEN_DEVICE                   -2
#define TASK_ERROR_RUN_WIRESHARK                 -3
#define TASK_ERROR_OPEN_PCAP_FILE_FOR_READING    -4
#define TASK_ERROR_OPEN_PCAP_FILE_FOR_WRITING    -5
#define TASK_ERROR_NPCAP_INSTALLED               -6
#define TASK_ERROR_LL_NOT_SUPPORTED              -7
#define TASK_ERROR_OPEN_PIPE                     -8
#define TASK_ERROR_WRITE_PIPE                    -9

//--------------------------------------------
void print_usage(void);
int task_start(task_settings_t *ts, int gui);
void task_stop(int gui);

#endif /* TASK_H_ */
