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
	int opt_c;
	int opt_m;
	int opt_f;
	char *opt_s_arg;
	char *opt_p_arg;
	char *opt_b_arg;
	char *opt_r_arg;
	char *opt_w_arg;
	char *opt_l_arg;
	char *opt_W_arg;
	char *opt_L_arg;
	char *opt_R_arg;
	char *opt_c_arg;
	char *opt_m_arg;
	char *opt_f_arg;
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
#define TASK_ERROR_INSUFFICIENT_MEMORY           -10

//--------------------------------------------
void print_usage(void);
int task_start(task_settings_t *ts, int gui);
void task_stop(int gui);
int task_parse_filter(char *arg, uint8_t *filter);
int task_parse_channels(char *arg, uint8_t *hop_map, uint8_t *hop_map_size);
int task_parse_rssi(char *arg, int *rssi);
int task_parse_mac_address(char *arg, uint8_t *mac, uint8_t *mac_addr_type);
int task_check_ltk(char *arg);

#endif /* TASK_H_ */
