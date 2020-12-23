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

#ifndef THREAD_PCAP_R_H_
#define THREAD_PCAP_R_H_

int thread_pcap_r_init(const char *name);
void thread_pcap_r_start(void);
void thread_pcap_r_stop(void);

#endif /* THREAD_PCAP_R_H_ */