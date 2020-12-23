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

#ifndef THREAD_SNIFF_H_
#define THREAD_SNIFF_H_

int thread_sniff_init(const char *name, const sniffer_t* sniff, int baudr);
void thread_sniff_start(void);
void thread_sniff_stop(void);

#endif /* THREAD_SNIFF_H_ */