/*
* Copyright (c) 2019, 2020 Vladimir Alemasov
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

#ifndef SERIAL_H_
#define SERIAL_H_

#include "list_lstbox.h"

//--------------------------------------------
#ifdef _WIN32
#define MAX_SERDEVNAME 7
#else
#define MAX_SERDEVNAME 15
#ifndef HANDLE
#define HANDLE int
#endif
#endif

//--------------------------------------------
#define SERIAL_BUF_SIZE  8192

//--------------------------------------------
typedef struct port_settings
{
	int baudrate;
	int flow_control;
} port_settings_t;

//--------------------------------------------
int serial_open(const char *name, const port_settings_t *set, HANDLE *dev);
void serial_flush(HANDLE dev);
void serial_close(HANDLE dev);
void serial_nonfreezing_close(HANDLE dev);
int serial_read(HANDLE dev, void *buf, size_t len);
int serial_write(HANDLE dev, const void *buf, size_t len);
void serial_enum(list_lstbox_t **list);

#endif /* SERIAL_H_ */