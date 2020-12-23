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

#ifndef PIPE_H_
#define PIPE_H_

//--------------------------------------------
#ifndef _WIN32
#ifndef HANDLE
#define HANDLE int
#endif
#define PIPE_NAME        "/tmp/bsniffhub"
#else
#define PIPE_NAME        "\\\\.\\pipe\\bsniffhub"
#endif


//--------------------------------------------
int pipe_open(const char *name, HANDLE *dev);
int pipe_change_state_to_nowait(HANDLE dev);
int pipe_change_state_to_wait(HANDLE dev);
void pipe_close(HANDLE dev);
int pipe_write(HANDLE dev, const void *buf, size_t len);

#endif /* PIPE_H_ */
