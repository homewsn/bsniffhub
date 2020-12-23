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

#include <stdint.h>     /* uint8_t ... uint64_t */
#ifdef _WIN32
#include <windows.h>    /* Windows stuff */
#else
#include <sys/stat.h>   /* mkfifo */
#include <fcntl.h>      /* open */
#include <unistd.h>     /* write, close */
#endif
#include <assert.h>     /* assert */

#ifndef DPRINTF
#define DPRINTF 0
#endif

#if DPRINTF
#include <stdio.h>
#ifdef _WIN32
#define print_error_pipe(line) \
	do { \
	char output[1024]; \
	LPTSTR s = NULL; \
	FormatMessageA(	FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
	NULL, \
	GetLastError(), \
	0, \
	(LPSTR)&s, \
	0, \
	NULL); \
	sprintf((char *)&output, "DEBUG: Pipe Error on line %d: %s\n", line, s); \
	LocalFree(s); \
	OutputDebugStringA(output); \
	} while (0)
#else
#include <errno.h>		/* errno */
#include <string.h>		/* strerror */
#define print_error_pipe(line) printf("DEBUG: Pipe Error on line %d: %s\n", line, strerror(errno))
#endif
#else
#define print_error_pipe(...)
#endif

#ifdef _WIN32

//--------------------------------------------
int pipe_open(const char *name, HANDLE *dev)
{
	assert(name);

	*dev = CreateNamedPipe(
		name,
		PIPE_ACCESS_OUTBOUND,
		PIPE_TYPE_MESSAGE | PIPE_WAIT,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	if (*dev == INVALID_HANDLE_VALUE)
	{
		print_error_pipe(__LINE__);
		return -1;
	}
	ConnectNamedPipe(*dev, NULL);
	return 0;
}

//--------------------------------------------
int pipe_change_state_to_nowait(HANDLE dev)
{
	DWORD state;

	state = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
	if (!SetNamedPipeHandleState(dev, &state, NULL, NULL))
	{
		print_error_pipe(__LINE__);
		return -1;
	}
	return 0;
}

//--------------------------------------------
int pipe_change_state_to_wait(HANDLE dev)
{
	DWORD state;

	state = PIPE_READMODE_MESSAGE | PIPE_WAIT;
	if (!SetNamedPipeHandleState(dev, &state, NULL, NULL))
	{
		print_error_pipe(__LINE__);
		return -1;
	}
	return 0;
}

//--------------------------------------------
void pipe_close(HANDLE dev)
{
	DWORD dwFlags;
	if (GetHandleInformation(dev, &dwFlags))
	{
		FlushFileBuffers(dev);
		DisconnectNamedPipe(dev);
		CloseHandle(dev);
	}
}

//--------------------------------------------
int pipe_write(HANDLE dev, const void *buf, size_t len)
{
	static int reconnect_on_error;
	DWORD written;
	BOOL res;
	DWORD err;

	if (reconnect_on_error)
	{
		res = pipe_change_state_to_nowait(dev);
		res = ConnectNamedPipe(dev, NULL);
		res = pipe_change_state_to_wait(dev);
		err = GetLastError();
		if (!res)
		{
			print_error_pipe(__LINE__);
			if (err != ERROR_PIPE_CONNECTED)
			{
				return -1;
			}
		}
	}
	if (!WriteFile(dev, buf, (DWORD)len, &written, NULL))
	{
		print_error_pipe(__LINE__);
		if (!reconnect_on_error)
		{
			DisconnectNamedPipe(dev);
			reconnect_on_error = 1;
		}
#if 0
		pipe_close(dev);
#endif
		return -1;
	}
	reconnect_on_error = 0;
	return written;
}

#else

//--------------------------------------------
#include "pipe.h"       /* HANDLE */
#include <stdio.h>      /* printf */
#include <errno.h>		/* errno */

//--------------------------------------------
int pipe_open(const char *name, HANDLE *dev)
{
	assert(name);

	unlink(name);
	if (mkfifo(name, 0666) < 0)
	{
		print_error_pipe(__LINE__);
		return -1;
	}
	*dev = open(name, O_WRONLY);
	if (*dev == -1)
	{
		print_error_pipe(__LINE__);
		return -1;
	}
	return 0;
}

//--------------------------------------------
void pipe_close(HANDLE dev)
{
	close(dev);
}

//--------------------------------------------
int pipe_write(HANDLE dev, const void *buf, size_t len)
{
	ssize_t res;

	res = write(dev, buf, len);
	if (res == -1)
	{
		print_error_pipe(__LINE__);
#if 0
		pipe_close(dev);
#endif
		return -1;
	}
	return (int)res;
}

#endif