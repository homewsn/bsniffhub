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

#ifdef _WIN32
#include <windows.h>    /* Windows stuff */
#else
#include <termios.h>    /* tcflush */
#include <fcntl.h>      /* open */
#include <errno.h>      /* errno */
#include <stdlib.h>     /* size_t */
#include <unistd.h>     /* read, close */
#include <dirent.h>     /* struct dirent */
#include <sys/stat.h>   /* lstat, S_ISLNK */
#include <libgen.h>     /* basename */
#endif
#include <assert.h>     /* assert */
#include <stdio.h>      /* sprintf */
#include "serial.h"

#ifndef DPRINTF
#define DPRINTF 0
#endif

#if DPRINTF
#include <stdio.h>
#ifdef _WIN32
#define print_error_serial(line) \
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
	sprintf((char *)&output, "DEBUG: Serial Error on line %ld: %s\n", line, s); \
	LocalFree(s); \
	OutputDebugStringA(output); \
	} while (0)
#else
#include <errno.h>		/* errno */
#include <string.h>		/* strerror */
#define print_error_serial(line) printf("DEBUG: Serial Error on line %d: %s\n", line, strerror(errno))
#endif
#else
#define print_error_serial(...)
#endif

#ifdef _WIN32

//--------------------------------------------
int serial_open(const char *name, const port_settings_t *set, HANDLE *dev)
{
	char filename[255] = "\\\\.\\";

	assert(name);
	assert(set);
	assert(dev);

	strcat(filename, name);
	*dev = CreateFile(
		filename,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
		NULL);
	if (*dev == INVALID_HANDLE_VALUE)
	{
		print_error_serial(__LINE__);
		return -1;
	}

	DCB dcb = { 0 };
	dcb.DCBlength = sizeof(DCB);
	dcb.fBinary = TRUE;
	dcb.ByteSize = 8;
	dcb.BaudRate = set->baudrate;
	if (set->flow_control)
	{
		dcb.fOutxCtsFlow = TRUE;
		dcb.fRtsControl = RTS_CONTROL_ENABLE;
	}

	if (!SetCommState(*dev, &dcb))
	{
		print_error_serial(__LINE__);
		serial_close(*dev);
		return -1;
	}

	COMMTIMEOUTS cto = { 0 };
	cto.ReadIntervalTimeout = MAXDWORD;
	cto.ReadTotalTimeoutMultiplier = MAXDWORD;
	cto.ReadTotalTimeoutConstant = 1;
	cto.WriteTotalTimeoutMultiplier = 0;
	cto.WriteTotalTimeoutConstant = 0;

	if (!SetCommTimeouts(*dev, &cto))
	{
		print_error_serial(__LINE__);
		serial_close(*dev);
		return -1;
	}

	serial_flush(*dev);

	return 0;
}

//--------------------------------------------
void serial_flush(HANDLE dev)
{
	PurgeComm(dev, PURGE_RXCLEAR | PURGE_TXCLEAR);
}

//--------------------------------------------
void serial_close(HANDLE dev)
{
	DWORD dwFlags;

	if (GetHandleInformation(dev, &dwFlags))
	{
		CloseHandle(dev);
	}
}

//--------------------------------------------
void serial_nonfreezing_close(HANDLE dev)
{
	DWORD dwFlags;

	if (GetHandleInformation(dev, &dwFlags))
	{
		// disable RTS control if it was
		DCB dcb = { 0 };
		dcb.DCBlength = sizeof(DCB);
		dcb.fBinary = TRUE;
		dcb.ByteSize = 8;
		dcb.BaudRate = 9600;
		SetCommState(dev, &dcb);

		CloseHandle(dev);
	}
}

//--------------------------------------------
int serial_read(HANDLE dev, void *buf, size_t len)
{
	DWORD read;
	BOOL res;

	assert(buf);
	assert(len);
	assert(dev != INVALID_HANDLE_VALUE);

	res = ReadFile(dev, buf, (DWORD)len, &read, NULL);
	if (res == FALSE)
	{
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	return (int)read;
}

//--------------------------------------------
int serial_write(HANDLE dev, const void *buf, size_t len)
{
	DWORD written;
	BOOL res;

	assert(buf);
	assert(len);
	assert(dev != INVALID_HANDLE_VALUE);

	res = WriteFile(dev, buf, (DWORD)len, &written, NULL);
	if (res == FALSE)
	{
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	return (int)written;
}

//--------------------------------------------
void serial_enum(list_lstbox_t **list)
{
	HANDLE dev;
	char devname[MAX_SERDEVNAME + 7];
	char scrname[MAX_SERDEVNAME];
	int cnt;

	for (cnt = 1; cnt <= 255; cnt++)
	{
		sprintf(devname, "\\\\.\\COM%d", cnt);
		sprintf(scrname, "COM%d", cnt);
		dev = CreateFile(
			devname,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
		if (dev == INVALID_HANDLE_VALUE)
		{
			continue;
		}
		serial_close(dev);
		list_lstbox_add(list, devname, scrname);
	}
}

#else

//--------------------------------------------
int serial_open(const char *name, const port_settings_t *set, HANDLE *dev)
{
	int baudrate_flag;
	int flow_control_flag;

	assert(name);
	assert(set);
	assert(dev);

	*dev = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (*dev == -1)
	{
		print_error_serial(__LINE__);
		return -1;
	}

	switch (set->baudrate)
	{
	case 921600:
		baudrate_flag = B921600;
		break;
	case 1000000:
		baudrate_flag = B1000000;
		break;
	case 2000000:
		baudrate_flag = B2000000;
		break;
	default:
		print_error_serial(__LINE__);
		return -1;
	}
	if (set->flow_control)
	{
		flow_control_flag = CRTSCTS;
	}
	else
	{
		flow_control_flag = 0;
	}

	struct termios tio = { 0 };
	tio.c_cflag = baudrate_flag | flow_control_flag | CS8 | CLOCAL | CREAD;
	tio.c_iflag = IGNPAR;
	tio.c_cc[VMIN] = 1;

	if (tcsetattr(*dev, TCSANOW, &tio) < 0)
	{
		print_error_serial(__LINE__);
		return -1;
	}

	serial_flush(*dev);

	return 0;
}

//--------------------------------------------
void serial_flush(HANDLE dev)
{
	tcflush(dev, TCIOFLUSH);
}

//--------------------------------------------
void serial_close(HANDLE dev)
{
	serial_flush(dev);
	close(dev);
}

//--------------------------------------------
void serial_nonfreezing_close(HANDLE dev)
{
	// disable RTS control if it was
	struct termios tio = { 0 };
	tio.c_cflag = B9600 | CS8 | CLOCAL | CREAD;
	tio.c_iflag = IGNPAR;
	tio.c_cc[VMIN] = 1;
	tcsetattr(dev, TCSANOW, &tio);

	close(dev);
}

//--------------------------------------------
int serial_read(HANDLE dev, void *buf, size_t len)
{
	ssize_t res;

	assert(buf);
	assert(len);
	assert(dev != -1);

	res = read(dev, buf, len);
	if (res == -1)
	{
		if (errno == EAGAIN)
		{
			return 0;
		}
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	if (res == 0)
	{
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	return (int)res;
}

//--------------------------------------------
int serial_write(HANDLE dev, const void *buf, size_t len)
{
	ssize_t res;

	assert(buf);
	assert(len);
	assert(dev != -1);

	res = write(dev, buf, len);
	if (res == -1)
	{
		if (errno == EAGAIN)
		{
			return 0;
		}
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	if (res == 0)
	{
		print_error_serial(__LINE__);
		serial_close(dev);
		return -1;
	}
	return (int)res;
}

//--------------------------------------------
void serial_enum(list_lstbox_t **list)
{
	int res;
	struct dirent **namelist;
	const char *sysdir = "/sys/class/tty/";
	const char *devdir = "/dev/";
	char devicedir[1024];
	char driverdir[1024];
	struct stat st;

	if ((res = scandir(sysdir, &namelist, NULL, NULL)) >= 0)
	{
		while (res--)
		{
			if (strcmp(namelist[res]->d_name, "..") && strcmp(namelist[res]->d_name, "."))
			{
				memset(devicedir, 0, sizeof(devicedir));
				memset(driverdir, 0, sizeof(driverdir));
				strcpy(devicedir, sysdir);
				strcat(devicedir, namelist[res]->d_name);
				strcat(devicedir, "/device");
				if (!lstat(devicedir, &st) && S_ISLNK(st.st_mode))
				{
					strcat(devicedir, "/driver");
					if (readlink(devicedir, driverdir, sizeof(driverdir)) > 0)
					{
						if (strcmp(basename(driverdir), "serial8250"))
						{
							memset(devicedir, 0, sizeof(devicedir));
							strcpy(devicedir, devdir);
							strcat(devicedir, namelist[res]->d_name);
							list_lstbox_add(list, devicedir, devicedir);
						}
					}
				}
			}
			free(namelist[res]);
		}
		free(namelist);
	}
}
#endif