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
#ifdef _WIN32
#include <windows.h>    /* Windows stuff */
#else
#include <sys/time.h>   /* gettimeofday */
#include <stddef.h>     /* NULL */
#endif

//--------------------------------------------
uint64_t get_usec_since_epoch(void)
{
#ifdef WIN32
	FILETIME ft; // 64-bit value representing the number of tiks since Jan 1, 1601 00:00 UTC
	LARGE_INTEGER li;
	const uint64_t epoch_offset_tiks = 0x019DB1DED53E8000; // tiks betweeen Jan 1, 1601 and Jan 1, 1970
	const uint64_t tiks_per_usec = 10; // a tick is 100ns

	GetSystemTimeAsFileTime(&ft);

	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;

	return ((li.QuadPart - epoch_offset_tiks) / tiks_per_usec);
#else
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (1000000 * (uint64_t)tv.tv_sec + tv.tv_usec);
#endif
}
