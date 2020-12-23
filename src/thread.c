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

#include "thread.h"

#ifdef _WIN32
#include <process.h>    /* _beginthreadex */

//--------------------------------------------
int thread_begin(unsigned (__stdcall *func)(void *), void *param, pthread_t *threadidptr)
{
	uintptr_t uip;
	HANDLE threadhandle;

	uip = _beginthreadex(NULL, 0, (unsigned (__stdcall *)(void *)) func, param, 0, NULL);
	threadhandle = (HANDLE) uip;
	if (threadidptr != NULL)
		*threadidptr = threadhandle;
	return (threadhandle == NULL) ? -1 : 0;
}

//--------------------------------------------
int pthread_mutex_init(pthread_mutex_t *mutex, void *unused)
{
	*mutex = CreateMutex(NULL, FALSE, NULL);
	return *mutex == NULL ? -1 : 0;
}

//--------------------------------------------
int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	return CloseHandle(*mutex) == 0 ? -1 : 0;
}

//--------------------------------------------
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1;
}

//--------------------------------------------
int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	return ReleaseMutex(*mutex) == 0 ? -1 : 0;
}

//--------------------------------------------
int pthread_cond_init(pthread_cond_t *cv, const void *unused)
{
	cv->signal = CreateEvent(NULL, FALSE, FALSE, NULL);
	cv->broadcast = CreateEvent(NULL, TRUE, FALSE, NULL);
	return cv->signal != NULL && cv->broadcast != NULL ? 0 : -1;
}

//--------------------------------------------
int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex)
{
	HANDLE handles[] = {cv->signal, cv->broadcast};
	ReleaseMutex(*mutex);
	WaitForMultipleObjects(2, handles, FALSE, INFINITE);
	return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0? 0 : -1;
}

//--------------------------------------------
int pthread_cond_signal(pthread_cond_t *cv)
{
	return SetEvent(cv->signal) == 0 ? -1 : 0;
}

//--------------------------------------------
int pthread_cond_broadcast(pthread_cond_t *cv)
{
	return PulseEvent(cv->broadcast) == 0 ? -1 : 0;
}

//--------------------------------------------
int pthread_cond_destroy(pthread_cond_t *cv)
{
	return CloseHandle(cv->signal) && CloseHandle(cv->broadcast) ? 0 : -1;
}

#else

//--------------------------------------------
int thread_begin(void *func(void *), void *param, pthread_t *threadidptr)
{
	pthread_t thread_id;
	pthread_attr_t attr;
	int result;

	pthread_attr_init(&attr);
	result = pthread_create(&thread_id, &attr, func, param);
	pthread_attr_destroy(&attr);
	pthread_detach(thread_id);
	if (threadidptr != NULL)
	{
		*threadidptr = thread_id;
	}
	return result;
}

#endif
