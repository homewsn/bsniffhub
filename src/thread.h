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

#ifndef THREAD_H_
#define THREAD_H_

#ifdef _WIN32
#include <windows.h>    /* Windows stuff */

typedef HANDLE pthread_t;
typedef HANDLE pthread_mutex_t;
typedef struct pthread_cond
{
	HANDLE signal;
	HANDLE broadcast;
} pthread_cond_t;

#undef sleep
#define sleep(a) Sleep(a)
#define sched_yield() Sleep(0)

int thread_begin(unsigned(__stdcall *func)(void *), void *param, pthread_t *threadidptr);
int pthread_mutex_init(pthread_mutex_t *mutex, void *unused);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_cond_init(pthread_cond_t *cv, const void *unused);
int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex);
int pthread_cond_timewait(pthread_cond_t *cv, pthread_mutex_t *mutex, unsigned long msec);
int pthread_cond_signal(pthread_cond_t *cv);
int pthread_cond_broadcast(pthread_cond_t *cv);
int pthread_cond_destroy(pthread_cond_t *cv);

#else
#include <pthread.h>
#include <unistd.h>		/* usleep */

#define sleep(a) usleep((a) * 1000)

int thread_begin(void *func(void *), void *param, pthread_t *threadidptr);
int pthread_cond_timewait(pthread_cond_t *cv, pthread_mutex_t *mutex, unsigned long msec);

#endif

#endif /* THREAD_H_ */
