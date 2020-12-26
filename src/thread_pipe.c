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
#include <stdio.h>      /* printf */
#include <assert.h>     /* assert */
#include <string.h>     /* memset */
#include <pcap/pcap.h>  /* pcap library stuff */
#include <time.h>       /* time */
#ifndef _WIN32
#include <errno.h>		/* errno */
#include <stdlib.h>     /* exit */
#include <fcntl.h>      /* open */
#include <unistd.h>     /* write, close */
#else
#include <fcntl.h>
#endif
#include "thread.h"
#include "thread_state.h"
#include "pipe.h"
#include "msg_ble.h"
#include "pcap.h"
#include "ble_pcap.h"
#include "msg_ble_pipe.h"
#include "msg_to_cli.h"
#include "task.h"


//--------------------------------------------
static volatile thread_state_t thread_state = THREAD_STOPPED;
static HANDLE dev;
static int pcap_dlt;


//--------------------------------------------
static int pipe_write_header(void)
{
	struct pcap_file_header pcap_hdr = { 0 };

	pcap_file_header_create(pcap_dlt, &pcap_hdr);
	return pipe_write(dev, &pcap_hdr, sizeof(struct pcap_file_header));
}

//--------------------------------------------
static int pipe_write_packet(ble_info_t *info)
{
	static uint8_t buf[MAX_PCAP_MSG_SIZE];
	struct pcap_pipe_pkthdr pcap_hdr = { 0 };
	size_t len;

	len = pcap_packet_create(pcap_dlt, info, buf);
	assert(len < MAX_PCAP_MSG_SIZE);
	pcap_packet_header_pipe_create((uint32_t)len, info, &pcap_hdr);
	if (pipe_write(dev, &pcap_hdr, sizeof(pcap_hdr)) < 0)
	{
		return -1;
	}
	if (pipe_write(dev, buf, len) < 0)
	{
		return -1;
	}
	return (int)(sizeof(pcap_hdr) + len);
}

//--------------------------------------------
static int wireshark_start(const char *name, char *pipe_name)
{
#ifdef _WIN32

	char path[MAX_PATH];
	char cmd[MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	if (name && strlen(name) < MAX_PATH)
	{
		strcpy(path, name);
	}
	else
	{
		strcpy(path, "C:\\Program Files\\Wireshark\\Wireshark.exe");
	}

	sprintf(cmd, " -i %s -k -l", pipe_name);

	if (!CreateProcess(
		path,           // The path
		cmd,            // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_NEW_PROCESS_GROUP,   // CTRL+C signals will be disabled for all processes within the new process group
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi             // Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
	))
	{
		printf("%s", "FATAL ERROR: Could not run Wireshark.\n");
		return TASK_ERROR_RUN_WIRESHARK;
	}

	if (pipe_open(pipe_name, &dev) < 0)
	{
		printf("FATAL ERROR: Could not open named pipe %s.\n", pipe_name);
		return TASK_ERROR_OPEN_PIPE;
	}

	if (pipe_write_header() < 0)
	{
		printf("FATAL ERROR: Could not write to named pipe %s.\n", pipe_name);
		return TASK_ERROR_WRITE_PIPE;
	}
	printf("%s", "Connection to Wireshark established.\n");

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

#else

	int res;
	pid_t pid;
	int child_pipe[2];
	char buf[] = { EXIT_FAILURE };

	pipe(child_pipe);
	pid = vfork();
	if (pid == 0)
	{
		char *newargv[] = { "wireshark", "-i", pipe_name, "-k", "-l", NULL };

		close(child_pipe[0]);
		fcntl(child_pipe[1], F_SETFD, FD_CLOEXEC);

		res = execvp("wireshark", newargv);
		if (res == -1)
		{
			write(child_pipe[1], buf, sizeof(buf));
			printf("%s", "FATAL ERROR: Could not run Wireshark.\n");
			perror("FATAL ERROR");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(child_pipe[1]);
	if (pid == -1)
	{
		close(child_pipe[0]);
		return TASK_ERROR_RUN_WIRESHARK;
	}
	res = read(child_pipe[0], buf, sizeof(buf));
	close(child_pipe[0]);
	if (res == sizeof(buf) && buf[0] == EXIT_FAILURE)
	{
		return TASK_ERROR_RUN_WIRESHARK;
	}

	if (pipe_open(pipe_name, &dev) < 0)
	{
		printf("FATAL ERROR: Could not open named pipe %s.\n", pipe_name);
		return TASK_ERROR_OPEN_PIPE;
	}

	if (pipe_write_header() < 0)
	{
		printf("FATAL ERROR: Could not write to named pipe %s.\n", pipe_name);
		return TASK_ERROR_WRITE_PIPE;
	}

	printf("%s", "Connection to Wireshark established.\n");

#endif

	return 0;
}


//--------------------------------------------
//** main thread

//--------------------------------------------
static void thread_run(void *param)
{
	int res = 0;
	int warning = 0;
	msg_ble_t *msg;

	for (;;)
	{
		if ((msg = msg_ble_pipe_get_first()) != NULL)
		{
			if (res >= 0)
			{
				if (msg->info)
				{
					res = pipe_write_packet(msg->info);
				}
			}
			if (!msg->info)
			{
				// last packet from PCAP file input
				msg_to_cli_add_print_command("%s", "File processing completed.\n");
				msg_to_cli_add_single_command(CLI_APP_EXIT);
			}
			msg_ble_pipe_remove(msg);
			if (res < 0)
			{
				if (!warning)
				{
					msg_to_cli_add_print_command("%s", "WARNING: Connection to Wireshark lost.\n");
					warning = 1;
				}
				if ((res = pipe_write_header()) > 0)
				{
					msg_to_cli_add_print_command("%s", "WARNING: Connection to Wireshark established.\n");
				}
			}
			else
			{
				warning = 0;
			}
		}

		if (thread_state == THREAD_STAYING)
		{
			break;
		}
		sleep(10);
	}

	pipe_close(dev);
	thread_state = THREAD_STOPPED;
}

//--------------------------------------------
#ifdef _WIN32
static unsigned int __stdcall thread_launcher(void *param)
{
	thread_run(param);
	return 0;
}
#else
static void *thread_launcher(void *param)
{
	thread_run(param);
	return NULL;
}
#endif

//--------------------------------------------
int thread_pipe_init(const char *name, int dlt)
{
	char pipe_name[100];
	char tmp_buf[50];

	assert(dlt);

	strcpy(pipe_name, PIPE_NAME);
	srand((unsigned int)time(0));
	sprintf(tmp_buf, "%d", rand());
	strcat(pipe_name, tmp_buf);

	pcap_dlt = dlt;
	return wireshark_start(name, pipe_name);
}

//--------------------------------------------
void thread_pipe_start(void)
{
	pthread_t thread;
	void *param = NULL;

	thread_state = THREAD_RUNNING;
	thread_begin(thread_launcher, param, &thread);
}

//--------------------------------------------
void thread_pipe_stop(void)
{
	if (thread_state == THREAD_RUNNING)
	{
		thread_state = THREAD_STAYING;
	}
	while (thread_state != THREAD_STOPPED)
	{
		sleep(10);
	}
}
