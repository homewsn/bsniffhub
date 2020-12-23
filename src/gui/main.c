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
#include <stdlib.h>     /* exit */
#include "gui_iup.h"
#include "msg_to_cli.h"
#include "thread.h"
#include "thread_cli.h"


//--------------------------------------------
int main(int argc, char *argv[])
{
	int res = EXIT_SUCCESS;

	msg_to_cli_init();

	if (gui_open(argc, argv) < 0)
	{
		res = EXIT_FAILURE;
		goto cleanup;
	}

	thread_cli_start();

	if (!gui_show())
	{
		gui_loop();
	}
	else
	{
		res = EXIT_FAILURE;
	}
	gui_close();

cleanup:
	msg_to_cli_close();
	thread_cli_stop();
	msg_to_cli_destroy();

	exit(res);
}
