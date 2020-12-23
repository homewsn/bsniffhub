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

#ifndef GUI_IUP_H_
#define GUI_IUP_H_

//--------------------------------------------
typedef enum key_entering_mode
{
	passkey_entering = 0,
	oob_key_entering = 1,
	ltk_entering = 2
} key_entering_mode_t;

//--------------------------------------------
int gui_open(int argc, char **argv);
int gui_show(void);
void gui_loop(void);
void gui_close(void);
void gui_log_append(const char *buf);
void gui_bledev_append(const char *buf);
void gui_stop(void);
void gui_ask_key(key_entering_mode_t mode, int seconds_left);
void gui_enter_key(key_entering_mode_t mode, int active);

#endif /* GUI_IUP_H_ */
