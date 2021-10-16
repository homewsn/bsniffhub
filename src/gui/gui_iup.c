/*
* Copyright (c) 2020, 2021 Vladimir Alemasov
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
#endif
#include <stdint.h>     /* uint8_t ... uint64_t */
#include <stdio.h>      /* sprintf */
#include <stdlib.h>     /* NULL */
#include <string.h>     /* memcpy */
#include <assert.h>     /* assert */
#include <iup.h>
#include "list_lstbox.h"
#include "serial.h"
#include "task.h"
#include "msg_cli_snif.h"
#include "msg_cli_ble.h"
#include "ble.h"
#include "gui_iup.h"
#include "thread_cli.h"
#include "ble_info.h"
#include "sniffers.h"
#ifndef _WIN32
#include "iup_icon.h"
#endif

//--------------------------------------------
#define LST_ITEM_DEVICE_RANDOM          "%d dBm %02x:%02x:%02x:%02x:%02x:%02x random"
#define LST_ITEM_DEVICE_PUBLIC          "%d dBm %02x:%02x:%02x:%02x:%02x:%02x public"

#define MSG_PRINT_ALLDEVICE_FOLLOW      "Sniffer follows all advertising devices.\n"
#define MSG_PRINT_DEVICE_FOLLOW         "Sniffer only follows %02x:%02x:%02x:%02x:%02x:%02x BLE device.\n"
#define MSG_QUESTION_PASSKEY_TIME       "Do you have the Passkey? (%.2d seconds left)"
#define MSG_INPUT_PASSKEY               "Please enter the Passkey (6 digits):"
#define MSG_INPUT_PASSKEY_RESULT        "Passkey entered: %s\n"
#define MSG_INPUT_PASSKEY_INVALID       "Invalid Passkey entered\n"
#define MSG_QUESTION_OOB_KEY_TIME       "Do you have the Out of Band (OOB) key? (%.2d seconds left)"
#define MSG_INPUT_OOB_KEY               "Please enter the OOB key (32 hex chars):"
#define MSG_INPUT_OOB_KEY_RESULT        "OOB key entered: %s\n"
#define MSG_INPUT_OOB_KEY_INVALID       "Invalid OOB key entered\n"
#define MSG_QUESTION_LTK_TIME           "Do you have the Long Term Key (LTK)? (%.2d seconds left)"
#define MSG_INPUT_LTK                   "Please enter the LTK (32 hex chars):"
#define MSG_INPUT_LTK_RESULT            "LTK entered: %s\n"
#define MSG_INPUT_LTK_INVALID           "Invalid LTK entered\n"

#define IUP_TEXT_MASK_6DIGITPASSKEY     "/d/d/d/d/d/d"
#define IUP_TEXT_MASK_32SYMBOLHEXKEY    "[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]"


//--------------------------------------------
static list_lstbox_t *list_iface, *list_sniff, *list_baudr, *list_link, *list_bledev;
static int dlg_width;
static int btn_out_path_mode;
static key_entering_mode_t key_mode;
static Ihandle *dlg;
static Ihandle *vbox_in, *vbox_in_path, *lbl_in_path;
static Ihandle *hbox_in_sel, *hbox_in_bleconn, *hbox_bledev, *hbox_in_capdev;
static Ihandle *vbox_out, *vbox_out_path, *lbl_out_path;
static Ihandle *tgl_in_pcap, *tgl_out_pcap;
static Ihandle *lst_iface, *lst_sniff, *lst_baudr, *lst_bledev, *lst_link;
static Ihandle *txt_in_path, *txt_out_path, *txt_log;
static Ihandle *btn_start, *btn_stop, *btn_bledev;
static Ihandle *lbl_qstn, *lbl_key, *txt_key;
static Ihandle *vbox_bleconn, *hbox_qstn, *hbox_key;
static Ihandle *tgl_nodec;

//--------------------------------------------
static void list_iface_load(void)
{
	list_lstbox_remove_all(&list_iface);
	serial_enum(&list_iface);
}

//--------------------------------------------
static void list_sniff_load(void)
{
	list_lstbox_init(&list_sniff);
	list_lstbox_add(&list_sniff, "S", "Sniffle v1.6");
	list_lstbox_add(&list_sniff, "N3", "nRF Sniffer v3.x.x");
	list_lstbox_add(&list_sniff, "N4", "nRF Sniffer v4.0.0");
	list_lstbox_add(&list_sniff, "T", "SmartRF Packet Sniffer 2 v1.9.0");
}

//--------------------------------------------
static void list_baudr_load(void)
{
	list_lstbox_init(&list_baudr);
	list_lstbox_add(&list_baudr, "921600", "921600");
	list_lstbox_add(&list_baudr, "1000000", "1000000");
	list_lstbox_add(&list_baudr, "2000000", "2000000");
	list_lstbox_add(&list_baudr, "3000000", "3000000");
}

//--------------------------------------------
static void list_bledev_load(void)
{
	list_lstbox_remove_all(&list_bledev);
	list_lstbox_add(&list_bledev, "\0\0\0\0\0\0", "All advertising devices");
}

//--------------------------------------------
static void list_link_load(void)
{
	list_lstbox_init(&list_link);
	list_lstbox_add(&list_link, "251", "LINKTYPE_BLUETOOTH_LE_LL");
	list_lstbox_add(&list_link, "256", "LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR");
	list_lstbox_add(&list_link, "272", "LINKTYPE_NORDIC_BLE");
}

//--------------------------------------------
static void lst_load(Ihandle *ih, list_lstbox_t **list, int next)
{
	IupSetAttribute(ih, "1", NULL);
	for (int cnt = 1; cnt <= (int)list_lstbox_get_length(list); cnt++)
	{
		IupSetStrAttributeId(ih, "", cnt, list_lstbox_find_scrname_by_id(list, cnt));
		IupSetIntId(ih, "ID", cnt, cnt);
	}
	IupSetInt(ih, "VALUE", next);
}

//--------------------------------------------
static int lst_sniff_action_cb(Ihandle *ih, char *text, int item, int state)
{
	char *name = list_lstbox_find_devname_by_id(&list_sniff, IupGetInt(lst_sniff, "VALUE"));
	const sniffer_t *sniff = get_sniffer(name);
	if (sniff)
	{
		char baudr[10];
		int id;
		sprintf(baudr, "%d", sniff->sets.baudrate);
		id = list_lstbox_find_id_by_devname(&list_baudr, baudr);
		if (id != -1)
		{
			IupSetInt(lst_baudr, "VALUE", id);
		}
	}
	return IUP_DEFAULT;
}

//--------------------------------------------
static void in_path_var(int var)
{
	if (!var)
	{
		IupUnmap(vbox_in_path);
		IupDetach(vbox_in_path);
		list_iface_load();
		lst_load(lst_iface, &list_iface, 1);
		lst_load(lst_sniff, &list_sniff, 1);
		lst_load(lst_baudr, &list_baudr, 1);
		IupInsert(vbox_in, hbox_in_bleconn, hbox_in_capdev);
		IupMap(hbox_in_capdev);
		lst_sniff_action_cb(NULL, NULL, 0, 0);
	}
	else
	{
		IupUnmap(hbox_in_capdev);
		IupDetach(hbox_in_capdev);
		IupInsert(vbox_in, hbox_in_bleconn, vbox_in_path);
		IupMap(vbox_in_path);
	}
	IupSetStrf(dlg, "SIZE", "%dx", dlg_width);
	IupRefresh(dlg);
}

//--------------------------------------------
static void out_path_var(int var)
{
#ifdef _WIN32
	if (!var)
	{
		IupSetAttribute(lbl_out_path, "TITLE", "Specify path to Wireshark:");
		IupSetAttribute(txt_out_path, "VALUE", "C:\\Program Files\\Wireshark\\Wireshark.exe");
		btn_out_path_mode = 0;
	}
	else
	{
		IupSetAttribute(lbl_out_path, "TITLE", "Specify path to PCAP file:");
		IupSetAttribute(txt_out_path, "VALUE", NULL);
		btn_out_path_mode = 1;
	}
#else
	if (!var)
	{
		IupUnmap(vbox_out_path);
		IupDetach(vbox_out_path);
	}
	else
	{
		IupAppend(vbox_out, vbox_out_path);
		IupMap(vbox_out_path);
	}
#endif
	IupSetStrf(dlg, "SIZE", "%dx", dlg_width);
	IupRefresh(dlg);
}

//--------------------------------------------
static int tgl_in_pcap_action_cb(Ihandle *ih)
{
	in_path_var(IupGetInt(ih, "VALUE"));
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_out_pcap_action_cb(Ihandle *ih)
{
	out_path_var(IupGetInt(ih, "VALUE"));
	return IUP_DEFAULT;
}

//--------------------------------------------
static int txt_log_postmessage_cb(Ihandle *ih, const char* s, int i, double d, void* p)
{
	IupSetAttribute(ih, "APPEND", s);
	IupSetInt(ih, "SCROLLTOPOS", IupGetInt(ih, "COUNT"));
	return IUP_DEFAULT;
}

//--------------------------------------------
static int lst_bledev_postmessage_cb(Ihandle *ih, const char* s, int i, double d, void* p)
{
	static char str_buf[255];
	static unsigned char adv_addr[DEVICE_ADDRESS_LENGTH + 1] = { 0 };

	memcpy(adv_addr, s, DEVICE_ADDRESS_LENGTH);
	if (s[DEVICE_ADDRESS_LENGTH + 1])
	{
		sprintf(str_buf, LST_ITEM_DEVICE_RANDOM, s[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
	}
	else
	{
		sprintf(str_buf, LST_ITEM_DEVICE_PUBLIC, s[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
	}
	IupSetAttribute(ih, "APPENDITEM", str_buf);
	list_lstbox_add(&list_bledev, (const char *)adv_addr, str_buf);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_in_path_action_cb(Ihandle* ih)
{
	Ihandle *dlg_file = IupFileDlg();

	IupSetAttribute(dlg_file, "DIALOGTYPE", "OPEN");
	IupSetAttribute(dlg_file, "TITLE", "Select Input PCAP file");
#if 1
	IupSetAttributes(dlg_file, "FILTER = \"*.pcap;*.pcapng\", FILTERINFO = \"PCAP Files\"");
#else
	IupSetAttributes(dlg_file, "FILTER = \"*.pcap\", FILTERINFO = \"PCAP Files\"");
#endif

	IupPopup(dlg_file, IUP_CURRENT, IUP_CURRENT);

	if (IupGetInt(dlg_file, "STATUS") != -1)
	{
		IupSetAttribute(txt_in_path, "VALUE", IupGetAttribute(dlg_file, "VALUE"));
	}

	IupDestroy(dlg_file);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_out_path_action_cb(Ihandle* ih)
{
	Ihandle *dlg_file = IupFileDlg();

#ifdef _WIN32
	if (btn_out_path_mode)
	{
		IupSetAttribute(dlg_file, "DIALOGTYPE", "SAVE");
		IupSetAttribute(dlg_file, "TITLE", "Select Output PCAP file");
		IupSetAttributes(dlg_file, "FILTER = \"*.pcap\", FILTERINFO = \"PCAP Files\"");
	}
	else
	{
		IupSetAttribute(dlg_file, "DIALOGTYPE", "OPEN");
		IupSetAttribute(dlg_file, "TITLE", "Find Wireshark executable file");
		IupSetAttribute(dlg_file, "FILE", "C:\\Program Files\\Wireshark\\Wireshark.exe");
		IupSetAttributes(dlg_file, "FILTER = \"Wireshark.exe\", FILTERINFO = \"Wireshark\"");
	}
#else
	IupSetAttribute(dlg_file, "DIALOGTYPE", "SAVE");
	IupSetAttribute(dlg_file, "TITLE", "Select Output PCAP file");
	IupSetAttributes(dlg_file, "FILTER = \"*.pcap\", FILTERINFO = \"PCAP Files\"");
#endif

	IupPopup(dlg_file, IUP_CURRENT, IUP_CURRENT);

	if (IupGetInt(dlg_file, "STATUS") != -1)
	{
		IupSetAttribute(txt_out_path, "VALUE", IupGetAttribute(dlg_file, "VALUE"));
	}

	IupDestroy(dlg_file);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_start_action_cb(Ihandle* ih)
{
	int in_pcap_option;
	int out_pcap_option;
	task_settings_t ts;
	int res;

	in_pcap_option = IupGetInt(tgl_in_pcap, "VALUE");

	if (!in_pcap_option)
	{
		ts.opt_s = 1;
		ts.opt_s_arg = list_lstbox_find_devname_by_id(&list_sniff, IupGetInt(lst_sniff, "VALUE"));
		ts.opt_p = 1;
		ts.opt_p_arg = list_lstbox_find_devname_by_id(&list_iface, IupGetInt(lst_iface, "VALUE"));
		ts.opt_b = 1;
		ts.opt_b_arg = list_lstbox_find_devname_by_id(&list_baudr, IupGetInt(lst_baudr, "VALUE"));
		ts.opt_r = 0;
	}
	else
	{
		ts.opt_s = 0;
		ts.opt_p = 0;
		ts.opt_b = 0;
		ts.opt_r = 1;
		ts.opt_r_arg = IupGetAttribute(txt_in_path, "VALUE");
	}

	out_pcap_option = IupGetInt(tgl_out_pcap, "VALUE");
	if (!out_pcap_option)
	{
#ifdef _WIN32
		ts.opt_W = 1;
		ts.opt_W_arg = IupGetAttribute(txt_out_path, "VALUE");
#else
		ts.opt_W = 0;
#endif
		ts.opt_w = 0;
	}
	else
	{
		ts.opt_W = 0;
		ts.opt_w = 1;
		ts.opt_w_arg = IupGetAttribute(txt_out_path, "VALUE");
	}
	ts.opt_l = 1;
	ts.opt_l_arg = list_lstbox_find_devname_by_id(&list_link, IupGetInt(lst_link, "VALUE"));
	ts.opt_n = IupGetInt(tgl_nodec, "VALUE");

	if ((res = task_start(&ts, 1)) < 0)
	{
		char str_buf[1024] = { 0 };

		switch (res)
		{
		case TASK_ERROR_OPEN_DEVICE:
			sprintf(str_buf, "FATAL ERROR: Could not open device %s.\n", list_lstbox_find_scrname_by_id(&list_iface, IupGetInt(lst_iface, "VALUE")));
			break;
		case TASK_ERROR_RUN_WIRESHARK:
		case TASK_ERROR_OPEN_PIPE:
		case TASK_ERROR_WRITE_PIPE:
			sprintf(str_buf, "FATAL ERROR: Could not run Wireshark or open pipe.\n");
			break;
		case TASK_ERROR_OPEN_PCAP_FILE_FOR_READING:
			sprintf(str_buf, "FATAL ERROR: Could not open file %s for reading.\n", IupGetAttribute(txt_in_path, "VALUE"));
			break;
		case TASK_ERROR_LL_NOT_SUPPORTED:
			sprintf(str_buf, "FATAL ERROR: Unsupported link layer type in %s.\n", IupGetAttribute(txt_in_path, "VALUE"));
			break;
		case TASK_ERROR_OPEN_PCAP_FILE_FOR_WRITING:
			sprintf(str_buf, "FATAL ERROR: Could not open file %s for writing.\n", IupGetAttribute(txt_out_path, "VALUE"));
			break;
		case TASK_ERROR_NPCAP_INSTALLED:
			sprintf(str_buf, "FATAL ERROR: Could not find Npcap runtime libraries installed.\n");
			break;
		default:
			sprintf(str_buf, "FATAL ERROR: Unknown.\n");
			break;
		}
		gui_log_append(str_buf);
		task_stop(1);
	}
	else
	{
		IupSetAttribute(hbox_in_sel, "ACTIVE", "NO");
		IupSetAttribute(btn_start, "ACTIVE", "NO");
		IupSetAttribute(btn_stop, "ACTIVE", "YES");

		IupSetAttribute(hbox_in_bleconn, "ACTIVE", "YES");
		if (!in_pcap_option)
		{
			IupSetAttribute(hbox_in_capdev, "ACTIVE", "NO");
			IupSetAttribute(hbox_bledev, "ACTIVE", "YES");
		}
		else
		{
			IupSetAttribute(vbox_in_path, "ACTIVE", "NO");
			IupSetAttribute(hbox_bledev, "ACTIVE", "NO");
		}
		IupSetAttribute(vbox_out, "ACTIVE", "NO");
	}

	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_stop_action_cb(Ihandle* ih)
{
	int in_pcap_option;

	task_stop(1);

	in_pcap_option = IupGetInt(tgl_in_pcap, "VALUE");
	IupSetAttribute(hbox_in_sel, "ACTIVE", "YES");
	IupSetAttribute(btn_start, "ACTIVE", "YES");
	IupSetAttribute(btn_stop, "ACTIVE", "NO");

	IupSetAttribute(hbox_in_bleconn, "ACTIVE", "NO");
	IupSetAttribute(hbox_bledev, "ACTIVE", "NO");
	if (!in_pcap_option)
	{
		IupSetAttribute(hbox_in_capdev, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(vbox_in_path, "ACTIVE", "YES");
	}
	IupSetAttribute(vbox_out, "ACTIVE", "YES");

	list_bledev_load();
	lst_load(lst_bledev, &list_bledev, 1);

	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_stop_postmessage_cb(Ihandle *ih, const char* s, int i, double d, void* p)
{
	return btn_stop_action_cb(ih);
}

//--------------------------------------------
static int btn_exit_action_cb(Ihandle* ih)
{
	btn_stop_action_cb(ih);
	return IUP_CLOSE;
}

//--------------------------------------------
static int btn_bledev_action_cb(Ihandle* ih)
{
	int res = IupGetInt(lst_bledev, "VALUE");
	unsigned char *adv_addr = (unsigned char *)list_lstbox_find_devname_by_id(&list_bledev, res);
	if (adv_addr)
	{
		char msg_buf[255] = { 0 };

		msg_cli_snif_copybuf_add_command(CLI_SNIF_FOLLOW_DEVICE, adv_addr, DEVICE_ADDRESS_LENGTH);
		if (res == 1)
		{
			strcpy(msg_buf, MSG_PRINT_ALLDEVICE_FOLLOW);
		}
		else
		{
			sprintf(msg_buf, MSG_PRINT_DEVICE_FOLLOW, adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
		}
		gui_log_append(msg_buf);
	}
	return IUP_DEFAULT;
}

//--------------------------------------------
static int hbox_qstn_postmessage_cb(Ihandle *ih, const char* s, int i, double d, void* p)
{
	if (!i)
	{
		IupUnmap(hbox_qstn);
		IupDetach(hbox_qstn);
	}
	else
	{
		switch (key_mode)
		{
		case passkey_entering:
			IupSetStrf(lbl_qstn, "TITLE", MSG_QUESTION_PASSKEY_TIME, i);
			break;
		case oob_key_entering:
			IupSetStrf(lbl_qstn, "TITLE", MSG_QUESTION_OOB_KEY_TIME, i);
			break;
		case ltk_entering:
			IupSetStrf(lbl_qstn, "TITLE", MSG_QUESTION_LTK_TIME, i);
			break;
		}
		IupSetAttribute(lbl_qstn, "FGCOLOR", "255 0 0");
		IupAppend(vbox_bleconn, hbox_qstn);
		IupMap(hbox_qstn);
	}
	IupSetStrf(dlg, "SIZE", "%dx", dlg_width);
	IupRefresh(dlg);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_yes_action_cb(Ihandle* ih)
{
	thread_cli_cancel_countdown(1);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_no_action_cb(Ihandle* ih)
{
	thread_cli_cancel_countdown(0);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int hbox_key_postmessage_cb(Ihandle *ih, const char* s, int i, double d, void* p)
{
	if (!i)
	{
		IupUnmap(hbox_key);
		IupDetach(hbox_key);
	}
	else
	{
		switch (key_mode)
		{
		case passkey_entering:
			IupSetAttribute(lbl_key, "TITLE", MSG_INPUT_PASSKEY);
			IupSetAttribute(txt_key, "MASK", IUP_TEXT_MASK_6DIGITPASSKEY);
			break;
		case oob_key_entering:
			IupSetAttribute(lbl_key, "TITLE", MSG_INPUT_OOB_KEY);
			IupSetAttribute(txt_key, "MASK", IUP_TEXT_MASK_32SYMBOLHEXKEY);
			break;
		case ltk_entering:
			IupSetAttribute(lbl_key, "TITLE", MSG_INPUT_LTK);
			IupSetAttribute(txt_key, "MASK", IUP_TEXT_MASK_32SYMBOLHEXKEY);
			break;
		}
		IupAppend(vbox_bleconn, hbox_key);
		IupMap(hbox_key);
		IupSetFocus(txt_key);
	}
	IupSetStrf(dlg, "SIZE", "%dx", dlg_width);
	IupRefresh(dlg);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_key_action_cb(Ihandle* ih)
{
	size_t len;
	char *buf;
	char msg_buf[255] = { 0 };

	buf = IupGetAttribute(txt_key, "VALUE");
	len = strlen(buf);
	switch (key_mode)
	{
	case passkey_entering:
		if (len == 6)
		{
			msg_cli_ble_copybuf_add_command(CLI_BLE_PASSKEY, (const uint8_t*)buf, len + 1);
			msg_cli_snif_copybuf_add_command(CLI_SNIF_PASSKEY, (const uint8_t*)buf, len + 1);
			sprintf(msg_buf, MSG_INPUT_PASSKEY_RESULT, buf);
			gui_log_append(msg_buf);
		}
		else
		{
			msg_cli_ble_add_single_command(CLI_BLE_NO_PASSKEY);
			gui_log_append(MSG_INPUT_PASSKEY_INVALID);
		}
		break;
	case oob_key_entering:
		if (len == 32)
		{
			msg_cli_ble_copybuf_add_command(CLI_BLE_OOB_KEY, (const uint8_t*)buf, len + 1);
			msg_cli_snif_copybuf_add_command(CLI_SNIF_OOB_KEY, (const uint8_t*)buf, len + 1);
			sprintf(msg_buf, MSG_INPUT_OOB_KEY_RESULT, buf);
			gui_log_append(msg_buf);
		}
		else
		{
			msg_cli_ble_add_single_command(CLI_BLE_NO_OOB_KEY);
			gui_log_append(MSG_INPUT_OOB_KEY_INVALID);
		}
		break;
	case ltk_entering:
		if (len == 32)
		{
			msg_cli_ble_copybuf_add_command(CLI_BLE_LTK, (const uint8_t*)buf, len + 1);
			msg_cli_snif_copybuf_add_command(CLI_SNIF_LTK, (const uint8_t*)buf, len + 1);
			sprintf(msg_buf, MSG_INPUT_LTK_RESULT, buf);
			gui_log_append(msg_buf);
		}
		else
		{
			msg_cli_ble_add_single_command(CLI_BLE_NO_LTK);
			gui_log_append(MSG_INPUT_LTK_INVALID);
		}
		break;
	}
	thread_cli_cancel_keyentering();
	IupPostMessage(hbox_key, NULL, 0, 0.0, NULL);
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_clear_action_cb(Ihandle* ih)
{
	IupSetAttribute(txt_log, "VALUE", "");
	return IUP_DEFAULT;
}

//--------------------------------------------
static int btn_ok_action_cb(Ihandle* ih)
{
	return IUP_CLOSE;
}

//--------------------------------------------
static int btn_about_action_cb(Ihandle* ih)
{
	Ihandle *lbl_1 = IupLabel("bsniffhub gui");
	Ihandle *sep = IupFlatSeparator();
	IupSetAttribute(sep, "ORIENTATION", "HORIZONTAL");
	IupSetAttribute(sep, "EXPAND", "HORIZONTAL");
	IupSetAttribute(sep, "STYLE", "LINE");
	IupSetAttribute(sep, "BARSIZE", "16");
	Ihandle *lbl_2 = IupLabel("Copyright (c) 2020, 2021 Vladimir Alemasov");
	Ihandle *lbl_3 = IupLabel("TinyCrypt - Copyright (c) 2017, Intel Corporation");
	Ihandle *lbl_4 = IupLabel("IUP - Copyright (c) 1994-2020 Tecgraf/PUC-Rio");
	Ihandle *lbl_5 = IupLabel("Icon - Copyright (c) Hopstarter (Jojo Mendoza)");
	Ihandle *btn_ok = IupButton("OK", NULL);
	IupSetAttribute(btn_ok, "PADDING", "10x2");
	Ihandle *hbox = IupHbox(btn_ok, NULL);
	Ihandle *vbox = IupVbox(lbl_1, sep, lbl_2, lbl_3, lbl_4, lbl_5, hbox, NULL);
	IupSetAttribute(vbox, "MARGIN", "10x10");
	IupSetAttribute(vbox, "ALIGNMENT", "ACENTER");
	Ihandle* dlg_about = IupDialog(vbox);
	IupSetAttribute(dlg_about, "TITLE", "About");
	IupSetAttribute(dlg_about, "DIALOGFRAME", "Yes");
	IupSetAttributeHandle(dlg_about, "DEFAULTENTER", btn_ok);
	IupSetAttributeHandle(dlg_about, "PARENTDIALOG", IupGetDialog(dlg));
	IupSetCallback(btn_ok, "ACTION", (Icallback)btn_ok_action_cb);
	IupPopup(dlg_about, IUP_CENTERPARENT, IUP_CENTERPARENT);
	IupDestroy(dlg_about);
	return IUP_DEFAULT;
}

//--------------------------------------------
int dlg_show_cb(Ihandle *ih, int state)
{
	if (state == IUP_SHOW && !dlg_width)
	{
		dlg_width = IupGetInt(dlg, "SIZE");
	}
	return IUP_DEFAULT;
}

//--------------------------------------------
int gui_open(int argc, char **argv)
{
	if (IupOpen(&argc, &argv) != IUP_NOERROR)
	{
		return -1;
	}
	return 0;
}

//--------------------------------------------
int gui_show(void)
{
	// Input -> Title
	Ihandle *lbl_in_title = IupLabel("Input");
	Ihandle *sep_in_title = IupFlatSeparator();
	IupSetAttribute(sep_in_title, "ORIENTATION", "HORIZONTAL");
	IupSetAttribute(sep_in_title, "EXPAND", "HORIZONTAL");
	IupSetAttribute(sep_in_title, "STYLE", "LINE");
	IupSetAttribute(sep_in_title, "BARSIZE", "16");
	Ihandle *hbox_in_title = IupHbox(lbl_in_title, sep_in_title, NULL);

	// Input -> Select
	Ihandle *tgl_in_dev = IupToggle("Capture Device", NULL);
	tgl_in_pcap = IupToggle("PCAP file", NULL);
	hbox_in_sel = IupHbox(tgl_in_dev, tgl_in_pcap, NULL);
	IupSetAttribute(hbox_in_sel, "NCMARGIN", "10x");
	Ihandle *radio_in_sel = IupRadio(hbox_in_sel);

	// Input -> Path
	lbl_in_path = IupLabel("Specify path to PCAP file:");
	txt_in_path = IupText(NULL);
	IupSetAttribute(txt_in_path, "EXPAND", "YES"); //?
	Ihandle *btn_in_path = IupButton("Path...", NULL);
	IupSetAttribute(btn_in_path, "EXPAND", "VERTICAL"); //?
	Ihandle *hbox_in_path = IupHbox(txt_in_path, btn_in_path, NULL);
	IupSetAttribute(hbox_in_path, "ALIGNMENT", "ACENTER");
	vbox_in_path = IupVbox(lbl_in_path, hbox_in_path, NULL);
	IupSetAttribute(vbox_in_path, "NCMARGIN", "10x");

	// Input -> Capture device -> Interface
	Ihandle *lbl_iface = IupLabel("Interface:");
	IupSetAttribute(lbl_iface, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_iface = IupVbox(lbl_iface, NULL);
	lst_iface = IupList(NULL);
	IupSetAttribute(lst_iface, "DROPDOWN", "YES");
	IupSetAttribute(lst_iface, "SIZE", "80");
	Ihandle *vbox_lst_iface = IupVbox(lst_iface, NULL);
	Ihandle *hbox_iface = IupHbox(vbox_lbl_iface, vbox_lst_iface, NULL);
	IupSetAttribute(hbox_iface, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_iface, "NCMARGIN", "5x");

	// Input -> Capture device -> Sniffer
	Ihandle *lbl_sniff = IupLabel("Sniffer:");
	IupSetAttribute(lbl_sniff, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_sniff = IupVbox(lbl_sniff, NULL);
	lst_sniff = IupList(NULL);
	IupSetAttribute(lst_sniff, "DROPDOWN", "YES");
	IupSetAttribute(lst_sniff, "SIZE", "140");
	Ihandle *vbox_lst_sniff = IupVbox(lst_sniff, NULL);
	Ihandle *hbox_sniff = IupHbox(vbox_lbl_sniff, vbox_lst_sniff, NULL);
	IupSetAttribute(hbox_sniff, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_sniff, "NCMARGIN", "5x");

	// Input -> Capture device -> Baudrate
	Ihandle *lbl_baudr = IupLabel("Baudrate:");
	IupSetAttribute(lbl_baudr, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_baudr = IupVbox(lbl_baudr, NULL);
	lst_baudr = IupList(NULL);
	IupSetAttribute(lst_baudr, "DROPDOWN", "YES");
	IupSetAttribute(lst_baudr, "SIZE", "50");
	Ihandle *vbox_lst_baudr = IupVbox(lst_baudr, NULL);
	Ihandle *hbox_baudr = IupHbox(vbox_lbl_baudr, vbox_lst_baudr, NULL);
	IupSetAttribute(hbox_baudr, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_baudr, "NCMARGIN", "5x");

	// Input -> Capture device
	Ihandle *hbox_capdev = IupHbox(hbox_iface, hbox_sniff, hbox_baudr, NULL);
	IupSetAttribute(hbox_capdev, "NCMARGIN", "3x5");
	Ihandle *frm_capdev = IupFrame(hbox_capdev);
	IupSetAttribute(frm_capdev, "TITLE", "Capture Device");
	hbox_in_capdev = IupHbox(frm_capdev, NULL);
	IupSetAttribute(hbox_in_capdev, "NCMARGIN", "10x");

	// Input -> BLE connection -> Device
	Ihandle *lbl_bledev = IupLabel("BLE Device:");
	IupSetAttribute(lbl_bledev, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_bledev = IupVbox(lbl_bledev, NULL);
	lst_bledev = IupList(NULL);
	IupSetAttribute(lst_bledev, "DROPDOWN", "YES");
	IupSetAttribute(lst_bledev, "EXPAND", "HORIZONTAL"); //?
	btn_bledev = IupButton("Send", NULL);
	IupSetAttribute(btn_bledev, "EXPAND", "VERTICAL"); //?
	hbox_bledev = IupHbox(vbox_lbl_bledev, lst_bledev, btn_bledev, NULL);
	IupSetAttribute(hbox_bledev, "ACTIVE", "NO");
	IupSetAttribute(hbox_bledev, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_bledev, "NCMARGIN", "5x");

	// Input -> BLE connection -> Question
	lbl_qstn = IupLabel(NULL);
	IupSetAttribute(lbl_qstn, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_qstn = IupVbox(lbl_qstn, NULL);
	Ihandle *btn_yes = IupButton("Yes", NULL);
	IupSetAttribute(btn_yes, "EXPAND", "VERTICAL"); //?
	Ihandle *btn_no = IupButton("No", NULL);
	IupSetAttribute(btn_no, "EXPAND", "VERTICAL"); //?
	hbox_qstn = IupHbox(vbox_lbl_qstn, btn_yes, btn_no, NULL);
	IupSetAttribute(hbox_qstn, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_qstn, "NCMARGIN", "5x");

	// Input -> BLE connection -> key
	lbl_key = IupLabel(NULL);
	IupSetAttribute(lbl_key, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_key = IupVbox(lbl_key, NULL);
	txt_key = IupText(NULL);
	IupSetAttribute(txt_key, "EXPAND", "YES"); //?
	Ihandle *btn_key = IupButton("Send", NULL);
	IupSetAttribute(btn_key, "EXPAND", "VERTICAL"); //?
	hbox_key = IupHbox(vbox_lbl_key, txt_key, btn_key, NULL);
	IupSetAttribute(hbox_key, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_key, "NCMARGIN", "5x");

	// Input -> BLE connection
	vbox_bleconn = IupVbox(hbox_bledev, NULL);
	IupSetAttribute(vbox_bleconn, "NCMARGIN", "3x5");
	Ihandle *frm_bleconn = IupFrame(vbox_bleconn);
	IupSetAttribute(frm_bleconn, "TITLE", "BLE Connection");
	hbox_in_bleconn = IupHbox(frm_bleconn, NULL);
	IupSetAttribute(hbox_in_bleconn, "NCMARGIN", "10x");

	// Input
	vbox_in = IupVbox(hbox_in_title, radio_in_sel, vbox_in_path, hbox_in_capdev, hbox_in_bleconn, NULL);
	Ihandle *hbox_in = IupHbox(vbox_in, NULL);

	// Output -> Title
	Ihandle *lbl_out_title = IupLabel("Output");
	Ihandle *sep_out_title = IupFlatSeparator();
	IupSetAttribute(sep_out_title, "ORIENTATION", "HORIZONTAL");
	IupSetAttribute(sep_out_title, "EXPAND", "HORIZONTAL");
	IupSetAttribute(sep_out_title, "STYLE", "LINE");
	IupSetAttribute(sep_out_title, "BARSIZE", "16");
	Ihandle *hbox_out_title = IupHbox(lbl_out_title, sep_out_title, NULL);

	// Output -> Select
	Ihandle *tgl_out_wrsh = IupToggle("Wireshark", NULL);
	tgl_out_pcap = IupToggle("PCAP file", NULL);
	Ihandle *hbox_out_sel = IupHbox(tgl_out_wrsh, tgl_out_pcap, NULL);
	IupSetAttribute(hbox_out_sel, "NCMARGIN", "10x");
	Ihandle *radio_out_sel = IupRadio(hbox_out_sel);

	// Output -> Path
	lbl_out_path = IupLabel("Specify path to PCAP file:");
	txt_out_path = IupText(NULL);
	IupSetAttribute(txt_out_path, "EXPAND", "YES"); //?
	Ihandle *btn_out_path = IupButton("Path...", NULL);
	IupSetAttribute(btn_out_path, "EXPAND", "VERTICAL"); //?
	Ihandle *hbox_out_path = IupHbox(txt_out_path, btn_out_path, NULL);
	IupSetAttribute(hbox_out_path, "ALIGNMENT", "ACENTER");
	vbox_out_path = IupVbox(lbl_out_path, hbox_out_path, NULL);
	IupSetAttribute(vbox_out_path, "NCMARGIN", "10x");

	// Output -> Link type
	Ihandle *lbl_link = IupLabel("Link type:");
	IupSetAttribute(lbl_link, "ALIGNMENT", "ARIGHT:");
	Ihandle *vbox_lbl_link = IupVbox(lbl_link, NULL);
	lst_link = IupList(NULL);
	IupSetAttribute(lst_link, "DROPDOWN", "YES");
//	IupSetAttribute(lst_link, "SIZE", "200");
	Ihandle *vbox_lst_link = IupVbox(lst_link, NULL);
	tgl_nodec = IupToggle("Don't try to decode", NULL);
	IupSetAttribute(tgl_nodec, "EXPAND", "VERTICAL"); //?
	Ihandle *hbox_link = IupHbox(vbox_lbl_link, vbox_lst_link, IupFill(), tgl_nodec, NULL);
	IupSetAttribute(hbox_link, "ALIGNMENT", "ACENTER");
	IupSetAttribute(hbox_link, "NCMARGIN", "10x");

	// Output
	vbox_out = IupVbox(hbox_out_title, radio_out_sel, hbox_link, vbox_out_path, NULL);
	Ihandle *hbox_out = IupHbox(vbox_out, NULL);

	// Log -> Title
	Ihandle *lbl_log_title = IupLabel("Log");
	Ihandle *sep_log_title = IupFlatSeparator();
	IupSetAttribute(sep_log_title, "ORIENTATION", "HORIZONTAL");
	IupSetAttribute(sep_log_title, "EXPAND", "HORIZONTAL");
	IupSetAttribute(sep_log_title, "STYLE", "LINE");
	IupSetAttribute(sep_log_title, "BARSIZE", "16");
	Ihandle *hbox_log_title = IupHbox(lbl_log_title, sep_log_title, NULL);

	// Log -> Text
	txt_log = IupText(NULL);
	IupSetAttribute(txt_log, "MULTILINE", "YES");
	IupSetAttribute(txt_log, "READONLY", "YES");
	IupSetAttribute(txt_log, "APPENDNEWLINE", "NO");
	IupSetAttribute(txt_log, "SIZE", "x100");
	IupSetAttribute(txt_log, "EXPAND", "HORIZONTAL");
	Ihandle *hbox_txt_log = IupHbox(txt_log, NULL);
	IupSetAttribute(hbox_txt_log, "NCMARGIN", "10x");

	// Log
	Ihandle *vbox_log = IupVbox(hbox_log_title, hbox_txt_log, NULL);
	Ihandle *hbox_log = IupHbox(vbox_log, NULL);

	// Buttons
	Ihandle *btn_clear = IupButton("Clear Log", NULL);
	IupSetAttribute(btn_clear, "SIZE", "40");
	Ihandle *btn_about = IupButton("About", NULL);
	IupSetAttribute(btn_about, "SIZE", "40");
	btn_start = IupButton("Start", NULL);
	IupSetAttribute(btn_start, "SIZE", "50");
	btn_stop = IupButton("Stop", NULL);
	IupSetAttribute(btn_stop, "SIZE", "50");
	IupSetAttribute(btn_stop, "ACTIVE", "NO");
	Ihandle *btn_exit = IupButton("Exit", NULL);
	IupSetAttribute(btn_exit, "SIZE", "50");
	Ihandle *hbox_btns = IupHbox(btn_clear, btn_about, IupFill(), btn_start, btn_stop, btn_exit, NULL);
	IupSetAttribute(hbox_btns, "NCMARGIN", "10x2");

	// Dialog
	Ihandle *vbox_dlg = IupVbox(hbox_in, hbox_out, hbox_log, hbox_in_capdev, hbox_btns, NULL);
	IupSetAttribute(vbox_dlg, "NMARGIN", "10x10");
	dlg = IupDialog(vbox_dlg);
	IupSetAttribute(dlg, "RESIZE", "NO");
	IupSetAttribute(dlg, "TITLE", "bsniffhub gui");
	IupSetAttribute(dlg, "GAP", "10");

	// Icon
#ifdef _WIN32
	IupSetAttribute(dlg, "ICON", "IDI_BSNIFFHUBGUI");
#else
	Ihandle* icon = IupImageRGBA(64, 64, icondata);
	IupSetAttributeHandle(dlg, "ICON", icon);
#endif

	// lists
	list_lstbox_init(&list_iface);
	list_lstbox_init(&list_bledev);
	list_sniff_load();
	list_baudr_load();
	list_link_load();
	list_bledev_load();
	lst_load(lst_link, &list_link, 2);
	lst_load(lst_bledev, &list_bledev, 1);

	// additional dialog elements initialization
	in_path_var(0);
	out_path_var(0);
	lst_sniff_action_cb(NULL, NULL, 0, 0);

	// callbacks
	IupSetCallback(tgl_in_pcap, "ACTION", (Icallback)tgl_in_pcap_action_cb);
	IupSetCallback(tgl_out_pcap, "ACTION", (Icallback)tgl_out_pcap_action_cb);
	IupSetCallback(txt_log, "POSTMESSAGE_CB", (Icallback)txt_log_postmessage_cb);
	IupSetCallback(lst_sniff, "ACTION", (Icallback)lst_sniff_action_cb);
	IupSetCallback(lst_bledev, "POSTMESSAGE_CB", (Icallback)lst_bledev_postmessage_cb);
	IupSetCallback(btn_bledev, "ACTION", (Icallback)btn_bledev_action_cb);
	IupSetCallback(btn_in_path, "ACTION", (Icallback)btn_in_path_action_cb);
	IupSetCallback(btn_out_path, "ACTION", (Icallback)btn_out_path_action_cb);
	IupSetCallback(btn_start, "ACTION", (Icallback)btn_start_action_cb);
	IupSetCallback(btn_stop, "ACTION", (Icallback)btn_stop_action_cb);
	IupSetCallback(btn_stop, "POSTMESSAGE_CB", (Icallback)btn_stop_postmessage_cb);
	IupSetCallback(btn_exit, "ACTION", (Icallback)btn_exit_action_cb);
	IupSetCallback(hbox_qstn, "POSTMESSAGE_CB", (Icallback)hbox_qstn_postmessage_cb);
	IupSetCallback(btn_yes, "ACTION", (Icallback)btn_yes_action_cb);
	IupSetCallback(btn_no, "ACTION", (Icallback)btn_no_action_cb);
	IupSetCallback(hbox_key, "POSTMESSAGE_CB", (Icallback)hbox_key_postmessage_cb);
	IupSetCallback(btn_key, "ACTION", (Icallback)btn_key_action_cb);
	IupSetCallback(btn_clear, "ACTION", (Icallback)btn_clear_action_cb);
	IupSetCallback(btn_about, "ACTION", (Icallback)btn_about_action_cb);
	IupSetCallback(dlg, "SHOW_CB", (Icallback)dlg_show_cb);

	if (IupShowXY(dlg, IUP_CENTER, IUP_CENTER) != IUP_NOERROR)
	{
		return -1;
	}
	return 0;
}

//--------------------------------------------
void gui_loop(void)
{
	IupMainLoop();
}

//--------------------------------------------
void gui_close(void)
{
	IupClose();
	list_lstbox_remove_all(&list_iface);
	list_lstbox_remove_all(&list_sniff);
	list_lstbox_remove_all(&list_baudr);
	list_lstbox_remove_all(&list_link);
	list_lstbox_remove_all(&list_bledev);
}

//--------------------------------------------
void gui_log_append(const char *buf)
{
	IupPostMessage(txt_log, buf, 0, 0.0, NULL);
}

//--------------------------------------------
void gui_bledev_append(const char *buf)
{
	IupPostMessage(lst_bledev, buf, 0, 0.0, NULL);
}

//--------------------------------------------
void gui_stop(void)
{
	IupPostMessage(btn_stop, NULL, 0, 0.0, NULL);
}

//--------------------------------------------
void gui_ask_key(key_entering_mode_t mode, int seconds_left)
{
	key_mode = mode;
	IupPostMessage(hbox_qstn, NULL, seconds_left, 0.0, NULL);
}

//--------------------------------------------
void gui_enter_key(key_entering_mode_t mode, int active)
{
	key_mode = mode;
	IupPostMessage(hbox_key, NULL, active, 0.0, NULL);
}
