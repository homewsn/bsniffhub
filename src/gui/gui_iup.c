/*
* Copyright (c) 2020 - 2025 Vladimir Alemasov
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
#include <stdbool.h>    /* bool */
#include <string.h>     /* memcpy, strncpy */
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
#include "base64.h"
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
//--------------------------------------------
static Ihandle *dlg;
static Ihandle *vbox_in, *vbox_in_path, *lbl_in_path;
static Ihandle *hbox_in_sel, *hbox_in_bleconn, *hbox_bledev, *hbox_in_capdev;
static Ihandle *vbox_out, *vbox_out_path, *lbl_out_path;
static Ihandle *tgl_in_pcap, *tgl_out_pcap;
static Ihandle *lst_iface, *lst_sniff, *lst_baudr, *lst_bledev, *lst_link;
static Ihandle *txt_in_path, *txt_out_path, *txt_log;
static Ihandle *btn_start, *btn_stop, *btn_bledev, *btn_options;
static Ihandle *lbl_qstn, *lbl_key, *txt_key;
static Ihandle *vbox_bleconn, *hbox_qstn, *hbox_key;
static Ihandle *tgl_nodec;

//--------------------------------------------
#define STRINGIFY_HELPER(x)      #x
#define STRINGIFY_EXPANDED(x)    STRINGIFY_HELPER(x)
//--------------------------------------------
// Blesniff
#define B_OPTION_C_MAX_LEN       8   // 37,38,39
#define B_OPTION_C_MAX_LEN_STR   STRINGIFY_EXPANDED(B_OPTION_C_MAX_LEN)
#define B_OPTION_C_TEXT_MASK     "[3][789][,][3][789][,][3][789]"
#define B_OPTION_R_MAX_LEN       4   // -127
#define B_OPTION_R_MAX_LEN_STR   STRINGIFY_EXPANDED(B_OPTION_R_MAX_LEN)
#define B_OPTION_R_TEXT_MASK     "[+/-]?/d/d/d"
#define B_OPTION_M_MAX_LEN       18  // 12:34:56:78:9A:BCr
#define B_OPTION_M_MAX_LEN_STR   STRINGIFY_EXPANDED(B_OPTION_M_MAX_LEN)
#define B_OPTION_M_TEXT_MASK     "[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F][r]"
#define B_OPTION_F_MAX_LEN       15  // conn,pa,cis,bis
#define B_OPTION_F_MAX_LEN_STR   STRINGIFY_EXPANDED(B_OPTION_F_MAX_LEN)
#define B_OPTION_F_TEXT_MASK     "(conn|pa|cis|bis)[,](conn|pa|cis|bis)[,](conn|pa|cis|bis)[,](conn|pa|cis|bis)"
#define B_OPTION_L_MAX_LEN       32  // 00112233445566778899aabbccddeeff
#define B_OPTION_L_MAX_LEN_STR   STRINGIFY_EXPANDED(B_OPTION_L_MAX_LEN)
#define B_OPTION_L_TEXT_MASK     "[0-9a-fA-F]+"
#define B_OPTION_DIALOG_MINSIZE  "400x"
//--------------------------------------------
// Sniffle
#define S_OPTION_C_MAX_LEN       2   // 37
#define S_OPTION_C_MAX_LEN_STR   STRINGIFY_EXPANDED(S_OPTION_C_MAX_LEN)
#define S_OPTION_C_TEXT_MASK     "[3][789]"
#define S_OPTION_R_MAX_LEN       B_OPTION_R_MAX_LEN
#define S_OPTION_R_MAX_LEN_STR   B_OPTION_R_MAX_LEN_STR
#define S_OPTION_R_TEXT_MASK     B_OPTION_R_TEXT_MASK
#define S_OPTION_M_MAX_LEN       B_OPTION_M_MAX_LEN
#define S_OPTION_M_MAX_LEN_STR   B_OPTION_M_MAX_LEN_STR
#define S_OPTION_M_TEXT_MASK     B_OPTION_M_TEXT_MASK
#define S_OPTION_DIALOG_MINSIZE  "400x"
//--------------------------------------------
// nRF sniffer
#define N_OPTION_C_MAX_LEN       B_OPTION_C_MAX_LEN
#define N_OPTION_C_MAX_LEN_STR   B_OPTION_C_MAX_LEN_STR
#define N_OPTION_C_TEXT_MASK     B_OPTION_C_TEXT_MASK
#define N_OPTION_R_MAX_LEN       B_OPTION_R_MAX_LEN
#define N_OPTION_R_MAX_LEN_STR   B_OPTION_R_MAX_LEN_STR
#define N_OPTION_R_TEXT_MASK     B_OPTION_R_TEXT_MASK
#define N_OPTION_M_MAX_LEN       B_OPTION_M_MAX_LEN
#define N_OPTION_M_MAX_LEN_STR   B_OPTION_M_MAX_LEN_STR
#define N_OPTION_M_TEXT_MASK     B_OPTION_M_TEXT_MASK
#define N_OPTION_L_MAX_LEN       B_OPTION_L_MAX_LEN
#define N_OPTION_L_MAX_LEN_STR   B_OPTION_L_MAX_LEN_STR
#define N_OPTION_L_TEXT_MASK     B_OPTION_L_TEXT_MASK
#define N_OPTION_DIALOG_MINSIZE  "400x"

//--------------------------------------------
// Additional options dialog's variables
static Ihandle *lbl_option_c, *lbl_option_R, *lbl_option_m, *lbl_option_f, *lbl_option_L;
static Ihandle *txt_option_c, *txt_option_R, *txt_option_m, *txt_option_f, *txt_option_L;
static Ihandle *tgl_option_c_en, *tgl_option_R_en, *tgl_option_m_en, *tgl_option_f_en, *tgl_option_L_en, *tgl_option_e_en;

//--------------------------------------------
// Blesniff
typedef struct
{
	bool option_c;
	char option_c_str[B_OPTION_C_MAX_LEN + 1];
	uint8_t hop_map[3];
	uint8_t hop_map_size;
	bool option_R;
	char option_R_str[B_OPTION_R_MAX_LEN + 1];
	int rssi;
	bool option_m;
	char option_m_str[B_OPTION_M_MAX_LEN + 1];
	uint8_t mac[6];
	uint8_t mac_addr_type;
	bool option_f;
	char option_f_str[B_OPTION_F_MAX_LEN + 1];
	uint8_t filter;
	bool option_L;
	char option_L_str[B_OPTION_L_MAX_LEN + 1];
} B_options_t;
static B_options_t B_options;
static B_options_t B_options_dlg;
//--------------------------------------------
// Sniffle
typedef struct
{
	bool option_c;
	char option_c_str[S_OPTION_C_MAX_LEN + 1];
	uint8_t hop_map[3];
	uint8_t hop_map_size;
	bool option_R;
	char option_R_str[S_OPTION_R_MAX_LEN + 1];
	int rssi;
	bool option_m;
	char option_m_str[S_OPTION_M_MAX_LEN + 1];
	uint8_t mac[6];
	uint8_t mac_addr_type;
	bool option_e;
} S_options_t;
static S_options_t S_options;
static S_options_t S_options_dlg;
//--------------------------------------------
// nRF sniffer
typedef struct
{
	bool option_c;
	char option_c_str[N_OPTION_C_MAX_LEN + 1];
	uint8_t hop_map[3];
	uint8_t hop_map_size;
	bool option_R;
	char option_R_str[N_OPTION_R_MAX_LEN + 1];
	int rssi;
	bool option_m;
	char option_m_str[N_OPTION_M_MAX_LEN + 1];
	uint8_t mac[6];
	uint8_t mac_addr_type;
	bool option_L;
	char option_L_str[N_OPTION_L_MAX_LEN + 1];
} N_options_t;
static N_options_t N_options;
static N_options_t N_options_dlg;


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
	list_lstbox_add(&list_sniff, "B", "Blesniff");
	list_lstbox_add(&list_sniff, "S", "Sniffle");
	list_lstbox_add(&list_sniff, "N3", "nRF Sniffer v3");
	list_lstbox_add(&list_sniff, "N4", "nRF Sniffer v4");
	list_lstbox_add(&list_sniff, "T", "SmartRF Packet Sniffer 2");
	list_lstbox_add(&list_sniff, "WB", "STM32WB BLE Sniffer");
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
	if (!strcmp(name, "B") || !strcmp(name, "S") || !strcmp(name, "N4"))
	{
		// Blesniffer
		IupSetAttribute(btn_options, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(btn_options, "ACTIVE", "NO");
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
	static char dec_buf[255];
	long res;

	res = base64_decode(dec_buf, s, (unsigned long)strlen(s));
	assert(res <= sizeof(dec_buf));
	memcpy(adv_addr, dec_buf, DEVICE_ADDRESS_LENGTH);
	if (dec_buf[DEVICE_ADDRESS_LENGTH + 1])
	{
		sprintf(str_buf, LST_ITEM_DEVICE_RANDOM, dec_buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
	}
	else
	{
		sprintf(str_buf, LST_ITEM_DEVICE_PUBLIC, dec_buf[DEVICE_ADDRESS_LENGTH], adv_addr[0], adv_addr[1], adv_addr[2], adv_addr[3], adv_addr[4], adv_addr[5]);
	}
	IupSetAttribute(ih, "APPENDITEM", str_buf);
	list_lstbox_add_devname_length(&list_bledev, (const char *)adv_addr, DEVICE_ADDRESS_LENGTH, str_buf);
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
	task_settings_t ts = { 0 };
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
	ts.opt_L = 0;

	if (ts.opt_s && !strcmp(ts.opt_s_arg, "B"))
	{
		// Blesniff options
		if (B_options.option_c)
		{
			ts.opt_c = 1;
			ts.opt_c_arg = B_options.option_c_str;
		}
		if (B_options.option_R)
		{
			ts.opt_R = 1;
			ts.opt_R_arg = B_options.option_R_str;
		}
		if (B_options.option_m)
		{
			ts.opt_m = 1;
			ts.opt_m_arg = B_options.option_m_str;
		}
		if (B_options.option_f)
		{
			ts.opt_f = 1;
			ts.opt_f_arg = B_options.option_f_str;
		}
		if (B_options.option_L)
		{
			ts.opt_L = 1;
			ts.opt_L_arg = B_options.option_L_str;
		}
	}
	if (ts.opt_s && !strcmp(ts.opt_s_arg, "S"))
	{
		// Sniffle options
		if (S_options.option_c)
		{
			ts.opt_c = 1;
			ts.opt_c_arg = S_options.option_c_str;
		}
		if (S_options.option_R)
		{
			ts.opt_R = 1;
			ts.opt_R_arg = S_options.option_R_str;
		}
		if (S_options.option_m)
		{
			ts.opt_m = 1;
			ts.opt_m_arg = S_options.option_m_str;
		}
		if (S_options.option_e)
		{
			ts.opt_e = 1;
		}
	}
	if (ts.opt_s && !strcmp(ts.opt_s_arg, "N4"))
	{
		// nRF sniffer options
		if (N_options.option_c)
		{
			ts.opt_c = 1;
			ts.opt_c_arg = N_options.option_c_str;
		}
		if (N_options.option_R)
		{
			ts.opt_R = 1;
			ts.opt_R_arg = N_options.option_R_str;
		}
		if (N_options.option_m)
		{
			ts.opt_m = 1;
			ts.opt_m_arg = N_options.option_m_str;
		}
		if (N_options.option_L)
		{
			ts.opt_L = 1;
			ts.opt_L_arg = N_options.option_L_str;
		}
	}

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
			IupSetAttribute(btn_options, "ACTIVE", "NO");
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
		char *name = list_lstbox_find_devname_by_id(&list_sniff, IupGetInt(lst_sniff, "VALUE"));
		if (!strcmp(name, "B") || !strcmp(name, "S") || !strcmp(name, "N4"))
		{
			// Blesniffer
			IupSetAttribute(btn_options, "ACTIVE", "YES");
		}
		else
		{
			IupSetAttribute(btn_options, "ACTIVE", "NO");
		}
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
	Ihandle *lbl_2 = IupLabel("Copyright (c) 2020-2025 Vladimir Alemasov");
	Ihandle *lbl_3 = IupLabel("TinyCrypt - Copyright (c) 2017, Intel Corporation");
	Ihandle *lbl_4 = IupLabel("IUP - Copyright (c) 1994-2025 Tecgraf/PUC-Rio");
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
// Blesniff options

//--------------------------------------------
static int dlg_B_options_btn_ok_action_cb(Ihandle* ih)
{
	char *value_str;
	if (B_options_dlg.option_c)
	{
		value_str = IupGetAttribute(txt_option_c, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -c option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_channels(value_str, B_options_dlg.hop_map, &B_options_dlg.hop_map_size) < 0)
		{
			IupMessage("Error: -c option", "Wrong channel number(s)!");
			return IUP_DEFAULT;
		}
		strncpy(B_options_dlg.option_c_str, value_str, B_OPTION_C_MAX_LEN);
	}
	if (B_options_dlg.option_R)
	{
		value_str = IupGetAttribute(txt_option_R, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -R option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_rssi(value_str, &B_options_dlg.rssi))
		{
			IupMessage("Error: -R option", "Wrong RSSI value!");
			return IUP_DEFAULT;
		}
		strncpy(B_options_dlg.option_R_str, value_str, B_OPTION_R_MAX_LEN);
	}
	if (B_options_dlg.option_m)
	{
		value_str = IupGetAttribute(txt_option_m, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -m option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_mac_address(value_str, B_options_dlg.mac, &B_options_dlg.mac_addr_type) < 0)
		{
			IupMessage("Error: -m option", "Wrong MAC address value!");
			return IUP_DEFAULT;
		}
		strncpy(B_options_dlg.option_m_str, value_str, B_OPTION_M_MAX_LEN);
	}
	if (B_options_dlg.option_f)
	{
		value_str = IupGetAttribute(txt_option_f, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -f option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_filter(value_str, &B_options_dlg.filter) < 0)
		{
			IupMessage("Error: -f option", "Wrong filter!");
			return IUP_DEFAULT;
		}
		strncpy(B_options_dlg.option_f_str, value_str, B_OPTION_F_MAX_LEN);
	}
	if (B_options_dlg.option_L)
	{
		value_str = IupGetAttribute(txt_option_L, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -L option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_check_ltk(value_str))
		{
			IupMessage("Error: -L option", "Wrong LTK!");
			return IUP_DEFAULT;
		}
		strncpy(B_options_dlg.option_L_str, value_str, B_OPTION_L_MAX_LEN);
	}
	B_options = B_options_dlg;
	return IUP_CLOSE;
}

//--------------------------------------------
static void dlg_B_options_set_en_value(void)
{
	IupSetInt(tgl_option_c_en, "VALUE", B_options_dlg.option_c);
	IupSetInt(tgl_option_R_en, "VALUE", B_options_dlg.option_R);
	IupSetInt(tgl_option_m_en, "VALUE", B_options_dlg.option_m);
	IupSetInt(tgl_option_f_en, "VALUE", B_options_dlg.option_f);
	IupSetInt(tgl_option_L_en, "VALUE", B_options_dlg.option_L);
}

//--------------------------------------------
static void dlg_B_options_set_active(void)
{
	if (B_options_dlg.option_c)
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "YES");
		IupSetAttribute(txt_option_c, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "NO");
		IupSetAttribute(txt_option_c, "ACTIVE", "NO");
	}
	if (B_options_dlg.option_R)
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "YES");
		IupSetAttribute(txt_option_R, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "NO");
		IupSetAttribute(txt_option_R, "ACTIVE", "NO");
	}
	if (B_options_dlg.option_m)
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "YES");
		IupSetAttribute(txt_option_m, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "NO");
		IupSetAttribute(txt_option_m, "ACTIVE", "NO");
	}
	if (B_options_dlg.option_f)
	{
		IupSetAttribute(lbl_option_f, "ACTIVE", "YES");
		IupSetAttribute(txt_option_f, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_f, "ACTIVE", "NO");
		IupSetAttribute(txt_option_f, "ACTIVE", "NO");
	}
	if (B_options_dlg.option_L)
	{
		IupSetAttribute(lbl_option_L, "ACTIVE", "YES");
		IupSetAttribute(txt_option_L, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_L, "ACTIVE", "NO");
		IupSetAttribute(txt_option_L, "ACTIVE", "NO");
	}
}

//--------------------------------------------
static int tgl_B_option_c_en_action_cb(Ihandle *ih, int v)
{
	B_options_dlg.option_c = v;
	dlg_B_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_B_option_R_en_action_cb(Ihandle *ih, int v)
{
	B_options_dlg.option_R = v;
	dlg_B_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_B_option_m_en_action_cb(Ihandle *ih, int v)
{
	B_options_dlg.option_m = v;
	dlg_B_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_B_option_f_en_action_cb(Ihandle *ih, int v)
{
	B_options_dlg.option_f = v;
	dlg_B_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_B_option_L_en_action_cb(Ihandle *ih, int v)
{
	B_options_dlg.option_L = v;
	dlg_B_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
// Sniffle options

//--------------------------------------------
static int dlg_S_options_btn_ok_action_cb(Ihandle* ih)
{
	char *value_str;
	if (S_options_dlg.option_c)
	{
		value_str = IupGetAttribute(txt_option_c, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -c option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_channels(value_str, S_options_dlg.hop_map, &S_options_dlg.hop_map_size) < 0)
		{
			IupMessage("Error: -c option", "Wrong channel number(s)!");
			return IUP_DEFAULT;
		}
		strncpy(S_options_dlg.option_c_str, value_str, S_OPTION_C_MAX_LEN);
	}
	if (S_options_dlg.option_R)
	{
		value_str = IupGetAttribute(txt_option_R, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -R option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_rssi(value_str, &S_options_dlg.rssi))
		{
			IupMessage("Error: -R option", "Wrong RSSI value!");
			return IUP_DEFAULT;
		}
		strncpy(S_options_dlg.option_R_str, value_str, S_OPTION_R_MAX_LEN);
	}
	if (S_options_dlg.option_m)
	{
		value_str = IupGetAttribute(txt_option_m, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -m option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_mac_address(value_str, S_options_dlg.mac, &S_options_dlg.mac_addr_type) < 0)
		{
			IupMessage("Error: -m option", "Wrong MAC address value!");
			return IUP_DEFAULT;
		}
		strncpy(S_options_dlg.option_m_str, value_str, S_OPTION_M_MAX_LEN);
	}
	S_options = S_options_dlg;
	return IUP_CLOSE;
}

//--------------------------------------------
static void dlg_S_options_set_en_value(void)
{
	IupSetInt(tgl_option_c_en, "VALUE", S_options_dlg.option_c);
	IupSetInt(tgl_option_R_en, "VALUE", S_options_dlg.option_R);
	IupSetInt(tgl_option_m_en, "VALUE", S_options_dlg.option_m);
	IupSetInt(tgl_option_e_en, "VALUE", S_options_dlg.option_e);
}

//--------------------------------------------
static void dlg_S_options_set_active(void)
{
	if (S_options_dlg.option_c)
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "YES");
		IupSetAttribute(txt_option_c, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "NO");
		IupSetAttribute(txt_option_c, "ACTIVE", "NO");
	}
	if (S_options_dlg.option_R)
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "YES");
		IupSetAttribute(txt_option_R, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "NO");
		IupSetAttribute(txt_option_R, "ACTIVE", "NO");
	}
	if (S_options_dlg.option_m)
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "YES");
		IupSetAttribute(txt_option_m, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "NO");
		IupSetAttribute(txt_option_m, "ACTIVE", "NO");
	}
}

//--------------------------------------------
static int tgl_S_option_c_en_action_cb(Ihandle *ih, int v)
{
	S_options_dlg.option_c = v;
	dlg_S_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_S_option_R_en_action_cb(Ihandle *ih, int v)
{
	S_options_dlg.option_R = v;
	dlg_S_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_S_option_m_en_action_cb(Ihandle *ih, int v)
{
	S_options_dlg.option_m = v;
	dlg_S_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_S_option_e_en_action_cb(Ihandle *ih, int v)
{
	S_options_dlg.option_e = v;
	return IUP_DEFAULT;
}

//--------------------------------------------
// nRF sniffer options

//--------------------------------------------
static int dlg_N_options_btn_ok_action_cb(Ihandle* ih)
{
	char *value_str;
	if (N_options_dlg.option_c)
	{
		value_str = IupGetAttribute(txt_option_c, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -c option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_channels(value_str, N_options_dlg.hop_map, &N_options_dlg.hop_map_size) < 0)
		{
			IupMessage("Error: -c option", "Wrong channel number(s)!");
			return IUP_DEFAULT;
		}
		strncpy(N_options_dlg.option_c_str, value_str, B_OPTION_C_MAX_LEN);
	}
	if (N_options_dlg.option_R)
	{
		value_str = IupGetAttribute(txt_option_R, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -R option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_rssi(value_str, &N_options_dlg.rssi))
		{
			IupMessage("Error: -R option", "Wrong RSSI value!");
			return IUP_DEFAULT;
		}
		strncpy(N_options_dlg.option_R_str, value_str, B_OPTION_R_MAX_LEN);
	}
	if (N_options_dlg.option_m)
	{
		value_str = IupGetAttribute(txt_option_m, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -m option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_parse_mac_address(value_str, N_options_dlg.mac, &N_options_dlg.mac_addr_type) < 0)
		{
			IupMessage("Error: -m option", "Wrong MAC address value!");
			return IUP_DEFAULT;
		}
		strncpy(N_options_dlg.option_m_str, value_str, B_OPTION_M_MAX_LEN);
	}
	if (N_options_dlg.option_L)
	{
		value_str = IupGetAttribute(txt_option_L, "VALUE");
		if (!strlen(value_str))
		{
			IupMessage("Error: -L option", "Argument required!");
			return IUP_DEFAULT;
		}
		if (task_check_ltk(value_str))
		{
			IupMessage("Error: -L option", "Wrong LTK!");
			return IUP_DEFAULT;
		}
		strncpy(N_options_dlg.option_L_str, value_str, B_OPTION_L_MAX_LEN);
	}
	N_options = N_options_dlg;
	return IUP_CLOSE;
}

//--------------------------------------------
static void dlg_N_options_set_en_value(void)
{
	IupSetInt(tgl_option_c_en, "VALUE", N_options_dlg.option_c);
	IupSetInt(tgl_option_R_en, "VALUE", N_options_dlg.option_R);
	IupSetInt(tgl_option_m_en, "VALUE", N_options_dlg.option_m);
	IupSetInt(tgl_option_L_en, "VALUE", N_options_dlg.option_L);
}

//--------------------------------------------
static void dlg_N_options_set_active(void)
{
	if (N_options_dlg.option_c)
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "YES");
		IupSetAttribute(txt_option_c, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_c, "ACTIVE", "NO");
		IupSetAttribute(txt_option_c, "ACTIVE", "NO");
	}
	if (N_options_dlg.option_R)
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "YES");
		IupSetAttribute(txt_option_R, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_R, "ACTIVE", "NO");
		IupSetAttribute(txt_option_R, "ACTIVE", "NO");
	}
	if (N_options_dlg.option_m)
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "YES");
		IupSetAttribute(txt_option_m, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_m, "ACTIVE", "NO");
		IupSetAttribute(txt_option_m, "ACTIVE", "NO");
	}
	if (N_options_dlg.option_L)
	{
		IupSetAttribute(lbl_option_L, "ACTIVE", "YES");
		IupSetAttribute(txt_option_L, "ACTIVE", "YES");
	}
	else
	{
		IupSetAttribute(lbl_option_L, "ACTIVE", "NO");
		IupSetAttribute(txt_option_L, "ACTIVE", "NO");
	}
}

//--------------------------------------------
static int tgl_N_option_c_en_action_cb(Ihandle *ih, int v)
{
	N_options_dlg.option_c = v;
	dlg_N_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_N_option_R_en_action_cb(Ihandle *ih, int v)
{
	N_options_dlg.option_R = v;
	dlg_N_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_N_option_m_en_action_cb(Ihandle *ih, int v)
{
	N_options_dlg.option_m = v;
	dlg_N_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
static int tgl_N_option_L_en_action_cb(Ihandle *ih, int v)
{
	N_options_dlg.option_L = v;
	dlg_N_options_set_active();
	return IUP_DEFAULT;
}

//--------------------------------------------
// Options dialog

//--------------------------------------------
static int dlg_options_btn_cancel_action_cb(Ihandle* ih)
{
	return IUP_CLOSE;
}

//--------------------------------------------
static int btn_options_action_cb(Ihandle* ih)
{
	char *name = list_lstbox_find_devname_by_id(&list_sniff, IupGetInt(lst_sniff, "VALUE"));
	if (!strcmp(name, "B"))
	{
		// Blesniffer
		// copy dialog settings
		B_options_dlg = B_options;

		// option_c
		tgl_option_c_en = IupToggle("Enable -c option", NULL);
		Ihandle *hbox_tgl_option_c_en = IupHbox(tgl_option_c_en, NULL);
		IupSetAttribute(hbox_tgl_option_c_en, "NCMARGIN", "3x1");
		lbl_option_c = IupLabel("Enter channel number(s):");
		Ihandle *hbox_lbl_option_c = IupHbox(lbl_option_c, NULL);
		IupSetAttribute(hbox_lbl_option_c, "NCMARGIN", "3x");
		txt_option_c = IupText(NULL);
		IupSetAttribute(txt_option_c, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_c, "VALUE", B_options.option_c_str);
		IupSetAttribute(txt_option_c, "NC", B_OPTION_C_MAX_LEN_STR);
		IupSetAttribute(txt_option_c, "MASK", B_OPTION_C_TEXT_MASK);
		Ihandle *hbox_txt_option_c = IupHbox(txt_option_c, NULL);
		IupSetAttribute(hbox_txt_option_c, "NCMARGIN", "3x");
		Ihandle *vbox_option_c = IupVbox(hbox_tgl_option_c_en, hbox_lbl_option_c, hbox_txt_option_c, NULL);
		IupSetAttribute(vbox_option_c, "NCMARGIN", "3x4");
		Ihandle *frm_option_c = IupFrame(vbox_option_c);
		IupSetAttribute(frm_option_c, "TITLE", "Primary advertising channel(s) to listen on");

		// option_R
		tgl_option_R_en = IupToggle("Enable -R option", NULL);
		Ihandle *hbox_tgl_option_R_en = IupHbox(tgl_option_R_en, NULL);
		IupSetAttribute(hbox_tgl_option_R_en, "NCMARGIN", "3x");
		lbl_option_R = IupLabel("Enter RSSI value:");
		Ihandle *hbox_lbl_option_R = IupHbox(lbl_option_R, NULL);
		IupSetAttribute(hbox_lbl_option_R, "NCMARGIN", "3x");
		txt_option_R = IupText(NULL);
		IupSetAttribute(txt_option_R, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_R, "VALUE", B_options.option_R_str);
		IupSetAttribute(txt_option_R, "NC", B_OPTION_R_MAX_LEN_STR);
		IupSetAttribute(txt_option_R, "MASK", B_OPTION_R_TEXT_MASK);
		Ihandle *hbox_txt_option_R = IupHbox(txt_option_R, NULL);
		IupSetAttribute(hbox_txt_option_R, "NCMARGIN", "3x");
		Ihandle *vbox_option_R = IupVbox(hbox_tgl_option_R_en, hbox_lbl_option_R, hbox_txt_option_R, NULL);
		IupSetAttribute(vbox_option_R, "NCMARGIN", "3x4");
		Ihandle *frm_option_R = IupFrame(vbox_option_R);
		IupSetAttribute(frm_option_R, "TITLE", "Filter packets on primary advertising channels by minimum RSSI");

		// option_m
		tgl_option_m_en = IupToggle("Enable -m option", NULL);
		Ihandle *hbox_tgl_option_m_en = IupHbox(tgl_option_m_en, NULL);
		IupSetAttribute(hbox_tgl_option_m_en, "NCMARGIN", "3x1");
		lbl_option_m = IupLabel("Enter MAC address:");
		Ihandle *hbox_lbl_option_m = IupHbox(lbl_option_m, NULL);
		IupSetAttribute(hbox_lbl_option_m, "NCMARGIN", "3x");
		txt_option_m = IupText(NULL);
		IupSetAttribute(txt_option_m, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_m, "VALUE", B_options.option_m_str);
		IupSetAttribute(txt_option_m, "NC", B_OPTION_M_MAX_LEN_STR);
		IupSetAttribute(txt_option_m, "MASK", B_OPTION_M_TEXT_MASK);
		Ihandle *hbox_txt_option_m = IupHbox(txt_option_m, NULL);
		IupSetAttribute(hbox_txt_option_m, "NCMARGIN", "3x");
		Ihandle *vbox_option_m = IupVbox(hbox_tgl_option_m_en, hbox_lbl_option_m, hbox_txt_option_m, NULL);
		IupSetAttribute(vbox_option_m, "NCMARGIN", "3x4");
		Ihandle *frm_option_m = IupFrame(vbox_option_m);
		IupSetAttribute(frm_option_m, "TITLE", "Filter packets on primary advertising channels by MAC address");

		// option_f
		tgl_option_f_en = IupToggle("Enable -f option", NULL);
		Ihandle *hbox_tgl_option_f_en = IupHbox(tgl_option_f_en, NULL);
		IupSetAttribute(hbox_tgl_option_f_en, "NCMARGIN", "3x1");
		lbl_option_f = IupLabel("Enter follow mode(s) (conn, pa, cis(conn required), bis(pa required)):");
		Ihandle *hbox_lbl_option_f = IupHbox(lbl_option_f, NULL);
		IupSetAttribute(hbox_lbl_option_f, "NCMARGIN", "3x");
		txt_option_f = IupText(NULL);
		IupSetAttribute(txt_option_f, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_f, "VALUE", B_options.option_f_str);
		IupSetAttribute(txt_option_f, "NC", B_OPTION_F_MAX_LEN_STR);
		IupSetAttribute(txt_option_f, "MASK", B_OPTION_F_TEXT_MASK);
		Ihandle *hbox_txt_option_f = IupHbox(txt_option_f, NULL);
		IupSetAttribute(hbox_txt_option_f, "NCMARGIN", "3x");
		Ihandle *vbox_option_f = IupVbox(hbox_tgl_option_f_en, hbox_lbl_option_f, hbox_txt_option_f, NULL);
		IupSetAttribute(vbox_option_f, "NCMARGIN", "3x4");
		Ihandle *frm_option_f = IupFrame(vbox_option_f);
		IupSetAttribute(frm_option_f, "TITLE", "Blesniff follow mode(s)");

		// option_L
		tgl_option_L_en = IupToggle("Enable -L option", NULL);
		Ihandle *hbox_tgl_option_L_en = IupHbox(tgl_option_L_en, NULL);
		IupSetAttribute(hbox_tgl_option_L_en, "NCMARGIN", "3x1");
		lbl_option_L = IupLabel("Enter LTK key:");
		Ihandle *hbox_lbl_option_L = IupHbox(lbl_option_L, NULL);
		IupSetAttribute(hbox_lbl_option_L, "NCMARGIN", "3x");
		txt_option_L = IupText(NULL);
		IupSetAttribute(txt_option_L, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_L, "VALUE", B_options.option_L_str);
		IupSetAttribute(txt_option_L, "NC", B_OPTION_L_MAX_LEN_STR);
		IupSetAttribute(txt_option_L, "MASK", B_OPTION_L_TEXT_MASK);
		Ihandle *hbox_txt_option_L = IupHbox(txt_option_L, NULL);
		IupSetAttribute(hbox_txt_option_L, "NCMARGIN", "3x");
		Ihandle *vbox_option_L = IupVbox(hbox_tgl_option_L_en, hbox_lbl_option_L, hbox_txt_option_L, NULL);
		IupSetAttribute(vbox_option_L, "NCMARGIN", "3x4");
		Ihandle *frm_option_L = IupFrame(vbox_option_L);
		IupSetAttribute(frm_option_L, "TITLE", "LTK key for decrypting packets");

		Ihandle *vbox_c = IupVbox(frm_option_c, frm_option_R, frm_option_m, frm_option_f, frm_option_L, NULL);
		IupSetAttribute(vbox_c, "EXPAND", "HORIZONTAL");
		Ihandle *hbox_c = IupHbox(vbox_c, NULL);

		Ihandle *btn_options_ok = IupButton("OK", NULL);
		IupSetAttribute(btn_options_ok, "SIZE", "40");
		Ihandle *btn_options_cancel = IupButton("Cancel", NULL);
		IupSetAttribute(btn_options_cancel, "SIZE", "40");
		Ihandle *hbox_options_btns = IupHbox(IupFill(), btn_options_ok, btn_options_cancel, NULL);

		Ihandle *vbox_dlg = IupVbox(hbox_c, hbox_options_btns, NULL);
		IupSetAttribute(vbox_dlg, "NMARGIN", "10x10");

		// callbacks
		IupSetCallback(tgl_option_c_en, "ACTION", (Icallback)tgl_B_option_c_en_action_cb);
		IupSetCallback(tgl_option_R_en, "ACTION", (Icallback)tgl_B_option_R_en_action_cb);
		IupSetCallback(tgl_option_m_en, "ACTION", (Icallback)tgl_B_option_m_en_action_cb);
		IupSetCallback(tgl_option_f_en, "ACTION", (Icallback)tgl_B_option_f_en_action_cb);
		IupSetCallback(tgl_option_L_en, "ACTION", (Icallback)tgl_B_option_L_en_action_cb);

		// activity
		dlg_B_options_set_en_value();
		dlg_B_options_set_active();

		Ihandle* dlg_options = IupDialog(vbox_dlg);
		IupSetAttribute(dlg_options, "TITLE", "Blesniff options");
		IupSetAttribute(dlg_options, "DIALOGFRAME", "Yes");
		IupSetAttribute(dlg_options, "MINSIZE", B_OPTION_DIALOG_MINSIZE);
		IupSetAttribute(dlg_options, "GAP", "5");
		IupSetAttributeHandle(dlg_options, "DEFAULTENTER", btn_options_ok);
		IupSetAttributeHandle(dlg_options, "PARENTDIALOG", IupGetDialog(dlg));
		IupSetCallback(btn_options_ok, "ACTION", (Icallback)dlg_B_options_btn_ok_action_cb);
		IupSetCallback(btn_options_cancel, "ACTION", (Icallback)dlg_options_btn_cancel_action_cb);
		IupPopup(dlg_options, IUP_CENTERPARENT, IUP_CENTERPARENT);
		IupDestroy(dlg_options);
	}
	if (!strcmp(name, "S"))
	{
		// Sniffle
		// copy dialog settings
		S_options_dlg = S_options;

		// option_c
		tgl_option_c_en = IupToggle("Enable -c option", NULL);
		Ihandle *hbox_tgl_option_c_en = IupHbox(tgl_option_c_en, NULL);
		IupSetAttribute(hbox_tgl_option_c_en, "NCMARGIN", "3x1");
		lbl_option_c = IupLabel("Enter channel number:");
		Ihandle *hbox_lbl_option_c = IupHbox(lbl_option_c, NULL);
		IupSetAttribute(hbox_lbl_option_c, "NCMARGIN", "3x");
		txt_option_c = IupText(NULL);
		IupSetAttribute(txt_option_c, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_c, "VALUE", S_options.option_c_str);
		IupSetAttribute(txt_option_c, "NC", S_OPTION_C_MAX_LEN_STR);
		IupSetAttribute(txt_option_c, "MASK", S_OPTION_C_TEXT_MASK);
		Ihandle *hbox_txt_option_c = IupHbox(txt_option_c, NULL);
		IupSetAttribute(hbox_txt_option_c, "NCMARGIN", "3x");
		Ihandle *vbox_option_c = IupVbox(hbox_tgl_option_c_en, hbox_lbl_option_c, hbox_txt_option_c, NULL);
		IupSetAttribute(vbox_option_c, "NCMARGIN", "3x4");
		Ihandle *frm_option_c = IupFrame(vbox_option_c);
		IupSetAttribute(frm_option_c, "TITLE", "Primary advertising channel to listen on");

		// option_R
		tgl_option_R_en = IupToggle("Enable -R option", NULL);
		Ihandle *hbox_tgl_option_R_en = IupHbox(tgl_option_R_en, NULL);
		IupSetAttribute(hbox_tgl_option_R_en, "NCMARGIN", "3x");
		lbl_option_R = IupLabel("Enter RSSI value:");
		Ihandle *hbox_lbl_option_R = IupHbox(lbl_option_R, NULL);
		IupSetAttribute(hbox_lbl_option_R, "NCMARGIN", "3x");
		txt_option_R = IupText(NULL);
		IupSetAttribute(txt_option_R, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_R, "VALUE", S_options.option_R_str);
		IupSetAttribute(txt_option_R, "NC", S_OPTION_R_MAX_LEN_STR);
		IupSetAttribute(txt_option_R, "MASK", S_OPTION_R_TEXT_MASK);
		Ihandle *hbox_txt_option_R = IupHbox(txt_option_R, NULL);
		IupSetAttribute(hbox_txt_option_R, "NCMARGIN", "3x");
		Ihandle *vbox_option_R = IupVbox(hbox_tgl_option_R_en, hbox_lbl_option_R, hbox_txt_option_R, NULL);
		IupSetAttribute(vbox_option_R, "NCMARGIN", "3x4");
		Ihandle *frm_option_R = IupFrame(vbox_option_R);
		IupSetAttribute(frm_option_R, "TITLE", "Filter advertising packets by minimum RSSI");

		// option_m
		tgl_option_m_en = IupToggle("Enable -m option", NULL);
		Ihandle *hbox_tgl_option_m_en = IupHbox(tgl_option_m_en, NULL);
		IupSetAttribute(hbox_tgl_option_m_en, "NCMARGIN", "3x1");
		lbl_option_m = IupLabel("Enter MAC address:");
		Ihandle *hbox_lbl_option_m = IupHbox(lbl_option_m, NULL);
		IupSetAttribute(hbox_lbl_option_m, "NCMARGIN", "3x");
		txt_option_m = IupText(NULL);
		IupSetAttribute(txt_option_m, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_m, "VALUE", S_options.option_m_str);
		IupSetAttribute(txt_option_m, "NC", S_OPTION_M_MAX_LEN_STR);
		IupSetAttribute(txt_option_m, "MASK", S_OPTION_M_TEXT_MASK);
		Ihandle *hbox_txt_option_m = IupHbox(txt_option_m, NULL);
		IupSetAttribute(hbox_txt_option_m, "NCMARGIN", "3x");
		Ihandle *vbox_option_m = IupVbox(hbox_tgl_option_m_en, hbox_lbl_option_m, hbox_txt_option_m, NULL);
		IupSetAttribute(vbox_option_m, "NCMARGIN", "3x4");
		Ihandle *frm_option_m = IupFrame(vbox_option_m);
		IupSetAttribute(frm_option_m, "TITLE", "Filter advertising packets by MAC address");

		// option_e
		tgl_option_e_en = IupToggle("Enable -e option", NULL);
		Ihandle *hbox_tgl_option_e_en = IupHbox(tgl_option_e_en, NULL);
		IupSetAttribute(hbox_tgl_option_e_en, "NCMARGIN", "3x1");
		Ihandle *vbox_option_e = IupVbox(hbox_tgl_option_e_en, NULL);
		IupSetAttribute(vbox_option_e, "NCMARGIN", "3x4");
		Ihandle *frm_option_e = IupFrame(vbox_option_e);
		IupSetAttribute(frm_option_e, "TITLE", "Follow connections on secondary advertising channels");
		IupSetAttribute(frm_option_e, "MINSIZE", S_OPTION_DIALOG_MINSIZE);

		Ihandle *vbox_c = IupVbox(frm_option_c, frm_option_R, frm_option_m, frm_option_e, NULL);
		IupSetAttribute(vbox_c, "EXPAND", "HORIZONTAL");
		Ihandle *hbox_c = IupHbox(vbox_c, NULL);

		Ihandle *btn_options_ok = IupButton("OK", NULL);
		IupSetAttribute(btn_options_ok, "SIZE", "40");
		Ihandle *btn_options_cancel = IupButton("Cancel", NULL);
		IupSetAttribute(btn_options_cancel, "SIZE", "40");
		Ihandle *hbox_options_btns = IupHbox(IupFill(), btn_options_ok, btn_options_cancel, NULL);

		Ihandle *vbox_dlg = IupVbox(hbox_c, hbox_options_btns, NULL);
		IupSetAttribute(vbox_dlg, "NMARGIN", "10x10");

		// callbacks
		IupSetCallback(tgl_option_c_en, "ACTION", (Icallback)tgl_S_option_c_en_action_cb);
		IupSetCallback(tgl_option_R_en, "ACTION", (Icallback)tgl_S_option_R_en_action_cb);
		IupSetCallback(tgl_option_m_en, "ACTION", (Icallback)tgl_S_option_m_en_action_cb);
		IupSetCallback(tgl_option_e_en, "ACTION", (Icallback)tgl_S_option_e_en_action_cb);

		// activity
		dlg_S_options_set_en_value();
		dlg_S_options_set_active();

		Ihandle* dlg_options = IupDialog(vbox_dlg);
		IupSetAttribute(dlg_options, "TITLE", "Sniffle options");
		IupSetAttribute(dlg_options, "DIALOGFRAME", "Yes");
		IupSetAttribute(dlg_options, "MINSIZE", S_OPTION_DIALOG_MINSIZE);
		IupSetAttribute(dlg_options, "GAP", "5");
		IupSetAttributeHandle(dlg_options, "DEFAULTENTER", btn_options_ok);
		IupSetAttributeHandle(dlg_options, "PARENTDIALOG", IupGetDialog(dlg));
		IupSetCallback(btn_options_ok, "ACTION", (Icallback)dlg_S_options_btn_ok_action_cb);
		IupSetCallback(btn_options_cancel, "ACTION", (Icallback)dlg_options_btn_cancel_action_cb);
		IupPopup(dlg_options, IUP_CENTERPARENT, IUP_CENTERPARENT);
		IupDestroy(dlg_options);
	}
	if (!strcmp(name, "N4"))
	{
		// Blesniffer
		// copy dialog settings
		N_options_dlg = N_options;

		// option_c
		tgl_option_c_en = IupToggle("Enable -c option", NULL);
		Ihandle *hbox_tgl_option_c_en = IupHbox(tgl_option_c_en, NULL);
		IupSetAttribute(hbox_tgl_option_c_en, "NCMARGIN", "3x1");
		lbl_option_c = IupLabel("Enter channel number(s):");
		Ihandle *hbox_lbl_option_c = IupHbox(lbl_option_c, NULL);
		IupSetAttribute(hbox_lbl_option_c, "NCMARGIN", "3x");
		txt_option_c = IupText(NULL);
		IupSetAttribute(txt_option_c, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_c, "VALUE", N_options.option_c_str);
		IupSetAttribute(txt_option_c, "NC", B_OPTION_C_MAX_LEN_STR);
		IupSetAttribute(txt_option_c, "MASK", B_OPTION_C_TEXT_MASK);
		Ihandle *hbox_txt_option_c = IupHbox(txt_option_c, NULL);
		IupSetAttribute(hbox_txt_option_c, "NCMARGIN", "3x");
		Ihandle *vbox_option_c = IupVbox(hbox_tgl_option_c_en, hbox_lbl_option_c, hbox_txt_option_c, NULL);
		IupSetAttribute(vbox_option_c, "NCMARGIN", "3x4");
		Ihandle *frm_option_c = IupFrame(vbox_option_c);
		IupSetAttribute(frm_option_c, "TITLE", "Primary advertising channel(s) to listen on");

		// option_R
		tgl_option_R_en = IupToggle("Enable -R option", NULL);
		Ihandle *hbox_tgl_option_R_en = IupHbox(tgl_option_R_en, NULL);
		IupSetAttribute(hbox_tgl_option_R_en, "NCMARGIN", "3x");
		lbl_option_R = IupLabel("Enter RSSI value:");
		Ihandle *hbox_lbl_option_R = IupHbox(lbl_option_R, NULL);
		IupSetAttribute(hbox_lbl_option_R, "NCMARGIN", "3x");
		txt_option_R = IupText(NULL);
		IupSetAttribute(txt_option_R, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_R, "VALUE", N_options.option_R_str);
		IupSetAttribute(txt_option_R, "NC", B_OPTION_R_MAX_LEN_STR);
		IupSetAttribute(txt_option_R, "MASK", B_OPTION_R_TEXT_MASK);
		Ihandle *hbox_txt_option_R = IupHbox(txt_option_R, NULL);
		IupSetAttribute(hbox_txt_option_R, "NCMARGIN", "3x");
		Ihandle *vbox_option_R = IupVbox(hbox_tgl_option_R_en, hbox_lbl_option_R, hbox_txt_option_R, NULL);
		IupSetAttribute(vbox_option_R, "NCMARGIN", "3x4");
		Ihandle *frm_option_R = IupFrame(vbox_option_R);
		IupSetAttribute(frm_option_R, "TITLE", "Filter packets by minimum RSSI");

		// option_m
		tgl_option_m_en = IupToggle("Enable -m option", NULL);
		Ihandle *hbox_tgl_option_m_en = IupHbox(tgl_option_m_en, NULL);
		IupSetAttribute(hbox_tgl_option_m_en, "NCMARGIN", "3x1");
		lbl_option_m = IupLabel("Enter MAC address:");
		Ihandle *hbox_lbl_option_m = IupHbox(lbl_option_m, NULL);
		IupSetAttribute(hbox_lbl_option_m, "NCMARGIN", "3x");
		txt_option_m = IupText(NULL);
		IupSetAttribute(txt_option_m, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_m, "VALUE", N_options.option_m_str);
		IupSetAttribute(txt_option_m, "NC", B_OPTION_M_MAX_LEN_STR);
		IupSetAttribute(txt_option_m, "MASK", B_OPTION_M_TEXT_MASK);
		Ihandle *hbox_txt_option_m = IupHbox(txt_option_m, NULL);
		IupSetAttribute(hbox_txt_option_m, "NCMARGIN", "3x");
		Ihandle *vbox_option_m = IupVbox(hbox_tgl_option_m_en, hbox_lbl_option_m, hbox_txt_option_m, NULL);
		IupSetAttribute(vbox_option_m, "NCMARGIN", "3x4");
		Ihandle *frm_option_m = IupFrame(vbox_option_m);
		IupSetAttribute(frm_option_m, "TITLE", "Filter advertising packets by MAC address");

		// option_L
		tgl_option_L_en = IupToggle("Enable -L option", NULL);
		Ihandle *hbox_tgl_option_L_en = IupHbox(tgl_option_L_en, NULL);
		IupSetAttribute(hbox_tgl_option_L_en, "NCMARGIN", "3x1");
		lbl_option_L = IupLabel("Enter LTK key:");
		Ihandle *hbox_lbl_option_L = IupHbox(lbl_option_L, NULL);
		IupSetAttribute(hbox_lbl_option_L, "NCMARGIN", "3x");
		txt_option_L = IupText(NULL);
		IupSetAttribute(txt_option_L, "EXPAND", "HORIZONTAL");
		IupSetAttribute(txt_option_L, "VALUE", N_options.option_L_str);
		IupSetAttribute(txt_option_L, "NC", B_OPTION_L_MAX_LEN_STR);
		IupSetAttribute(txt_option_L, "MASK", B_OPTION_L_TEXT_MASK);
		Ihandle *hbox_txt_option_L = IupHbox(txt_option_L, NULL);
		IupSetAttribute(hbox_txt_option_L, "NCMARGIN", "3x");
		Ihandle *vbox_option_L = IupVbox(hbox_tgl_option_L_en, hbox_lbl_option_L, hbox_txt_option_L, NULL);
		IupSetAttribute(vbox_option_L, "NCMARGIN", "3x4");
		Ihandle *frm_option_L = IupFrame(vbox_option_L);
		IupSetAttribute(frm_option_L, "TITLE", "LTK key for decrypting packets");

		Ihandle *vbox_c = IupVbox(frm_option_c, frm_option_R, frm_option_m, frm_option_L, NULL);
		IupSetAttribute(vbox_c, "EXPAND", "HORIZONTAL");
		Ihandle *hbox_c = IupHbox(vbox_c, NULL);

		Ihandle *btn_options_ok = IupButton("OK", NULL);
		IupSetAttribute(btn_options_ok, "SIZE", "40");
		Ihandle *btn_options_cancel = IupButton("Cancel", NULL);
		IupSetAttribute(btn_options_cancel, "SIZE", "40");
		Ihandle *hbox_options_btns = IupHbox(IupFill(), btn_options_ok, btn_options_cancel, NULL);

		Ihandle *vbox_dlg = IupVbox(hbox_c, hbox_options_btns, NULL);
		IupSetAttribute(vbox_dlg, "NMARGIN", "10x10");

		// callbacks
		IupSetCallback(tgl_option_c_en, "ACTION", (Icallback)tgl_N_option_c_en_action_cb);
		IupSetCallback(tgl_option_R_en, "ACTION", (Icallback)tgl_N_option_R_en_action_cb);
		IupSetCallback(tgl_option_m_en, "ACTION", (Icallback)tgl_N_option_m_en_action_cb);
		IupSetCallback(tgl_option_L_en, "ACTION", (Icallback)tgl_N_option_L_en_action_cb);

		// activity
		dlg_N_options_set_en_value();
		dlg_N_options_set_active();

		Ihandle* dlg_options = IupDialog(vbox_dlg);
		IupSetAttribute(dlg_options, "TITLE", "nRF Sniffer options");
		IupSetAttribute(dlg_options, "DIALOGFRAME", "Yes");
		IupSetAttribute(dlg_options, "MINSIZE", B_OPTION_DIALOG_MINSIZE);
		IupSetAttribute(dlg_options, "GAP", "5");
		IupSetAttributeHandle(dlg_options, "DEFAULTENTER", btn_options_ok);
		IupSetAttributeHandle(dlg_options, "PARENTDIALOG", IupGetDialog(dlg));
		IupSetCallback(btn_options_ok, "ACTION", (Icallback)dlg_N_options_btn_ok_action_cb);
		IupSetCallback(btn_options_cancel, "ACTION", (Icallback)dlg_options_btn_cancel_action_cb);
		IupPopup(dlg_options, IUP_CENTERPARENT, IUP_CENTERPARENT);
		IupDestroy(dlg_options);
	}
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
	IupSetAttribute(lst_sniff, "SIZE", "110");
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

	// Input -> Capture device -> Options
	btn_options = IupButton("Options...", NULL);
	IupSetAttribute(btn_options, "EXPAND", "VERTICAL"); //?

	// Input -> Capture device
	Ihandle *hbox_capdev = IupHbox(hbox_iface, hbox_sniff, hbox_baudr, btn_options, NULL);
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
	IupSetAttribute(lbl_link, "ALIGNMENT", "ARIGHT");
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
	IupSetCallback(btn_options, "ACTION", (Icallback)btn_options_action_cb);

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
