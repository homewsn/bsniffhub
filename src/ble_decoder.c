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
#include <assert.h>     /* assert */
#include <stdio.h>      /* sscanf */
#include <string.h>     /* memset, memcpy, memcmp */
#include <stddef.h>     /* size_t */
#include <stdlib.h>     /* strtol */
#include "ble_crypto.h"
#include "msg_ble.h"
#include "msg_to_cli.h"
#include "list_adv.h"
#include "ble_decoder.h"

#ifndef SC_OOB_TEST
#define SC_OOB_TEST 0
#endif

#ifndef DPRINTF
#define DPRINTF 0
#endif

#if DPRINTF
#define dprintf(...) msg_to_cli_add_print_command(__VA_ARGS__)
#else
#define dprintf(...)
#endif

//--------------------------------------------
typedef enum ble_pairing_method
{
	BLE_PAIRING_METHOD_UNDEFINED = 0,
	BLE_LEGACY_PAIRING,
	BLE_SECURE_CONNECTION
} ble_pairing_method_t;

typedef enum ble_association_model
{
	BLE_ASSOCIATION_MODEL_UNDEFINED = 0,
	BLE_JUST_WORKS,
	BLE_PASSKEY_ENTRY,
	BLE_OUT_OF_BAND,
	BLE_NUMERIC_COMPARISON
} ble_association_model_t;

typedef enum ble_io_capability
{
	BLE_DISPLAY_ONLY = 0x00,
	BLE_DISPLAY_YES_NO = 0x01,
	BLE_KEYBOARD_ONLY = 0x02,
	BLE_NO_INPUT_NO_OUTPUT = 0x03,
	BLE_KEYBOARD_DISPLAY = 0x04
} ble_io_capability_t;

//--------------------------------------------
typedef struct ble_time_cfg
{
	uint32_t win_size;                           // usec
	uint32_t win_offset;                         // usec
	uint32_t interval;                           // usec
	uint16_t latency;
	uint16_t timeout;
} ble_time_cfg_t;

//--------------------------------------------
typedef struct ble_secure_connection_cfg
{
	uint8_t PKax[32];
	uint8_t PKay[32];
	uint8_t PKbx[32];
	uint8_t PKby[32];
	uint8_t debug_mode;                         // 0 - no debug mode, 1 - master's debug mode, 2 - slave's debug mode
	uint8_t DHKey[32];
	uint8_t MacKey[16];
	uint8_t Ea[16];
	uint8_t Eb[16];
	uint8_t Ca[16];
	uint8_t Na[16];
	uint8_t Cb[16];
	uint8_t Nb[16];
	size_t passkey_bit_cnt;
	uint32_t passkey;
} ble_secure_connection_cfg_t;

//--------------------------------------------
typedef struct ble_legacy_pairing_cfg
{
	uint8_t tk[AES128_BLOCK_LENGTH];
	uint8_t mconfirm[AES128_BLOCK_LENGTH];
	uint8_t sconfirm[AES128_BLOCK_LENGTH];
	uint8_t mrand[AES128_BLOCK_LENGTH];
	uint8_t srand[AES128_BLOCK_LENGTH];
	uint8_t stk[AES128_BLOCK_LENGTH];
} ble_legacy_pairing_cfg_t;

//--------------------------------------------
typedef struct ble_conn
{
	uint8_t data_access_address[ACCESS_ADDRESS_LENGTH];
	uint32_t crc_init;
	pkt_dir_t current_packet_direction;
	pkt_dir_t previous_packet_direction;
	uint8_t encrypted_packet;                    // the next packet will be encrypted or not
	uint8_t use_brute_force;                     // use brute force to find Passkey or not
	uint8_t first_window;                        // first time window after CONNECT_REQ packet or not
	uint8_t csa;                                 // channel selection algorithm #2 or not
	uint8_t master_more_data;                    // more data flag from master
	uint8_t slave_more_data;                     // more data flag from slave
	uint64_t master_encrypted_packet_counter;
	uint64_t slave_encrypted_packet_counter;
	uint16_t connection_event_counter;
	ble_time_cfg_t time_cfg;
	ble_time_cfg_t time_cfg_update;
	uint16_t time_cfg_update_instant;
	uint64_t anchor_point;                       // usec
	uint64_t previous_packet_start_timestamp;    // usec
	uint64_t current_packet_transmission_time;   // usec
	uint64_t previous_packet_transmission_time;  // usec
	uint8_t channel_remapping_table[DATA_CHANNELS_NUMBER];
	uint8_t channel_map[DATA_CHANNELS_BYTES_NUMBER];
	uint8_t channel_map_update[DATA_CHANNELS_BYTES_NUMBER];
	uint16_t channel_map_update_instant;
	uint32_t channel_identifier;
	uint8_t unmapped_channel;
	uint8_t used_channels_number;
	uint8_t used_channel;
	uint8_t hop;
	uint8_t iat;
	uint8_t rat;
	uint8_t ia[DEVICE_ADDRESS_LENGTH];
	uint8_t ra[DEVICE_ADDRESS_LENGTH];
	uint8_t preq[SMP_PAIRING_REQUEST_LENGTH];
	uint8_t pres[SMP_PAIRING_RESPONSE_LENGTH];
	uint8_t isc;
	uint8_t rsc;
	uint8_t ioob;
	uint8_t roob;
	uint8_t imitm;
	uint8_t rmitm;
	ble_io_capability_t iiocap;
	ble_io_capability_t riocap;
	ble_pairing_method_t pair_method;
	ble_association_model_t assoc_model;
	ble_legacy_pairing_cfg_t pair_legacy;
	ble_secure_connection_cfg_t pair_secconn;
	uint8_t session_key[AES128_BLOCK_LENGTH];
	uint8_t rand[8];
	uint8_t ediv[2];
	uint8_t skdm[AES128_BLOCK_LENGTH / 2];
	uint8_t skds[AES128_BLOCK_LENGTH / 2];
	uint8_t ivm[4];
	uint8_t ivs[4];
	uint8_t iv[8];
} ble_conn_t;

#if SC_OOB_TEST
//--------------------------------------------
typedef struct oob_data
{
	uint8_t ra[16];
	uint8_t rb[16];
	uint8_t Ca[16];
	uint8_t Cb[16];
} oob_data_t;
#endif

//--------------------------------------------
static ble_conn_t conn;
static list_adv_t *adv_devs = NULL;
static uint8_t ltk[AES128_BLOCK_LENGTH];
static uint16_t total_packet_counter;

#if SC_OOB_TEST
static oob_data_t oob =
{
	.ra = { 0 },
	.rb = { 0x5E, 0x88, 0x24, 0x17, 0xA9, 0x87, 0x22, 0x24, 0x23, 0xA1, 0xA9, 0xEC, 0x71, 0x9A, 0xED, 0x27 },
	.Ca = { 0 },
	.Cb = { 0xA3, 0x70, 0x0E, 0xAE, 0x6F, 0xDD, 0xE2, 0x3C, 0x09, 0x68, 0xB1, 0x48, 0xD2, 0x23, 0xD9, 0x50 }
};
#endif


//--------------------------------------------
static ble_association_model_t mapping_io_capabilities_to_association_model(ble_conn_t *conn)
{
	switch (conn->pair_method)
	{
	case BLE_LEGACY_PAIRING:
		if (conn->ioob == 1 && conn->roob == 1)
		{
			return BLE_OUT_OF_BAND;
		}
		else
		{
			break;
		}
	case BLE_SECURE_CONNECTION:
		if (conn->ioob == 0 && conn->roob == 0)
		{
			break;
		}
		else
		{
			return BLE_OUT_OF_BAND;
		}
	default:
		return BLE_ASSOCIATION_MODEL_UNDEFINED;
	}

	if (conn->imitm == 0 && conn->rmitm == 0)
	{
		return BLE_JUST_WORKS;
	}

	switch (conn->riocap)
	{
	case BLE_DISPLAY_ONLY:
		switch (conn->iiocap)
		{
		case BLE_DISPLAY_ONLY:
		case BLE_DISPLAY_YES_NO:
		case BLE_NO_INPUT_NO_OUTPUT:
			return BLE_JUST_WORKS;
		case BLE_KEYBOARD_ONLY:
		case BLE_KEYBOARD_DISPLAY:
			return BLE_PASSKEY_ENTRY;
		default:
			return BLE_ASSOCIATION_MODEL_UNDEFINED;
		}
	case BLE_DISPLAY_YES_NO:
		switch (conn->iiocap)
		{
		case BLE_DISPLAY_ONLY:
		case BLE_NO_INPUT_NO_OUTPUT:
			return BLE_JUST_WORKS;
		case BLE_DISPLAY_YES_NO:
			switch (conn->pair_method)
			{
			case BLE_LEGACY_PAIRING:
				return BLE_JUST_WORKS;
			case BLE_SECURE_CONNECTION:
				return BLE_NUMERIC_COMPARISON;
			default:
				return BLE_ASSOCIATION_MODEL_UNDEFINED;
			}
		case BLE_KEYBOARD_ONLY:
			return BLE_PASSKEY_ENTRY;
		case BLE_KEYBOARD_DISPLAY:
			switch (conn->pair_method)
			{
			case BLE_LEGACY_PAIRING:
				return BLE_PASSKEY_ENTRY;
			case BLE_SECURE_CONNECTION:
				return BLE_NUMERIC_COMPARISON;
			default:
				return BLE_ASSOCIATION_MODEL_UNDEFINED;
			}
		default:
			return BLE_ASSOCIATION_MODEL_UNDEFINED;
		}
	case BLE_KEYBOARD_ONLY:
		switch (conn->iiocap)
		{
		case BLE_DISPLAY_ONLY:
		case BLE_DISPLAY_YES_NO:
		case BLE_KEYBOARD_ONLY:
		case BLE_KEYBOARD_DISPLAY:
			return BLE_PASSKEY_ENTRY;
		case BLE_NO_INPUT_NO_OUTPUT:
			return BLE_JUST_WORKS;
		default:
			return BLE_ASSOCIATION_MODEL_UNDEFINED;
		}
	case BLE_NO_INPUT_NO_OUTPUT:
		switch (conn->iiocap)
		{
		case BLE_DISPLAY_ONLY:
		case BLE_DISPLAY_YES_NO:
		case BLE_KEYBOARD_ONLY:
		case BLE_KEYBOARD_DISPLAY:
		case BLE_NO_INPUT_NO_OUTPUT:
			return BLE_JUST_WORKS;
		default:
			return BLE_ASSOCIATION_MODEL_UNDEFINED;
		}
	case BLE_KEYBOARD_DISPLAY:
		switch (conn->iiocap)
		{
		case BLE_DISPLAY_ONLY:
			return BLE_PASSKEY_ENTRY;
		case BLE_DISPLAY_YES_NO:
		case BLE_KEYBOARD_DISPLAY:
			switch (conn->pair_method)
			{
			case BLE_LEGACY_PAIRING:
				return BLE_PASSKEY_ENTRY;
			case BLE_SECURE_CONNECTION:
				return BLE_NUMERIC_COMPARISON;
			default:
				return BLE_ASSOCIATION_MODEL_UNDEFINED;
			}
		case BLE_KEYBOARD_ONLY:
			return BLE_PASSKEY_ENTRY;
		case BLE_NO_INPUT_NO_OUTPUT:
			return BLE_JUST_WORKS;
		default:
			return BLE_ASSOCIATION_MODEL_UNDEFINED;
		}
	default:
		return BLE_ASSOCIATION_MODEL_UNDEFINED;
	}
}

//--------------------------------------------
static void legacy_pairing_rand_generate(ble_conn_t *conn)
{
	uint8_t buf[16];

	if (conn->current_packet_direction == DIR_MASTER_SLAVE)
	{
		// mrand
		ble_c1_reverse(conn->pair_legacy.tk, conn->pair_legacy.mconfirm, conn->preq, conn->pres, conn->iat, conn->ia, conn->rat, conn->ra, buf);
	}
	else
	{
		// srand
		ble_c1_reverse(conn->pair_legacy.tk, conn->pair_legacy.sconfirm, conn->preq, conn->pres, conn->iat, conn->ia, conn->rat, conn->ra, buf);
	}
}

//--------------------------------------------
static int legacy_pairing_confirm_generate_and_compare(ble_conn_t *conn)
{
	uint8_t buf[16];

	if (conn->current_packet_direction == DIR_MASTER_SLAVE)
	{
		// mconfirm
		ble_c1(conn->pair_legacy.tk, conn->pair_legacy.mrand, conn->preq, conn->pres, conn->iat, conn->ia, conn->rat, conn->ra, buf);
		return (!memcmp(conn->pair_legacy.mconfirm, buf, AES128_BLOCK_LENGTH)) ? 0 : -1;
	}
	else
	{
		// sconfirm
		ble_c1(conn->pair_legacy.tk, conn->pair_legacy.srand, conn->preq, conn->pres, conn->iat, conn->ia, conn->rat, conn->ra, buf);
		return (!memcmp(conn->pair_legacy.sconfirm, buf, AES128_BLOCK_LENGTH)) ? 0 : -1;
	}
}

//--------------------------------------------
static void legacy_pairing_stk_generate(ble_conn_t *conn)
{
	ble_s1(conn->pair_legacy.tk, conn->pair_legacy.srand, conn->pair_legacy.mrand, conn->pair_legacy.stk);
}

//--------------------------------------------
static void secure_connection_debug_mode_detect(ble_conn_t *conn)
{
	uint8_t public_key[64];
	const uint8_t debug_public_key_x[32] =
	{
		0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c, 0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9,
		0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb, 0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6
	};
	const uint8_t debug_public_key_y[32] =
	{
		0xdc, 0x80, 0x9c, 0x49, 0x65, 0x2a, 0xeb, 0x6d, 0x63, 0x32, 0x9a, 0xbf, 0x5a, 0x52, 0x15, 0x5c,
		0x76, 0x63, 0x45, 0xc2, 0x8f, 0xed, 0x30, 0x24, 0x74, 0x1c, 0x8e, 0xd0, 0x15, 0x89, 0xd2, 0x8b
	};
	const uint8_t debug_private_key[32] =
	{
		0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38, 0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
		0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99, 0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd
	};

	if (!memcmp(conn->pair_secconn.PKax, debug_public_key_x, 32) &&
		!memcmp(conn->pair_secconn.PKay, debug_public_key_y, 32))
	{
		memcpy(public_key, conn->pair_secconn.PKbx, 32);
		memcpy(&public_key[32], conn->pair_secconn.PKby, 32);
		conn->pair_secconn.debug_mode = 1;
	}
	else if (!memcmp(conn->pair_secconn.PKbx, debug_public_key_x, 32) &&
		!memcmp(conn->pair_secconn.PKby, debug_public_key_y, 32))
	{
		memcpy(public_key, conn->pair_secconn.PKax, 32);
		memcpy(&public_key[32], conn->pair_secconn.PKay, 32);
		conn->pair_secconn.debug_mode = 2;
	}
	else
	{
		return;
	}
	if (ble_p256(debug_private_key, public_key, conn->pair_secconn.DHKey) < 0)
	{
		conn->pair_secconn.debug_mode = 0;
		return;
	}
	msg_to_cli_add_print_command("BLE Secure Connection Debug mode of the %s device detected.\n",
		(conn->pair_secconn.debug_mode == 1) ? "master" : "slave");
}

//--------------------------------------------
static void secure_connection_mackey_ltk_generate(ble_conn_t *conn)
{
	uint8_t A1[7];
	uint8_t A2[7];

	A1[0] = conn->iat;
	A2[0] = conn->rat;
	memcpy(&A1[1], conn->ia, DEVICE_ADDRESS_LENGTH);
	memcpy(&A2[1], conn->ra, DEVICE_ADDRESS_LENGTH);
	ble_f5(conn->pair_secconn.DHKey, conn->pair_secconn.Na, conn->pair_secconn.Nb, A1, A2, conn->pair_secconn.MacKey, ltk);
	msg_to_cli_add_print_command("LTK found: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		ltk[0], ltk[1], ltk[2], ltk[3], ltk[4], ltk[5], ltk[6], ltk[7],
		ltk[8], ltk[9], ltk[10], ltk[11], ltk[12], ltk[13], ltk[14], ltk[15]);
}

#if SC_OOB_TEST
//--------------------------------------------
static void secure_connection_oob_check(ble_conn_t *conn, int initiator)
{
	uint8_t Z[1] = { 0x00 };
	uint8_t confirm[16];

	if (initiator)
	{
		if (conn->roob)
		{
			ble_f4(conn->pair_secconn.PKax, conn->pair_secconn.PKax, oob.ra, Z, confirm);
#if 0
			assert(!memcmp(oob.Ca, confirm, 16));
#else
			if (memcmp(oob.Ca, confirm, 16))
			{
				dprintf("%s", "DEBUG: Secure connection Ca is wrong.\n");
			}
#endif
		}
		else
		{
			memset(oob.ra, 0, sizeof(oob.ra));
		}
	}
	else
	{
		if (conn->ioob)
		{
			ble_f4(conn->pair_secconn.PKbx, conn->pair_secconn.PKbx, oob.rb, Z, confirm);
#if 0
			assert(!memcmp(oob.Cb, confirm, 16));
#else
			if (memcmp(oob.Cb, confirm, 16))
			{
				dprintf("%s", "DEBUG: Secure connection Cb is wrong.\n");
			}
#endif
		}
		else
		{
			memset(oob.rb, 0, sizeof(oob.rb));
		}
	}
}
#endif

//--------------------------------------------
static void secure_connection_number_check(ble_conn_t *conn)
{
	uint8_t Z[1] = { 0x00 };
	uint8_t confirm[16];

	ble_f4(conn->pair_secconn.PKbx, conn->pair_secconn.PKax, conn->pair_secconn.Nb, Z, confirm);
	secure_connection_mackey_ltk_generate(conn);
#if 0
	assert(!memcmp(conn->pair_secconn.Cb, confirm, 16));
#else
	if (memcmp(conn->pair_secconn.Cb, confirm, 16))
	{
		dprintf("%s", "DEBUG: Secure connection Cb is wrong.\n");
		return;
	}
#endif
	if (conn->assoc_model == BLE_NUMERIC_COMPARISON)
	{
		uint32_t compare_value;
		ble_g2(conn->pair_secconn.PKax, conn->pair_secconn.PKbx, conn->pair_secconn.Na, conn->pair_secconn.Nb, &compare_value);
		compare_value %= 1000000;
		msg_to_cli_add_print_command("The numeric compare value found: %d\n", compare_value);
	}
}

//--------------------------------------------
static void secure_connection_passkey_bit_check(ble_conn_t *conn)
{
	uint8_t Z[1] = { 0x80 };
	uint8_t confirm[16];

	ble_f4(conn->pair_secconn.PKax, conn->pair_secconn.PKbx, conn->pair_secconn.Na, Z, confirm);
	if (memcmp(conn->pair_secconn.Ca, confirm, 16))
	{
		conn->pair_secconn.passkey |= 1 << conn->pair_secconn.passkey_bit_cnt;
	}
	conn->pair_secconn.passkey_bit_cnt++;
	if (conn->pair_secconn.passkey_bit_cnt == 20)
	{
		secure_connection_mackey_ltk_generate(conn);
		msg_to_cli_add_print_command("The entered Passkey found: %d\n", conn->pair_secconn.passkey);
	}
}

//--------------------------------------------
static void secure_connection_check_value_generate(ble_conn_t *conn)
{
	uint8_t buf[16];
	uint8_t A1[7];
	uint8_t A2[7];
	uint8_t r[16] = { 0 };
	uint8_t IOcap[3];

	switch (conn->assoc_model)
	{
	case BLE_JUST_WORKS:
	case BLE_NUMERIC_COMPARISON:
		break;
	case BLE_PASSKEY_ENTRY:
		r[15] = (uint8_t)(conn->pair_secconn.passkey);
		r[14] = (uint8_t)(conn->pair_secconn.passkey >> 8);
		r[13] = (uint8_t)(conn->pair_secconn.passkey >> 16);
		r[12] = (uint8_t)(conn->pair_secconn.passkey >> 24);
		break;
	case BLE_OUT_OF_BAND:
#if SC_OOB_TEST
		if (conn->current_packet_direction == DIR_MASTER_SLAVE)
		{
			memcpy(r, oob.rb, 16);
		}
		else
		{
			memcpy(r, oob.ra, 16);
		}
		break;
#else
		return;
#endif
	default:
		assert(0);
		break;
	}

	A1[0] = conn->iat;
	A2[0] = conn->rat;
	memcpy(&A1[1], conn->ia, DEVICE_ADDRESS_LENGTH);
	memcpy(&A2[1], conn->ra, DEVICE_ADDRESS_LENGTH);

	if (conn->current_packet_direction == DIR_MASTER_SLAVE)
	{
		// Ea
		memcpy(IOcap, &conn->preq[3], sizeof(IOcap));
		ble_f6(conn->pair_secconn.MacKey, conn->pair_secconn.Na, conn->pair_secconn.Nb, r, IOcap, A1, A2, buf);
		if (conn->pair_secconn.debug_mode)
		{
#if 0
			assert(!memcmp(conn->pair_secconn.Ea, buf, 16));
#else
			if (memcmp(conn->pair_secconn.Ea, buf, 16))
			{
				dprintf("%s", "DEBUG: Secure connection Ea is wrong.\n");
			}
#endif
		}
	}
	else
	{
		// Eb
		memcpy(IOcap, &conn->pres[3], sizeof(IOcap));
		ble_f6(conn->pair_secconn.MacKey, conn->pair_secconn.Nb, conn->pair_secconn.Na, r, IOcap, A2, A1, buf);
		if (conn->pair_secconn.debug_mode)
		{
#if 0
			assert(!memcmp(conn->pair_secconn.Eb, buf, 16));
#else
			if (memcmp(conn->pair_secconn.Eb, buf, 16))
			{
				dprintf("%s", "DEBUG: Secure connection Eb is wrong.\n");
			}
#endif
		}
	}
}

//--------------------------------------------
static void ble_session_key_generate(ble_conn_t *conn)
{
	if (conn->pair_method == BLE_LEGACY_PAIRING && !conn->ediv[0] && !conn->ediv[1])
	{
		ble_sk(conn->pair_legacy.stk, conn->skds, conn->skdm, conn->session_key);
	}
	else
	{
		ble_sk(ltk, conn->skds, conn->skdm, conn->session_key);
	}
}

//--------------------------------------------
// Bluetooth core specification:             NIST Special Publication 800-38C:
// Message Integrity Check (MIC)        <=>  Message Authentication Code (MAC)
// Additional authenticated data (AAD)  <=>  Associated data
static int ble_packet_decrypt(ble_conn_t *conn, uint8_t *buf, size_t *size)
{
	static uint8_t pdu_buf[MAXIMUM_PDU_AES_BUFFER_LENGTH];
	uint8_t nonce[NONCE_LENGTH];
	uint8_t associated_data[1];
	uint8_t cp_flag;
	uint8_t header_flags;
	uint8_t pdu_len;
	int res;

	header_flags = buf[ACCESS_ADDRESS_LENGTH];
	cp_flag = header_flags & CP_MASK ? 1 : 0;
	// Payload includes MIC (MAC)
	pdu_len = buf[ACCESS_ADDRESS_LENGTH + 1];
	if (pdu_len <= MIC_LENGTH)
	{
		return -1;
	}

	// Nonce
	nonce[0] = conn->current_packet_direction == DIR_MASTER_SLAVE ?
		(uint8_t)(conn->master_encrypted_packet_counter) :
		(uint8_t)(conn->slave_encrypted_packet_counter);
	nonce[1] = conn->current_packet_direction == DIR_MASTER_SLAVE ?
		(uint8_t)(conn->master_encrypted_packet_counter >> 8) :
		(uint8_t)(conn->slave_encrypted_packet_counter >> 8);
	nonce[2] = conn->current_packet_direction == DIR_MASTER_SLAVE ?
		(uint8_t)(conn->master_encrypted_packet_counter >> 16) :
		(uint8_t)(conn->slave_encrypted_packet_counter >> 16);
	nonce[3] = conn->current_packet_direction == DIR_MASTER_SLAVE ?
		(uint8_t)(conn->master_encrypted_packet_counter >> 24) :
		(uint8_t)(conn->slave_encrypted_packet_counter >> 24);
	nonce[4] = conn->current_packet_direction == DIR_MASTER_SLAVE ?
		((uint8_t)(conn->master_encrypted_packet_counter >> 32) & 0x7F) | 0x80 :
		((uint8_t)(conn->slave_encrypted_packet_counter >> 32) & 0x7F);
	memcpy(&nonce[5], conn->iv, sizeof(conn->iv));

	// AAD (associated data)
	associated_data[0] = header_flags & 0xE3;

	// Decryption
	res = ble_ccm(conn->session_key, nonce, associated_data, &buf[HDR_LENGTH + cp_flag], pdu_len, pdu_buf);

	// Verification
	if (!res)
	{
		// Payload change
		uint32_t crc_calc;

		buf[ACCESS_ADDRESS_LENGTH + 1] -= MIC_LENGTH;
		memcpy(&buf[HDR_LENGTH + cp_flag], pdu_buf, pdu_len);
		crc_calc = ble_crc_gen(bits_reverse(conn->crc_init) >> 8, &buf[ACCESS_ADDRESS_LENGTH], pdu_len + MINIMUM_HEADER_LENGTH + cp_flag);
		*size -= MIC_LENGTH;
		buf[*size - 3] = (uint8_t)crc_calc;
		buf[*size - 2] = (uint8_t)(crc_calc >> 8);
		buf[*size - 1] = (uint8_t)(crc_calc >> 16);
		return 0;
	}
	return -1;
}

//--------------------------------------------
static void csa_identify(ble_conn_t *conn)
{
	list_adv_t *item;
	if ((item = list_adv_find_addr(&adv_devs, conn->ra)) == NULL)
	{
		assert(0);
		return;
	}
	if (conn->csa && item->csa)
	{
		// csa #2
		conn->csa = 1;
	}
	else
	{
		// csa #1
		conn->csa = 0;
		conn->unmapped_channel = 0;
	}
}

//--------------------------------------------
static void channel_map_update(ble_conn_t *conn)
{
	uint8_t ch;
	uint32_t access_address;

	conn->used_channels_number = 0;
	for (ch = 0; ch < DATA_CHANNELS_NUMBER; ch++)
	{
		if (conn->channel_map[ch / 8] & (1 << ch % 8))
		{
			conn->channel_remapping_table[conn->used_channels_number++] = ch;
		}
	}

	// data_access_address in conn reversed, i.e. low byte is the first etc.
	access_address = (conn->data_access_address[3] << 24) | (conn->data_access_address[2] << 16) |
		(conn->data_access_address[1] << 8) | (conn->data_access_address[0]);
	conn->channel_identifier = (access_address >> 16) ^ (access_address & 0xFFFF);
}

//--------------------------------------------
static uint16_t csa2_permute(uint16_t v)
{
	v = (((v & 0xAAAA) >> 1) | ((v & 0x5555) << 1));
	v = (((v & 0xCCCC) >> 2) | ((v & 0x3333) << 2));
	return (((v & 0xF0F0) >> 4) | ((v & 0x0F0F) << 4));
}

//--------------------------------------------
static uint16_t csa2_mam(uint16_t a, uint16_t b)
{
	return (17 * a + b) % (0x10000);
}

//--------------------------------------------
static uint16_t csa2_prng(uint16_t counter, uint16_t chanid)
{
	uint16_t prn_e;

	prn_e = counter ^ chanid;
	prn_e = csa2_mam(csa2_permute(prn_e), chanid);
	prn_e = csa2_mam(csa2_permute(prn_e), chanid);
	prn_e = csa2_mam(csa2_permute(prn_e), chanid);
	return prn_e ^ chanid;
}

//--------------------------------------------
static void used_channel_update(ble_conn_t *conn)
{
	if (!conn->first_window)
	{
		// close previous connection event
		conn->connection_event_counter++;
	}

	if (!conn->csa)
	{
		// csa #1
		conn->unmapped_channel = (conn->unmapped_channel + conn->hop) % DATA_CHANNELS_NUMBER;
		if (!(conn->channel_map[conn->unmapped_channel / 8] & (1 << conn->unmapped_channel % 8)))
		{
			conn->used_channel = conn->channel_remapping_table[conn->unmapped_channel % conn->used_channels_number];
		}
		else
		{
			conn->used_channel = conn->unmapped_channel;
		}
	}
	else
	{
		// csa #2
		uint16_t prn_e;

		prn_e = csa2_prng(conn->connection_event_counter, conn->channel_identifier);
		conn->used_channel = prn_e % DATA_CHANNELS_NUMBER;
		if (!(conn->channel_map[conn->used_channel / 8] & (1 << conn->used_channel % 8)))
		{
			conn->used_channel = conn->channel_remapping_table[(((uint32_t)conn->used_channel) * (uint32_t)prn_e) >> 16];
		}
	}
}

//--------------------------------------------
static ble_packet_decode_res_t packet_decode(ble_info_t *info, uint8_t recursion)
{
	uint8_t header_flags;
	uint8_t header_length;
	uint8_t cp_flag;
	uint32_t crc_calc;
	uint32_t crc_recv;
	size_t packet_length;
	uint8_t *buf;
	static uint8_t buf_smp[MAXIMUM_SMP_PACKET_LENGTH];
	static size_t buf_l2cap_length;
	static size_t buf_smp_length;
	static size_t buf_packet_length;

	assert(info);
	assert(info->buf);
	assert(info->size);

	buf = info->buf;
	packet_length = info->size;

	if (!recursion)
	{
		// for original packets only (not for a recursive function call)
		info->counter_total = ++total_packet_counter;
		conn.previous_packet_transmission_time = conn.current_packet_transmission_time;
		conn.current_packet_transmission_time = ble_packet_transmission_time_us_calc(info);

		if (!info->delta_time)
		{
			// if the sniffer or pcap file do not provide the delta_time, then calculate it here
			info->delta_time = conn.previous_packet_start_timestamp ?
				(uint32_t)(info->timestamp - conn.previous_packet_start_timestamp - conn.previous_packet_transmission_time) : 0;
		}
		conn.previous_packet_start_timestamp = info->timestamp;
	}
	
	if (packet_length < MINIMUM_PACKET_LENGTH)
	{
		return PACKET_NOT_PROCESSED;
	}

	if (!memcmp(buf, adv_channel_access_address, ACCESS_ADDRESS_LENGTH))
	{
		// advertising channel packet
		info->pdu = PDU_ADV;
		header_flags = buf[ACCESS_ADDRESS_LENGTH];
		header_length = buf[ACCESS_ADDRESS_LENGTH + 1];

		info->counter_conn = 0;

		// packet length checking
		if (packet_length != MINIMUM_PACKET_LENGTH + header_length)
		{
			// corrupted packet
			return PACKET_NOT_PROCESSED;
		}

		if (info->status_crc == CHECK_UNKNOWN)
		{
			// CRC checking
			crc_calc = ble_crc_gen(bits_reverse(ADV_CHANNEL_CRC_INIT) >> 8,
				buf + ACCESS_ADDRESS_LENGTH,
				packet_length - CRC_LENGTH - ACCESS_ADDRESS_LENGTH);
			crc_recv = (buf[packet_length - 3]) | (buf[packet_length - 2] << 8) | (buf[packet_length - 1] << 16);
			info->status_crc = (crc_recv != crc_calc) ? CHECK_FAIL : CHECK_OK;
		}
		if (info->status_crc == CHECK_FAIL)
		{
			// corrupted packet
			return PACKET_NOT_PROCESSED;
		}

		switch (header_flags & PDU_TYPE_MASK)
		{
		case ADV_IND:
		{
			uint8_t adv_addr[DEVICE_ADDRESS_LENGTH];
			memcpy_reverse(adv_addr, &buf[HDR_LENGTH], DEVICE_ADDRESS_LENGTH);
			list_adv_add_replace(&adv_devs, adv_addr, header_flags & CSA_MASK ? 1 : 0, header_flags & TXADD_MASK ? 1 : 0);
			break;
		}
		case CONNECT_REQ:
			if (header_length != CONNECT_REQ_PDU_LENGTH)
			{
				// corrupted packet
				return PACKET_NOT_PROCESSED;
			}
			memset(&conn, 0, sizeof(ble_conn_t));
			memcpy(conn.data_access_address, &buf[CONNECT_REQ_LL_DATA], ACCESS_ADDRESS_LENGTH);
			conn.csa = header_flags & CSA_MASK ? 1 : 0;
			conn.iat = header_flags & TXADD_MASK ? 1 : 0;
			conn.rat = header_flags & RXADD_MASK ? 1 : 0;
			memcpy_reverse(conn.ia, &buf[HDR_LENGTH], DEVICE_ADDRESS_LENGTH);
			memcpy_reverse(conn.ra, &buf[HDR_LENGTH + DEVICE_ADDRESS_LENGTH], DEVICE_ADDRESS_LENGTH);
			csa_identify(&conn);
			conn.crc_init = (buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH]) |
				(buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 1] << 8) |
				(buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 2] << 16);
			conn.time_cfg.win_size = buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 3] * CONNECT_REQ_TIME_UNIT;
			conn.time_cfg.win_offset = (buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 4] |
				(buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 5] << 8))
				* CONNECT_REQ_TIME_UNIT;
			conn.time_cfg.interval = (buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 6] |
				(buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 7] << 8))
				* CONNECT_REQ_TIME_UNIT;
			conn.time_cfg.latency = (buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 8] |
				(buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 9] << 8));
			memcpy(conn.channel_map, &buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 12], DATA_CHANNELS_BYTES_NUMBER);
			channel_map_update(&conn);
			conn.hop = buf[CONNECT_REQ_LL_DATA + ACCESS_ADDRESS_LENGTH + 12 + DATA_CHANNELS_BYTES_NUMBER] & HOP_MASK;
			conn.first_window = 1;
			used_channel_update(&conn);
			conn.anchor_point = info->timestamp;
			conn.current_packet_direction = DIR_MASTER_SLAVE;
			msg_to_cli_add_print_command("%s", "Connection created.\n");
			msg_to_cli_add_print_command("Channel selection algorithm #%d detected.\n", (conn.csa == 1) ? 2 : 1);
			break;
		default:
#if 0
			assert(0);
#endif
			break;
		}
	}
	else if (conn.anchor_point)
	{
		// process data channel packet only after CONNECT_REQ event 
		uint8_t more_data;

		info->pdu = PDU_DATA;

		// packet length checking
		header_flags = buf[ACCESS_ADDRESS_LENGTH];
		header_length = buf[ACCESS_ADDRESS_LENGTH + 1];
		cp_flag = header_flags & CP_MASK ? 1 : 0;
		more_data = header_flags & MORE_DATA_MASK ? 1 : 0;

		// Reading and analysis of SN and NESN are not performed, since
		// it is not clear how to handle retransmissions in the general case.
		// Repeated packets are processed as necessary at the next levels, see, for example,
		// checking the call to the secure_connection_passkey_bit_check function
		// when the SMP_PAIRING_RANDOM command is detected.

		if (packet_length != MINIMUM_PACKET_LENGTH + cp_flag + header_length)
		{
			// corrupted packet
			return PACKET_NOT_PROCESSED;
		}

		// data channel packet
		if (memcmp(buf, conn.data_access_address, ACCESS_ADDRESS_LENGTH))
		{
			// someone else's packet
			return PACKET_NOT_PROCESSED;
		}

		if (!recursion)
		{
			// for original packets only (not for a recursive function call)
			// first it is absolutely needed to establish or to confirm the packet direction
			conn.previous_packet_direction = conn.current_packet_direction;
			if (conn.first_window)
			{
				if (info->dir != DIR_UNKNOWN)
				{
					assert(info->dir == DIR_MASTER_SLAVE);
				}
				conn.anchor_point = info->timestamp;
				conn.first_window = 0;
				msg_to_cli_add_print_command("%s", "Connection established.\n");
			}
			else
			{
				uint64_t window_size;
				window_size = conn.time_cfg.interval - T_WIN_MAX_DRIFT;
				if (info->timestamp - conn.anchor_point > window_size)
				{
					size_t event_cnt_quotient;
					size_t event_cnt_remainder;
					size_t cnt;
					event_cnt_quotient = (size_t)((info->timestamp - conn.anchor_point) / conn.time_cfg.interval);
					event_cnt_remainder = (size_t)((info->timestamp - conn.anchor_point) % conn.time_cfg.interval);
					if (event_cnt_remainder < T_WIN_MAX_DRIFT + T_IFS + T_IFS_MAX_DRIFT)
					{
						event_cnt_quotient--;
						if (event_cnt_remainder < T_WIN_MAX_DRIFT)
						{
							conn.anchor_point = info->timestamp;
							conn.current_packet_direction = DIR_MASTER_SLAVE;
						}
						else
						{
							dprintf("DEBUG: M->S data packet missed. Packet number %d\n", total_packet_counter);
							conn.anchor_point = info->timestamp - T_IFS - T_IFS_MAX_DRIFT;
							conn.current_packet_direction = DIR_SLAVE_MASTER;
						}
					}
					else
					{
						conn.anchor_point = info->timestamp;
						conn.current_packet_direction = DIR_MASTER_SLAVE;
					}
					if (event_cnt_quotient > 0)
					{
						dprintf("DEBUG: M->S and possibly S->M %d data packet(s) missed. Packet number %d\n", event_cnt_quotient, total_packet_counter);
					}
					for (cnt = 0; cnt <= event_cnt_quotient; cnt++)
					{
						if (conn.channel_map_update_instant && conn.channel_map_update_instant == conn.connection_event_counter)
						{
							memcpy(&conn.channel_map, &conn.channel_map_update, DATA_CHANNELS_BYTES_NUMBER);
							channel_map_update(&conn);
							conn.channel_map_update_instant = 0;
						}
						used_channel_update(&conn);
					}
					if (info->dir != DIR_UNKNOWN)
					{
#if 0
						assert(info->dir == conn.current_packet_direction);
#else
						if (info->dir != conn.current_packet_direction)
						{
							dprintf("DEBUG: info->dir = %d, conn.current_packet_direction = %d. Packet number %d. Line %d\n",
								info->dir,
								conn.current_packet_direction,
								total_packet_counter,
								__LINE__);
						}
#endif
					}
				}
				else
				{
					if (info->delta_time < T_IFS + T_IFS_MAX_DRIFT)
					{
						if (conn.previous_packet_direction == DIR_MASTER_SLAVE)
						{
							conn.current_packet_direction = DIR_SLAVE_MASTER;
							if (info->dir != DIR_UNKNOWN)
							{
#if 0
								assert(info->dir == conn.current_packet_direction);
#else
								if (info->dir != conn.current_packet_direction)
								{
									dprintf("DEBUG: info->dir = %d, conn.current_packet_direction = %d. Packet number %d. Line %d\n",
										info->dir,
										conn.current_packet_direction,
										total_packet_counter,
										__LINE__);
								}
#endif
							}
							if (conn.time_cfg_update_instant && conn.time_cfg_update_instant == conn.connection_event_counter)
							{
								memcpy(&conn.time_cfg, &conn.time_cfg_update, sizeof(ble_time_cfg_t));
								conn.time_cfg_update_instant = 0;
							}
						}
						else if (conn.previous_packet_direction == DIR_SLAVE_MASTER)
						{
							if (conn.master_more_data || conn.slave_more_data)
							{
								conn.current_packet_direction = DIR_MASTER_SLAVE;
								if (info->dir != DIR_UNKNOWN)
								{
#if 0
									assert(info->dir == conn.current_packet_direction);
#else
									if (info->dir != conn.current_packet_direction)
									{
										dprintf("DEBUG: info->dir = %d, conn.current_packet_direction = %d. Packet number %d. Line %d\n",
											info->dir,
											conn.current_packet_direction,
											total_packet_counter,
											__LINE__);
									}
#endif
								}
							}
							else
							{
								// unknown
								dprintf("DEBUG: Wrong(1) data packet in the same interval. Delta time %d us. Packet number %d\n", info->delta_time, total_packet_counter);
								if (info->dir == DIR_UNKNOWN)
								{
									conn.current_packet_direction = DIR_UNKNOWN;
									return PACKET_NOT_PROCESSED;
								}
								else
								{
									conn.current_packet_direction = info->dir;
								}
							}
						}
						else
						{
							// unknown
							dprintf("DEBUG: Wrong(2) data packet in the same interval. Delta time %d us. Packet number %d\n", info->delta_time, total_packet_counter);
							if (info->dir == DIR_UNKNOWN)
							{
								conn.current_packet_direction = DIR_UNKNOWN;
								return PACKET_NOT_PROCESSED;
							}
							else
							{
								conn.current_packet_direction = info->dir;
							}
						}
					}
					else
					{
						// unknown
						dprintf("DEBUG: Wrong(3) data packet in the same interval. Delta time %d us. Packet number %d\n", info->delta_time, total_packet_counter);
						if (info->dir == DIR_UNKNOWN)
						{
							conn.current_packet_direction = DIR_UNKNOWN;
							return PACKET_NOT_PROCESSED;
						}
						else
						{
							conn.current_packet_direction = info->dir;
						}
					}
				}
			}

			if (info->dir == DIR_UNKNOWN)
			{
				// if the sniffer or pcap file does not provide the packet direction, use calculated one
				info->dir = conn.current_packet_direction;
			}
			else
			{
				// if the sniffer or pcap file does provide the packet direction, always use it
				conn.current_packet_direction = info->dir;
			}

			if (info->channel == -1)
			{
				// if the sniffer or pcap file does not provide the channel number, use calculated one
				info->channel = conn.used_channel;
			}
			if (!info->counter_conn)
			{
				// if the sniffer or pcap file does not provide the connection event counter, use calculated one
				info->counter_conn = conn.connection_event_counter;
			}

#if 0
			assert(info->channel == conn.used_channel);
			assert(info->counter_conn == conn.connection_event_counter);
#else
			if (info->channel != conn.used_channel)
			{
				dprintf("DEBUG: info->channel = %d, conn.used_channel = %d. Packet number %d\n",
					info->channel,
					conn.used_channel,
					total_packet_counter);
			}
			if (info->counter_conn != conn.connection_event_counter)
			{
				dprintf("DEBUG: info->counter_conn = %d, conn.connection_event_counter = %d. Packet number %d\n",
					info->counter_conn,
					conn.connection_event_counter,
					total_packet_counter);
			}
#endif

			if (conn.current_packet_direction == DIR_SLAVE_MASTER)
			{
				conn.slave_more_data = more_data;
				if (more_data)
				{
					dprintf("DEBUG: S->M packet with More Data flag. Packet number %d\n", total_packet_counter);
				}
			}

			if (conn.current_packet_direction == DIR_MASTER_SLAVE)
			{
				conn.master_more_data = more_data;
				if (more_data)
				{
					dprintf("DEBUG: M->S packet with More Data flag. Packet number %d\n", total_packet_counter);
				}
			}
		}

		if (info->status_crc == CHECK_UNKNOWN)
		{
			// CRC checking
			crc_calc = ble_crc_gen(bits_reverse(conn.crc_init) >> 8,
				&buf[ACCESS_ADDRESS_LENGTH + cp_flag],
				packet_length - CRC_LENGTH - ACCESS_ADDRESS_LENGTH);
			crc_recv = (buf[packet_length - 3]) | (buf[packet_length - 2] << 8) | (buf[packet_length - 1] << 16);
			info->status_crc = (crc_recv != crc_calc) ? CHECK_FAIL : CHECK_OK;
		}
		if (info->status_crc == CHECK_FAIL)
		{
			// corrupted packet
			if (conn.encrypted_packet && conn.current_packet_direction != conn.previous_packet_direction)
			{
				info->status_enc = ENC_ENCRYPTED;
				// increment packet counter excluding retransmitted packets
				if (conn.current_packet_direction == DIR_MASTER_SLAVE)
				{
					conn.master_encrypted_packet_counter++;
				}
				else
				{
					conn.slave_encrypted_packet_counter++;
				}
			}
			return PACKET_NOT_PROCESSED;
		}

		// empty PDU checking
		if (((header_flags & LLID_MASK) == LL_DATA_FRAG_PDU) && header_length == 0)
		{
			// empty PDU
			return PACKET_PROCESSED;
		}

		if (!recursion && conn.encrypted_packet)
		{
			// for original packets only (not for a recursive function call)
			// (conn.encrypted_packet == 1) The original packet is(was) encrypted ...
			uint64_t *enc_cnt;
			enc_cnt = conn.current_packet_direction == DIR_MASTER_SLAVE ?
				&conn.master_encrypted_packet_counter :
				&conn.slave_encrypted_packet_counter;

			if ((info->status_enc == ENC_ENCRYPTED && info->status_mic == CHECK_FAIL) || info->status_enc == ENC_UNKNOWN)
			{
				// (info->status_enc == ENC_ENCRYPTED && info->status_mic == CHECK_FAIL) ... and nRF Sniffer could not decrypt it ...
				// (info->status_enc == ENC_UNKNOWN) ... while others did not even try ...
				// ... so try here

#if 0
				if (info->status_enc == ENC_ENCRYPTED && info->status_mic == CHECK_FAIL)
				{
					// but, unfortunately, nRF Sniffer corrupts the original payload if it cannot decrypt,
					// so no chance to decrypt here
					return PACKET_NOT_PROCESSED;
				}
#endif

				// decryption
				if (ble_packet_decrypt(&conn, info->buf, &info->size) < 0)
				{
					size_t cnt;
					pkt_dir_t current_packet_direction = conn.current_packet_direction;
					uint64_t master_encrypted_packet_counter = conn.master_encrypted_packet_counter;
					uint64_t slave_encrypted_packet_counter = conn.slave_encrypted_packet_counter;
					(*enc_cnt)--;
					for (cnt = 0; cnt < DECRYPTION_ATTEMPTS_NUMBER; cnt++)
					{
						if (!ble_packet_decrypt(&conn, info->buf, &info->size))
						{
							break;
						}
						(*enc_cnt)++;
					}
					if (cnt == DECRYPTION_ATTEMPTS_NUMBER)
					{
						// unsuccessful decryption
						if (current_packet_direction == DIR_MASTER_SLAVE)
						{
							conn.master_encrypted_packet_counter = master_encrypted_packet_counter;
							conn.current_packet_direction = DIR_SLAVE_MASTER;
						}
						else
						{
							conn.slave_encrypted_packet_counter = slave_encrypted_packet_counter;
							conn.current_packet_direction = DIR_MASTER_SLAVE;
						}
						enc_cnt = conn.current_packet_direction == DIR_MASTER_SLAVE ?
							&conn.master_encrypted_packet_counter :
							&conn.slave_encrypted_packet_counter;
						(*enc_cnt)--;
						for (cnt = 0; cnt < DECRYPTION_ATTEMPTS_NUMBER; cnt++)
						{
							if (!ble_packet_decrypt(&conn, info->buf, &info->size))
							{
								break;
							}
							(*enc_cnt)++;
						}
						conn.current_packet_direction = current_packet_direction;
						if (cnt == DECRYPTION_ATTEMPTS_NUMBER)
						{
							// unsuccessful decryption
							info->status_enc = ENC_ENCRYPTED;
							info->status_mic = CHECK_FAIL;
							return PACKET_NOT_PROCESSED;
						}
					}
					info->dir = conn.current_packet_direction;
				}
				// increment encrypted packet counter
				(*enc_cnt)++;

				// recursion for decrypted packet
				info->status_enc = ENC_DECRYPTED;
				info->status_mic = CHECK_OK;
				return packet_decode(info, 1);
			}
			else
			{
				// ... and already decrypted
				// increment encrypted packet counter
				(*enc_cnt)++;
			}
		}

		if (info->status_enc == ENC_UNKNOWN)
		{
			info->status_enc = ENC_UNENCRYPTED;
		}

		// unencrypted or decrypted packet
		// the packet may be unencrypted or already decrypted by this function or nRF Sniffer

		switch (header_flags & LLID_MASK)
		{
		case LL_CONTROL_PDU:
		{
			switch (buf[HDR_LENGTH + cp_flag])
			{
			case LL_CONNECTION_UPDATE_IND:
				if (header_length != LL_CONNECTION_UPDATE_IND_PDU_LENGTH)
				{
					// corrupted packet
					return PACKET_NOT_PROCESSED;
				}
				conn.time_cfg_update.win_size = buf[HDR_LENGTH + cp_flag + 1] * CONNECT_REQ_TIME_UNIT;
				conn.time_cfg_update.win_offset = (buf[HDR_LENGTH + cp_flag + 2] |
					(buf[HDR_LENGTH + cp_flag + 3] << 8))
					* CONNECT_REQ_TIME_UNIT;
				conn.time_cfg_update.interval = (buf[HDR_LENGTH + cp_flag + 4] |
					(buf[HDR_LENGTH + cp_flag + 5] << 8))
					* CONNECT_REQ_TIME_UNIT;
				conn.time_cfg_update.latency = (buf[HDR_LENGTH + cp_flag + 6] |
					(buf[HDR_LENGTH + cp_flag + 7] << 8));
				conn.time_cfg_update_instant = (buf[HDR_LENGTH + cp_flag + 10] |
					(buf[HDR_LENGTH + cp_flag + 11] << 8));
				dprintf("DEBUG: LL_CONNECTION_UPDATE_IND detected. Packet number %d\n", total_packet_counter);
				break;
			case LL_CHANNEL_MAP_IND:
				if (header_length != LL_CHANNEL_MAP_IND_PDU_LENGTH)
				{
					// corrupted packet
					return PACKET_NOT_PROCESSED;
				}
				memcpy(conn.channel_map_update, &buf[HDR_LENGTH + cp_flag + 1], DATA_CHANNELS_BYTES_NUMBER);
				conn.channel_map_update_instant = (buf[HDR_LENGTH + cp_flag + 6] |
					(buf[HDR_LENGTH + cp_flag + 7] << 8));
				dprintf("DEBUG: LL_CHANNEL_MAP_IND detected. Packet number %d\n", total_packet_counter);
				break;
			case LL_TERMINATE_IND:
				msg_to_cli_add_print_command("%s", "Connection terminated.\n");
				break;
			case LL_ENC_REQ:
				if (header_length != LL_ENC_REQ_PDU_LENGTH)
				{
					// corrupted packet
					return PACKET_NOT_PROCESSED;
				}
				memcpy_reverse(conn.rand,
					&buf[HDR_LENGTH + cp_flag + 1],
					sizeof(conn.rand));
				memcpy_reverse(conn.ediv,
					&buf[HDR_LENGTH + cp_flag + 1 + sizeof(conn.rand)],
					sizeof(conn.ediv));
				memcpy_reverse(conn.skdm,
					&buf[HDR_LENGTH + cp_flag + 1 + sizeof(conn.rand) + sizeof(conn.ediv)],
					sizeof(conn.skdm));
				memcpy(conn.ivm,
					&buf[HDR_LENGTH + cp_flag + 1 + sizeof(conn.rand) + sizeof(conn.ediv) + sizeof(conn.skdm)],
					sizeof(conn.ivm));
				if (conn.pair_method == BLE_LEGACY_PAIRING && !conn.ediv[0] && !conn.ediv[1])
				{
					size_t cnt;
					for (cnt = 0; cnt < sizeof(conn.pair_legacy.stk); cnt++)
					{
						if (conn.pair_legacy.stk[cnt] != 0)
						{
							break;
						}
					}
					if (cnt == sizeof(conn.pair_legacy.stk))
					{
						msg_to_cli_add_print_command("%s", "Encryption request detected, but STK unknown.\n");
					}
				}
				else
				{
					size_t cnt;
					for (cnt = 0; cnt < sizeof(ltk); cnt++)
					{
						if (ltk[cnt] != 0)
						{
							break;
						}
					}
					if (cnt == sizeof(ltk))
					{
						msg_to_cli_add_print_command("%s", "Encryption request detected, but LTK unknown.\n");
						msg_to_cli_add_single_command(CLI_INPUT_LTK);
						return PACKET_PROCESSED_WAIT_CLI_MSG;
					}
				}
				break;
			case LL_ENC_RSP:
				if (header_length != LL_ENC_RSP_PDU_LENGTH)
				{
					// corrupted packet
					return PACKET_NOT_PROCESSED;
				}
				memcpy_reverse(conn.skds,
					&buf[HDR_LENGTH + cp_flag + 1],
					sizeof(conn.skds));
				memcpy(conn.ivs,
					&buf[HDR_LENGTH + cp_flag + 1 + sizeof(conn.skds)],
					sizeof(conn.ivs));
				memcpy(conn.iv, conn.ivm, sizeof(conn.ivm));
				memcpy(&conn.iv[sizeof(conn.ivm)], conn.ivs, sizeof(conn.ivs));
				ble_session_key_generate(&conn);
				break;
			case LL_START_ENC_REQ:
				conn.encrypted_packet = 1;
				msg_to_cli_add_print_command("Encryption start detected. %s used.\n",
					(conn.pair_method == BLE_LEGACY_PAIRING && !conn.ediv[0] && !conn.ediv[1]) ? "STK" : "LTK");
				break;
			case LL_PAUSE_ENC_RSP:
				if (conn.current_packet_direction == DIR_SLAVE_MASTER)
				{
					msg_to_cli_add_print_command("%s", "Encryption end detected.\n");
					conn.encrypted_packet = 0;
					conn.master_encrypted_packet_counter = 0;
					conn.slave_encrypted_packet_counter = 0;
				}
				break;
			default:
				break;
			}
			break;
		}
		case LL_DATA_START_PDU:
		{
			// start of an L2CAP message or a complete L2CAP message with no fragmentation
			uint16_t l2cap_length;
			uint16_t ccid;
			l2cap_length = buf[HDR_LENGTH + cp_flag] | (buf[HDR_LENGTH + cp_flag + 1] << 8);
			ccid = buf[HDR_LENGTH + cp_flag + L2CAP_LENGTH] | (buf[HDR_LENGTH + cp_flag + L2CAP_LENGTH + 1] << 8);
			if (ccid == CID_SMP)
			{
				// Security Manager protocol (SMP)
				switch (buf[SMP_HDR_LENGTH + cp_flag])
				{
				case SMP_PAIRING_REQUEST:
					if (header_length != SMP_PAIRING_REQUEST_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					memcpy_reverse(conn.preq,
						&buf[SMP_HDR_LENGTH + cp_flag],
						SMP_PAIRING_REQUEST_LENGTH);
					conn.iiocap = (ble_io_capability_t)buf[SMP_HDR_LENGTH + cp_flag + 1];
					conn.ioob = buf[SMP_HDR_LENGTH + cp_flag + 2];
					conn.isc = buf[SMP_HDR_LENGTH + cp_flag + 3] & SC_MASK ? 1 : 0;
					conn.imitm = buf[SMP_HDR_LENGTH + cp_flag + 3] & MITM_MASK ? 1 : 0;
					break;
				case SMP_PAIRING_RESPONSE:
					if (header_length != SMP_PAIRING_RESPONSE_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					memcpy_reverse(conn.pres,
						&buf[SMP_HDR_LENGTH + cp_flag],
						SMP_PAIRING_RESPONSE_LENGTH);
					conn.riocap = (ble_io_capability_t)buf[SMP_HDR_LENGTH + cp_flag + 1];
					conn.roob = buf[SMP_HDR_LENGTH + cp_flag + 2];
					conn.rsc = buf[SMP_HDR_LENGTH + cp_flag + 3] & SC_MASK ? 1 : 0;
					conn.rmitm = buf[SMP_HDR_LENGTH + cp_flag + 3] & MITM_MASK ? 1 : 0;
					if (conn.isc == 1 && conn.rsc == 1)
					{
						conn.pair_method = BLE_SECURE_CONNECTION;
						memset(&conn.pair_secconn, 0, sizeof(conn.pair_secconn));
						msg_to_cli_add_print_command("%s", "BLE Secure Connection method detected.\n");
					}
					else
					{
						conn.pair_method = BLE_LEGACY_PAIRING;
						memset(&conn.pair_legacy, 0, sizeof(conn.pair_legacy));
						msg_to_cli_add_print_command("%s", "BLE Legacy pairing method detected.\n");
					}
					conn.assoc_model = mapping_io_capabilities_to_association_model(&conn);
					switch (conn.assoc_model)
					{
					case BLE_JUST_WORKS:
						msg_to_cli_add_print_command("%s", "Just Works association model used.\n");
						break;
					case BLE_PASSKEY_ENTRY:
						msg_to_cli_add_print_command("%s", "Passkey Entry association model used.\n");
						if (conn.pair_method == BLE_LEGACY_PAIRING)
						{
							msg_to_cli_add_single_command(CLI_INPUT_PASSKEY);
							return PACKET_PROCESSED_WAIT_CLI_MSG;
						}
						break;
					case BLE_OUT_OF_BAND:
						msg_to_cli_add_print_command("%s", "Out Of Band association model used.\n");
						if (conn.pair_method == BLE_LEGACY_PAIRING)
						{
							msg_to_cli_add_single_command(CLI_INPUT_OOB_KEY);
							return PACKET_PROCESSED_WAIT_CLI_MSG;
						}
						break;
					case BLE_NUMERIC_COMPARISON:
						msg_to_cli_add_print_command("%s", "Numeric Comparison association model used.\n");
						break;
					case BLE_ASSOCIATION_MODEL_UNDEFINED:
						msg_to_cli_add_print_command("%s", "Unknown association model used.\n");
						assert(0);
						break;
					}
					break;
				case SMP_PAIRING_CONFIRM:
					if (header_length != SMP_PAIRING_CONFIRM_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					if (conn.pair_method == BLE_LEGACY_PAIRING)
					{
						if (conn.current_packet_direction == DIR_MASTER_SLAVE)
						{
							memcpy_reverse(conn.pair_legacy.mconfirm,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH);
						}
						else
						{
							memcpy_reverse(conn.pair_legacy.sconfirm,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH);
						}
#if 0
						// just to test the function
						legacy_pairing_rand_generate(&conn);
#endif
					}
					else if (conn.pair_secconn.debug_mode)
					{
						if (conn.assoc_model == BLE_JUST_WORKS || conn.assoc_model == BLE_NUMERIC_COMPARISON)
						{
							if (conn.current_packet_direction == DIR_SLAVE_MASTER)
							{
								memcpy_reverse(conn.pair_secconn.Cb,
									&buf[SMP_HDR_LENGTH + cp_flag + 1],
									AES128_BLOCK_LENGTH);
							}
						}
						else if (conn.assoc_model == BLE_PASSKEY_ENTRY)
						{
							if (conn.current_packet_direction == DIR_MASTER_SLAVE)
							{
								memcpy_reverse(conn.pair_secconn.Ca,
									&buf[SMP_HDR_LENGTH + cp_flag + 1],
									AES128_BLOCK_LENGTH);
							}
							else
							{
								memcpy_reverse(conn.pair_secconn.Cb,
									&buf[SMP_HDR_LENGTH + cp_flag + 1],
									AES128_BLOCK_LENGTH);
							}
						}
					}
					break;
				case SMP_PAIRING_RANDOM:
					if (header_length != SMP_PAIRING_RANDOM_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					if (conn.pair_method == BLE_LEGACY_PAIRING)
					{
						if (conn.current_packet_direction == DIR_MASTER_SLAVE)
						{
							uint32_t pass_cnt;

							if (conn.assoc_model == BLE_JUST_WORKS)
							{
								memset(conn.pair_legacy.tk, 0, AES128_BLOCK_LENGTH);
							}

							memcpy_reverse(conn.pair_legacy.mrand,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH);

							if (conn.assoc_model == BLE_PASSKEY_ENTRY && conn.use_brute_force)
							{
								memset(conn.pair_legacy.tk, 0, AES128_BLOCK_LENGTH);
								msg_to_cli_add_print_command("%s", "Please wait. Brute force method will be used to find the Passkey.\n");
								for (pass_cnt = 0; pass_cnt <= 999999; pass_cnt++)
								{
									conn.pair_legacy.tk[15] = (uint8_t)(pass_cnt);
									conn.pair_legacy.tk[14] = (uint8_t)(pass_cnt >> 8);
									conn.pair_legacy.tk[13] = (uint8_t)(pass_cnt >> 16);
									conn.pair_legacy.tk[12] = (uint8_t)(pass_cnt >> 24);
									if (!legacy_pairing_confirm_generate_and_compare(&conn))
									{
										break;
									}
								}
								if (pass_cnt <= 999999)
								{
									msg_to_cli_add_print_command("The entered Passkey found: %d\n", pass_cnt);
								}
								else
								{
									msg_to_cli_add_print_command("%s", "The Passkey not found. Possibly another pairing method is used.\n");
								}
							}
						}
						else
						{
							memcpy_reverse(conn.pair_legacy.srand,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH);

							if (legacy_pairing_confirm_generate_and_compare(&conn))
							{
#if 0
								assert(0);
#else
								dprintf("DEBUG: Legacy pairing sconfirm value is wrong. Packet number %d\n",
									total_packet_counter);
#endif
							}

							legacy_pairing_stk_generate(&conn);
							msg_to_cli_add_print_command("STK found: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
								conn.pair_legacy.stk[0], conn.pair_legacy.stk[1], conn.pair_legacy.stk[2], conn.pair_legacy.stk[3],
								conn.pair_legacy.stk[4], conn.pair_legacy.stk[5], conn.pair_legacy.stk[6], conn.pair_legacy.stk[7],
								conn.pair_legacy.stk[8], conn.pair_legacy.stk[9], conn.pair_legacy.stk[10], conn.pair_legacy.stk[11],
								conn.pair_legacy.stk[12], conn.pair_legacy.stk[13], conn.pair_legacy.stk[14], conn.pair_legacy.stk[15]);
						}
					}
					else if (conn.pair_secconn.debug_mode)
					{
						if (conn.current_packet_direction == DIR_MASTER_SLAVE)
						{
							memcpy_reverse(conn.pair_secconn.Na,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH);
#if SC_OOB_TEST
							if (conn.assoc_model == BLE_OUT_OF_BAND)
							{
								secure_connection_oob_check(&conn, 1);
								break;
							}
#endif
						}
						else
						{
							if (memcmp_reverse(conn.pair_secconn.Nb,
								&buf[SMP_HDR_LENGTH + cp_flag + 1],
								AES128_BLOCK_LENGTH) < 0)
							{
								// not retransmitted packet
								memcpy_reverse(conn.pair_secconn.Nb,
									&buf[SMP_HDR_LENGTH + cp_flag + 1],
									AES128_BLOCK_LENGTH);
								switch (conn.assoc_model)
								{
								case BLE_JUST_WORKS:
								case BLE_NUMERIC_COMPARISON:
									secure_connection_number_check(&conn);
									break;
								case BLE_PASSKEY_ENTRY:
									secure_connection_passkey_bit_check(&conn);
									break;
								case BLE_OUT_OF_BAND:
#if SC_OOB_TEST
									secure_connection_oob_check(&conn, 0);
#endif
									secure_connection_mackey_ltk_generate(&conn);
									break;
								case BLE_ASSOCIATION_MODEL_UNDEFINED:
									assert(0);
									break;
								}
							}
						}
					}
					break;
				case SMP_ENCRYPTION_INFORMATION:
					if (header_length != SMP_ENCRYPTION_INFORMATION_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					if (conn.current_packet_direction == DIR_SLAVE_MASTER)
					{
						memcpy_reverse(ltk,
							&buf[SMP_HDR_LENGTH + cp_flag + 1],
							AES128_BLOCK_LENGTH);
						msg_to_cli_add_print_command("LTK found: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							ltk[0], ltk[1], ltk[2], ltk[3], ltk[4], ltk[5], ltk[6], ltk[7],
							ltk[8], ltk[9], ltk[10], ltk[11], ltk[12], ltk[13], ltk[14], ltk[15]);
					}
					break;
				case SMP_PAIRING_PUBLIC_KEY:
					if (header_length != SMP_PAIRING_PUBLIC_KEY_PDU_LENGTH)
					{
						if (header_length < l2cap_length)
						{
							// start of message
							buf_l2cap_length = l2cap_length + L2CAP_LENGTH + CCID_LENGTH;
							buf_smp_length = header_length;
							buf_packet_length = packet_length - CRC_LENGTH;
							memcpy(buf_smp, buf, buf_packet_length);
							break;
						}
						return PACKET_NOT_PROCESSED;
					}
					if (conn.current_packet_direction == DIR_MASTER_SLAVE)
					{
						memcpy_reverse(conn.pair_secconn.PKax,
							&buf[SMP_HDR_LENGTH + cp_flag + 1],
							32);
						memcpy_reverse(conn.pair_secconn.PKay,
							&buf[SMP_HDR_LENGTH + cp_flag + 1 + 32],
							32);
					}
					else
					{
						memcpy_reverse(conn.pair_secconn.PKbx,
							&buf[SMP_HDR_LENGTH + cp_flag + 1],
							32);
						memcpy_reverse(conn.pair_secconn.PKby,
							&buf[SMP_HDR_LENGTH + cp_flag + 1 + 32],
							32);
						secure_connection_debug_mode_detect(&conn);
					}
					break;
#if 1
				case SMP_PAIRING_DHKEY_CHECK:
					// just to test the function
					if (header_length != SMP_PAIRING_DHKEY_CHECK_PDU_LENGTH)
					{
						return PACKET_NOT_PROCESSED;
					}
					if (conn.current_packet_direction == DIR_MASTER_SLAVE)
					{
						memcpy_reverse(conn.pair_secconn.Ea,
							&buf[SMP_HDR_LENGTH + cp_flag + 1],
							16);
					}
					else
					{
						memcpy_reverse(conn.pair_secconn.Eb,
							&buf[SMP_HDR_LENGTH + cp_flag + 1],
							16);
					}
					secure_connection_check_value_generate(&conn);
					break;
#endif
				default:
					break;
				}
			}
			break;
		}
		case LL_DATA_FRAG_PDU:
			if (buf_packet_length)
			{
				if (buf_smp_length + header_length <= buf_l2cap_length)
				{
					memcpy(&buf_smp[buf_packet_length], &buf[HDR_LENGTH + cp_flag], header_length);
					buf_packet_length += header_length;
					buf_smp_length += header_length;
					if (buf_smp_length == buf_l2cap_length)
					{
						uint8_t *buf_orig = info->buf;
						size_t size_orig = info->size;
						buf_smp[ACCESS_ADDRESS_LENGTH + 1] = (uint8_t)buf_l2cap_length;
						info->buf = buf_smp;
						info->size = buf_packet_length + CRC_LENGTH;
						packet_decode(info, 1);
						info->buf = buf_orig;
						info->size = size_orig;
						buf_packet_length = 0;
						buf_smp_length = 0;
						buf_l2cap_length = 0;
					}
				}
			}
			break;
		default:
			break;
		}
		return PACKET_PROCESSED;
	}
	return PACKET_NOT_PROCESSED;
}

//--------------------------------------------
ble_packet_decode_res_t ble_packet_decode(ble_info_t *info)
{
	return packet_decode(info, 0);
}
	
//--------------------------------------------
void brute_force_use(uint8_t mode)
{
	conn.use_brute_force = mode;
}

//--------------------------------------------
void legacy_pairing_passkey_set(uint8_t *buf, size_t size)
{
	unsigned long pass;

	assert(size == 7);

	pass = strtoul((char *)buf, NULL, 10);
	memset(conn.pair_legacy.tk, 0, sizeof(conn.pair_legacy.tk));
	conn.pair_legacy.tk[15] = (uint8_t)(pass);
	conn.pair_legacy.tk[14] = (uint8_t)(pass >> 8);
	conn.pair_legacy.tk[13] = (uint8_t)(pass >> 16);
	conn.pair_legacy.tk[12] = (uint8_t)(pass >> 24);
}

//--------------------------------------------
void legacy_pairing_oob_key_set(uint8_t *buf, size_t size)
{
	size_t cnt;
	uint8_t oob_key[16];

	assert(size == 33);

	for (cnt = 0; cnt < size / 2; cnt++, buf += 2)
	{
		sscanf((const char *)buf, "%2hhx", &oob_key[cnt]);
	}
	memcpy_reverse(conn.pair_legacy.tk, oob_key, 16);
}

//--------------------------------------------
void ltk_set(uint8_t *buf, size_t size)
{
	size_t cnt;

	assert(size == 33);

	for (cnt = 0; cnt < size / 2; cnt++, buf += 2)
	{
		sscanf((const char *)buf, "%2hhx", &ltk[cnt]);
	}
}

//--------------------------------------------
void ble_decoder_close(void)
{
	list_adv_remove_all(&adv_devs);
	total_packet_counter = 0;
}
