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
#include <string.h>     /* memcpy */
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dh.h"
#include "tinycrypt/cmac_mode.h"
#include "tinycrypt/ccm_mode.h"

//--------------------------------------------
void ble_c1(const uint8_t *c1_k,
	const uint8_t *c1_r,
	const uint8_t *c1_preq,
	const uint8_t *c1_pres,
	const uint8_t c1_iat,
	const uint8_t *c1_ia,
	const uint8_t c1_rat,
	const uint8_t *c1_ra,
	uint8_t *c1_confirm)
{
	uint8_t c1_buf[16];
	uint8_t p1[16];
	uint8_t p2[16];
	size_t cnt;
	struct tc_aes_key_sched_struct sched;

	assert(c1_k);
	assert(c1_r);
	assert(c1_preq);
	assert(c1_pres);
	assert(c1_ia);
	assert(c1_ra);
	assert(c1_confirm);

	memcpy(&p1[0], c1_pres, 7);
	memcpy(&p1[7], c1_preq, 7);
	p1[14] = c1_rat;
	p1[15] = c1_iat;
	memset(p2, 0x00, 4); // c1_padding
	memcpy(&p2[4], c1_ia, 6);
	memcpy(&p2[10], c1_ra, 6);

	tc_aes128_set_encrypt_key(&sched, c1_k);
	memcpy(c1_buf, c1_r, 16);
	for (cnt = 0; cnt < 16; cnt++)
	{
		c1_buf[cnt] ^= p1[cnt];
	}
	tc_aes_encrypt(c1_buf, c1_buf, &sched);
	for (cnt = 0; cnt < 16; cnt++)
	{
		c1_buf[cnt] ^= p2[cnt];
	}
	tc_aes_encrypt(c1_confirm, c1_buf, &sched);
}

//--------------------------------------------
void ble_c1_reverse(const uint8_t *c1_k,
	const uint8_t *c1_r,
	const uint8_t *c1_preq,
	const uint8_t *c1_pres,
	const uint8_t c1_iat,
	const uint8_t *c1_ia,
	const uint8_t c1_rat,
	const uint8_t *c1_ra,
	uint8_t *c1_rand)
{
	uint8_t c1_buf[16];
	uint8_t p1[16];
	uint8_t p2[16];
	size_t cnt;
	struct tc_aes_key_sched_struct sched;

	assert(c1_k);
	assert(c1_r);
	assert(c1_preq);
	assert(c1_pres);
	assert(c1_ia);
	assert(c1_ra);
	assert(c1_rand);

	memcpy(&p1[0], c1_pres, 7);
	memcpy(&p1[7], c1_preq, 7);
	p1[14] = c1_rat;
	p1[15] = c1_iat;
	memset(p2, 0x00, 4); // c1_padding
	memcpy(&p2[4], c1_ia, 6);
	memcpy(&p2[10], c1_ra, 6);

	tc_aes128_set_decrypt_key(&sched, c1_k);
	memcpy(c1_buf, c1_r, 16);
	for (cnt = 0; cnt < 16; cnt++)
	{
		c1_buf[cnt] ^= p2[cnt];
	}
	tc_aes_decrypt(c1_buf, c1_buf, &sched);
	for (cnt = 0; cnt < 16; cnt++)
	{
		c1_buf[cnt] ^= p1[cnt];
	}
	tc_aes_decrypt(c1_rand, c1_buf, &sched);
}

//--------------------------------------------
void ble_s1(const uint8_t *s1_k,
	const uint8_t *s1_r1,
	const uint8_t *s1_r2,
	uint8_t *s1_stk)
{
	uint8_t s1_buf[16];
	struct tc_aes_key_sched_struct sched;

	assert(s1_k);
	assert(s1_r1);
	assert(s1_r2);
	assert(s1_stk);

	memcpy(&s1_buf[0], &s1_r1[8], 8);
	memcpy(&s1_buf[8], &s1_r2[8], 8);
	tc_aes128_set_encrypt_key(&sched, s1_k);
	tc_aes_encrypt(s1_stk, s1_buf, &sched);
}

//--------------------------------------------
void ble_sk(const uint8_t *sk_k,
	const uint8_t *sk_skds,
	const uint8_t *sk_skdm,
	uint8_t *sk_sk)
{
	uint8_t sk_buf[16];
	struct tc_aes_key_sched_struct sched;

	assert(sk_k);
	assert(sk_skdm);
	assert(sk_skds);
	assert(sk_sk);

	memcpy(&sk_buf[0], sk_skds, 8);
	memcpy(&sk_buf[8], sk_skdm, 8);
	tc_aes128_set_encrypt_key(&sched, sk_k);
	tc_aes_encrypt(sk_sk, sk_buf, &sched);
}

//--------------------------------------------
void ble_f4(const uint8_t *f4_U,
	const uint8_t *f4_V,
	const uint8_t *f4_X,
	const uint8_t *f4_Z,
	uint8_t *f4_C)
{
	uint8_t cmac_buf[65];
	struct tc_cmac_struct cmac_state;
	struct tc_aes_key_sched_struct sched;

	assert(f4_U);
	assert(f4_V);
	assert(f4_X);
	assert(f4_Z);
	assert(f4_C);

	memcpy(&cmac_buf[0], f4_U, 32);
	memcpy(&cmac_buf[32], f4_V, 32);
	memcpy(&cmac_buf[64], f4_Z, 1);
	tc_cmac_setup(&cmac_state, f4_X, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, cmac_buf, sizeof(cmac_buf));
	tc_cmac_final(f4_C, &cmac_state);
}

//--------------------------------------------
void ble_f5(const uint8_t *f5_W,
	const uint8_t *f5_N1,
	const uint8_t *f5_N2,
	const uint8_t *f5_A1,
	const uint8_t *f5_A2,
	uint8_t *f5_MacKey,
	uint8_t *f5_LTK)
{
	uint8_t cmac_buf[53];
	uint8_t f5_T[16];
	struct tc_cmac_struct cmac_state;
	struct tc_aes_key_sched_struct sched;
	static const uint8_t f5_SALT[16] =	{ 0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38, 0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe };
	static const uint8_t f5_Length[2] =	{ 0x01, 0x00 };
	static const uint8_t f5_keyID[4] = { 0x62, 0x74, 0x6C, 0x65 };

	assert(f5_W);
	assert(f5_N1);
	assert(f5_N2);
	assert(f5_A1);
	assert(f5_A2);
	assert(f5_MacKey);
	assert(f5_LTK);

	tc_cmac_setup(&cmac_state, f5_SALT, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, f5_W, 32);
	tc_cmac_final(f5_T, &cmac_state);

	cmac_buf[0] = 0x00;
	memcpy(&cmac_buf[1], f5_keyID, 4);
	memcpy(&cmac_buf[5], f5_N1, 16);
	memcpy(&cmac_buf[21], f5_N2, 16);
	memcpy(&cmac_buf[37], f5_A1, 7);
	memcpy(&cmac_buf[44], f5_A2, 7);
	memcpy(&cmac_buf[51], f5_Length, 2);
	tc_cmac_setup(&cmac_state, f5_T, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, cmac_buf, sizeof(cmac_buf));
	tc_cmac_final(f5_MacKey, &cmac_state);

	cmac_buf[0] = 0x01;
	memcpy(&cmac_buf[1], f5_keyID, 4);
	memcpy(&cmac_buf[5], f5_N1, 16);
	memcpy(&cmac_buf[21], f5_N2, 16);
	memcpy(&cmac_buf[37], f5_A1, 7);
	memcpy(&cmac_buf[44], f5_A2, 7);
	memcpy(&cmac_buf[51], f5_Length, 2);
	tc_cmac_setup(&cmac_state, f5_T, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, cmac_buf, sizeof(cmac_buf));
	tc_cmac_final(f5_LTK, &cmac_state);
}

//--------------------------------------------
void ble_f6(const uint8_t *f6_W,
	const uint8_t *f6_N1,
	const uint8_t *f6_N2,
	const uint8_t *f6_R,
	const uint8_t *f6_IOcap,
	const uint8_t *f6_A1,
	const uint8_t *f6_A2,
	uint8_t *f6_E)
{
	uint8_t cmac_buf[65];
	struct tc_cmac_struct cmac_state;
	struct tc_aes_key_sched_struct sched;

	assert(f6_W);
	assert(f6_N1);
	assert(f6_N2);
	assert(f6_R);
	assert(f6_IOcap);
	assert(f6_A1);
	assert(f6_A2);
	assert(f6_E);

	memcpy(&cmac_buf[0], f6_N1, 16);
	memcpy(&cmac_buf[16], f6_N2, 16);
	memcpy(&cmac_buf[32], f6_R, 16);
	memcpy(&cmac_buf[48], f6_IOcap, 3);
	memcpy(&cmac_buf[51], f6_A1, 7);
	memcpy(&cmac_buf[58], f6_A2, 7);
	tc_cmac_setup(&cmac_state, f6_W, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, cmac_buf, sizeof(cmac_buf));
	tc_cmac_final(f6_E, &cmac_state);
}

//--------------------------------------------
void ble_g2(const uint8_t *g2_U,
	const uint8_t *g2_V,
	const uint8_t *g2_X,
	const uint8_t *g2_Y,
	uint32_t *g2_CV)
{
	uint8_t cmac_buf[80];
	uint8_t cv_buf[16];
	struct tc_cmac_struct cmac_state;
	struct tc_aes_key_sched_struct sched;

	assert(g2_U);
	assert(g2_V);
	assert(g2_X);
	assert(g2_Y);
	assert(g2_CV);

	memcpy(&cmac_buf[0], g2_U, 32);
	memcpy(&cmac_buf[32], g2_V, 32);
	memcpy(&cmac_buf[64], g2_Y, 16);
	tc_cmac_setup(&cmac_state, g2_X, &sched);
	tc_cmac_init(&cmac_state);
	tc_cmac_update(&cmac_state, cmac_buf, sizeof(cmac_buf));
	tc_cmac_final(cv_buf, &cmac_state);
	*g2_CV = cv_buf[15] | (cv_buf[14] << 8) | (cv_buf[13] << 16) | (cv_buf[12] << 24);
}

//--------------------------------------------
int ble_p256(const uint8_t *p256_SK,
	const uint8_t *p256_PK,
	uint8_t *p256_DHKey)
{
	int res;

	assert(p256_SK);
	assert(p256_PK);

	if ((res = uECC_valid_public_key(p256_PK, &curve_secp256r1)) < 0)
	{
		return res;
	}
	if ((res = uECC_shared_secret(p256_PK, p256_SK, p256_DHKey, &curve_secp256r1)) == 1)
	{
		return 0;
	}
	return -1;
}

//--------------------------------------------
int ble_ccm(const uint8_t *aes_key,
	const uint8_t *nonce,
	const uint8_t *associated_data,
	const uint8_t *payload,
	uint8_t payload_length,
	uint8_t *decrypted_payload)
{
	int res;
	struct tc_ccm_mode_struct ccm_state;
	struct tc_aes_key_sched_struct sched;

	assert(aes_key);
	assert(nonce);
	assert(associated_data);
	assert(payload);
	assert(payload_length > 4);
	assert(decrypted_payload);

	tc_aes128_set_encrypt_key(&sched, aes_key);
	if ((res = tc_ccm_config(&ccm_state, &sched, (uint8_t *)nonce, 13, 4)) != 1)
	{
		return -1;
	}
	if ((res = tc_ccm_decryption_verification(decrypted_payload, payload_length - 4, associated_data, 1, payload, payload_length, &ccm_state)) != 1)
	{
		return -1;
	}
	return 0;
}
