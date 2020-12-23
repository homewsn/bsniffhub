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

#ifndef BLE_CRYPTO_H_
#define BLE_CRYPTO_H_

void ble_c1(const uint8_t *c1_k, const uint8_t *c1_r, const uint8_t *c1_preq, const uint8_t *c1_pres, const uint8_t c1_iat, const uint8_t *c1_ia, const uint8_t c1_rat,	const uint8_t *c1_ra, uint8_t *c1_confirm);
void ble_c1_reverse(const uint8_t *c1_k, const uint8_t *c1_r, const uint8_t *c1_preq, const uint8_t *c1_pres, const uint8_t c1_iat, const uint8_t *c1_ia, const uint8_t c1_rat, const uint8_t *c1_ra, uint8_t *c1_rand);
void ble_s1(const uint8_t *s1_k, const uint8_t *s1_r1, const uint8_t *s1_r2, uint8_t *s1_stk);
void ble_sk(const uint8_t *sk_k, const uint8_t *sk_skds, const uint8_t *sk_skdm, uint8_t *sk_sk);
void ble_f4(const uint8_t *f4_U, const uint8_t *f4_V, const uint8_t *f4_X, const uint8_t *f4_Z, uint8_t *f4_C);
void ble_f5(const uint8_t *f5_W, const uint8_t *f5_N1, const uint8_t *f5_N2, const uint8_t *f5_A1, const uint8_t *f5_A2, uint8_t *f5_MacKey, uint8_t *f5_LTK);
void ble_f6(const uint8_t *f6_W, const uint8_t *f6_N1, const uint8_t *f6_N2, const uint8_t *f6_R, const uint8_t *f6_IOcap, const uint8_t *f6_A1, const uint8_t *f6_A2, uint8_t *f6_E);
void ble_g2(const uint8_t *g2_U, const uint8_t *g2_V, const uint8_t *g2_X, const uint8_t *g2_Y, uint32_t *g2_CV);
int ble_p256(const uint8_t *p256_SK, const uint8_t *p256_PK, uint8_t *p256_DHKey);
int ble_ccm(const uint8_t *aes_key, const uint8_t *nonce, const uint8_t *associated_data, const uint8_t *payload, uint8_t payload_length, uint8_t *decrypted_payload);

#endif /* BLE_CRYPTO_H_ */
