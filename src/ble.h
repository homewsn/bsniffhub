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

#ifndef BLE_H_
#define BLE_H_

//--------------------------------------------
#define ACCESS_ADDRESS_LENGTH                      4U
#define MINIMUM_HEADER_LENGTH                      2U
#define MAXIMUM_HEADER_LENGTH                      3U
#define CRC_LENGTH                                 3U
#define MIC_LENGTH                                 4U
#define MAXIMUM_PDU_LENGTH                         255U
#define MINIMUM_PACKET_LENGTH                      (ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + CRC_LENGTH)
#define HDR_LENGTH                                 (ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH)
#define L2CAP_LENGTH                               2U
#define CCID_LENGTH                                2U
#define SMP_HDR_LENGTH                             (HDR_LENGTH + L2CAP_LENGTH + CCID_LENGTH)
#define MAXIMUM_PACKET_LENGTH                      (ACCESS_ADDRESS_LENGTH + MAXIMUM_HEADER_LENGTH + CRC_LENGTH + MAXIMUM_PDU_LENGTH)
#define PDU_TYPE_MASK                              0x0F
#define CSA_MASK                                   0x20
#define TXADD_MASK                                 0x40
#define RXADD_MASK                                 0x80
#define ADV_IND                                    0x00
#define CONNECT_REQ                                0x05
#define CONNECT_REQ_PDU_LENGTH                     34
#define CONNECT_REQ_TIME_UNIT                      1250
#define DEVICE_ADDRESS_LENGTH                      6
#define CONNECT_REQ_LL_DATA                        (ACCESS_ADDRESS_LENGTH + MINIMUM_HEADER_LENGTH + DEVICE_ADDRESS_LENGTH + DEVICE_ADDRESS_LENGTH)
#define LLID_MASK                                  0x03
#define NESN_MASK                                  0x04
#define SN_MASK                                    0x08
#define MORE_DATA_MASK                             0x10
#define CP_MASK                                    0x20
#define LL_CONTROL_PDU                             0x03
#define LL_DATA_START_PDU                          0x02
#define LL_DATA_FRAG_PDU                           0x01
#define CID_SMP                                    0x06
#define SMP_PAIRING_REQUEST                        0x01
#define SMP_PAIRING_REQUEST_PDU_LENGTH             11
#define SMP_PAIRING_REQUEST_LENGTH                 7
#define SMP_PAIRING_RESPONSE                       0x02
#define SMP_PAIRING_RESPONSE_PDU_LENGTH            11
#define SMP_PAIRING_RESPONSE_LENGTH                7
#define SMP_PAIRING_CONFIRM                        0x03
#define SMP_PAIRING_CONFIRM_PDU_LENGTH             21
#define SMP_PAIRING_RANDOM                         0x04
#define SMP_PAIRING_RANDOM_PDU_LENGTH              21
#define SMP_ENCRYPTION_INFORMATION                 0x06
#define SMP_ENCRYPTION_INFORMATION_PDU_LENGTH      21
#define SMP_PAIRING_PUBLIC_KEY                     0x0C
#define SMP_PAIRING_PUBLIC_KEY_PDU_LENGTH          69
#define SMP_PAIRING_DHKEY_CHECK                    0x0D
#define SMP_PAIRING_DHKEY_CHECK_PDU_LENGTH         21
#define MAXIMUM_SMP_PACKET_LENGTH                  (MINIMUM_PACKET_LENGTH + SMP_PAIRING_PUBLIC_KEY_PDU_LENGTH + 1)
#define SC_MASK                                    0x08
#define MITM_MASK                                  0x04
#define AES128_BLOCK_LENGTH                        16
#define NONCE_LENGTH                               13
#define LL_CONNECTION_UPDATE_IND                   0x00
#define LL_CONNECTION_UPDATE_IND_PDU_LENGTH        12
#define LL_CHANNEL_MAP_IND                         0x01
#define LL_CHANNEL_MAP_IND_PDU_LENGTH              8
#define LL_TERMINATE_IND                           0x02
#define LL_ENC_REQ                                 0x03
#define LL_ENC_REQ_PDU_LENGTH                      23
#define LL_ENC_RSP                                 0x04
#define LL_ENC_RSP_PDU_LENGTH                      13
#define LL_START_ENC_REQ                           0x05
#define LL_PAUSE_ENC_RSP                           0x0B
#define MAXIMUM_PDU_AES_BUFFER_LENGTH              (MAXIMUM_PDU_LENGTH / AES128_BLOCK_LENGTH + 1) * AES128_BLOCK_LENGTH
#define ADV_CHANNEL_CRC_INIT                       0x555555
#define ADV_CHANNEL_ACCESS_ADDRESS                 { 0xD6, 0xBE, 0x89, 0x8E }
#define T_IFS                                      150
#define T_IFS_MAX_DRIFT                            10
#define T_WIN_MAX_DRIFT                            170
#define DATA_CHANNELS_NUMBER                       37
#define DATA_CHANNELS_BYTES_NUMBER                 (((DATA_CHANNELS_NUMBER - 1) / 8) + 1)
#define HOP_MASK                                   0x1F
#define DECRYPTION_ATTEMPTS_NUMBER                 10
#define CODED_PHY_CODING_SCHEME_S2                 2
#define CODED_PHY_CODING_SCHEME_S8                 8


//--------------------------------------------
static const uint8_t adv_channel_access_address[ACCESS_ADDRESS_LENGTH] = ADV_CHANNEL_ACCESS_ADDRESS;

//--------------------------------------------
uint32_t ble_crc_gen(uint32_t crc_init, const uint8_t *data, size_t len);
uint32_t ble_crc_calc(uint32_t crc_init, const uint8_t *data, size_t len);
uint32_t bits_reverse(uint32_t num);
void memcpy_reverse(uint8_t *dst, const uint8_t *src, size_t size);
int memcmp_reverse(uint8_t *dst, const uint8_t *src, size_t size);

#endif /* BLE_H_ */
