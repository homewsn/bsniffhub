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
#include "msg_pckt_ble.h"
#include "serial.h"
#include "sniffers.h"

//--------------------------------------------
extern const sniffer_t sniffer_nrf3;
extern const sniffer_t sniffer_sniffle;
extern const sniffer_t sniffer_ti2;

//--------------------------------------------
SNIFFERS(&sniffer_nrf3, &sniffer_sniffle, &sniffer_ti2);

//--------------------------------------------
const sniffer_t *get_sniffer(char id)
{
	size_t cnt;
	for (cnt = 0; ; cnt++)
	{
		if (sniffers[cnt] == NULL)
		{
			return NULL;
		}
		if (sniffers[cnt]->id == id)
		{
			return sniffers[cnt];
		}
	}
}