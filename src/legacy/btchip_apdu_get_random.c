/*******************************************************************************
*   Ledger App - PLC Ultima Wallet
*   (c) 2016-2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define MAX_LENGTH 248

unsigned short btchip_apdu_get_random()
{
    unsigned char length = G_io_apdu_buffer[ISO_OFFSET_LC];
    if (length == 0)
    {
        length = MAX_LENGTH;
    }

    if (length > MAX_LENGTH)
    {
        return BTCHIP_SW_INCORRECT_LENGTH;
    }

    cx_rng(G_io_apdu_buffer, length);

    btchip_context_D.outLength = length;

    return BTCHIP_SW_OK;
}
