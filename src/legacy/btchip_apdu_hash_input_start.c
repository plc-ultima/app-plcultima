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

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "btchip_internal.h"
#include "btchip_apdu_constants.h"
#include "btchip_bagl_extensions.h"

#define P1_FIRST 0x00
#define P1_NEXT 0x80
#define P2_NEW 0x00
#define P2_CONTINUE 0x80

#define IS_INPUT() \
    (G_io_apdu_buffer[ISO_OFFSET_LC] - 1 > 8 && G_io_apdu_buffer[ISO_OFFSET_LC] - 1 <= TRUSTED_INPUT_TOTAL_SIZE + 2 && G_io_apdu_buffer[ISO_OFFSET_CDATA] <= 0x02)

#define IS_INPUT_TRUSTED() \
    (G_io_apdu_buffer[ISO_OFFSET_CDATA] == 0x01 && G_io_apdu_buffer[ISO_OFFSET_CDATA + 1] == TRUSTED_INPUT_TOTAL_SIZE && G_io_apdu_buffer[ISO_OFFSET_CDATA + 2] == MAGIC_TRUSTED_INPUT && G_io_apdu_buffer[ISO_OFFSET_CDATA + 3] == 0x00)

unsigned short btchip_apdu_hash_input_start()
{
    unsigned char apduLength;
    apduLength = G_io_apdu_buffer[ISO_OFFSET_LC];

    SB_CHECK(N_btchip.bkp.config.operationMode);
    switch (SB_GET(N_btchip.bkp.config.operationMode))
    {
    case BTCHIP_MODE_WALLET:
    case BTCHIP_MODE_RELAXED_WALLET:
    case BTCHIP_MODE_SERVER:
        break;
    default:
        return BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST)
    {
        // Initialize
        btchip_context_D.transactionContext.transactionState =
            BTCHIP_TRANSACTION_NONE;
        btchip_set_check_internal_structure_integrity(1);
        btchip_context_D.transactionHashOption = TRANSACTION_HASH_BOTH;
    }
    else if (G_io_apdu_buffer[ISO_OFFSET_P1] != P1_NEXT)
    {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    if (G_io_apdu_buffer[ISO_OFFSET_P2] == P2_NEW)
    {
        // btchip_context_D.transactionContext.consumeP2SH =
        // ((N_btchip.bkp.config.options & BTCHIP_OPTION_SKIP_2FA_P2SH) != 0);
        if (G_io_apdu_buffer[ISO_OFFSET_P1] == P1_FIRST)
        {
            // Request PIN validation
            // Only request PIN validation (user presence) to start a new
            // transaction signing flow.
            // Thus allowing for numerous output to be processed in the
            // background without
            // requiring to disable autolock/autopoweroff
            if (!btchip_context_D.transactionContext.firstSigned &&
                os_global_pin_is_validated() != BOLOS_UX_OK)
            {
                return BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
            }
            // Master transaction reset
            btchip_context_D.transactionContext.firstSigned = 1;
            btchip_context_D.transactionContext.consumeP2SH = 0;
            btchip_context_D.transactionContext.relaxed = 0;
            btchip_set_check_internal_structure_integrity(1);
            // Initialize for screen pairing
            os_memset(&btchip_context_D.tmpCtx.output, 0,
                      sizeof(btchip_context_D.tmpCtx.output));
            btchip_context_D.tmpCtx.output.changeAccepted = 1;
        }
    }
    else if (G_io_apdu_buffer[ISO_OFFSET_P2] != P2_CONTINUE)
    {
        return BTCHIP_SW_INCORRECT_P1_P2;
    }

    // Start parsing of the 1st chunk
    btchip_context_D.transactionBufferPointer =
        G_io_apdu_buffer + ISO_OFFSET_CDATA;
    btchip_context_D.transactionDataRemaining = apduLength;

    transaction_parse(PARSE_MODE_SIGNATURE);

    return BTCHIP_SW_OK;
}
