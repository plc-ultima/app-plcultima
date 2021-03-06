/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
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
 *****************************************************************************/

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include <assert.h>

#include "os.h"
#include "ux.h"

#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

// common declarations between legacy and new code; will refactor it out later
#include "legacy/include/btchip_context.h"
#include "legacy/include/swap_lib_calls.h"
#include "legacy/include/swap_lib_calls.h"

#ifndef DISABLE_LEGACY_SUPPORT
#include "legacy/main_old.h"
#include "legacy/btchip_display_variables.h"
#else
// we don't import main_old.h in legacy-only mode, but we still need libargs_s; will refactor later
struct libargs_s {
    unsigned int id;
    unsigned int command;
    btchip_altcoin_config_t *coin_config;
    union {
        check_address_parameters_t *check_address;
        create_transaction_parameters_t *create_transaction;
        get_printable_amount_parameters_t *get_printable_amount;
    };
};
#endif

#include "main.h"

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

#ifdef TARGET_NANOS
// on NanoS only, we optimize the usage of the globals with a custom linker script
dispatcher_context_t __attribute__((section(".new_globals"))) G_dispatcher_context;

#ifndef DISABLE_LEGACY_SUPPORT
// legacy variables
btchip_context_t __attribute__((section(".legacy_globals"))) btchip_context_D;
#endif  // DISABLE_LEGACY_SUPPORT
#else   // #ifndef TARGET_NANOS
dispatcher_context_t G_dispatcher_context;

// legacy variables
#ifndef DISABLE_LEGACY_SUPPORT
btchip_context_t btchip_context_D;
#endif  // DISABLE_LEGACY_SUPPORT
#endif

// shared between legacy and new
global_context_t *G_coin_config;  // same type as btchip_altcoin_config_t

uint8_t G_app_mode;

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    // {
    //     .cla = CLA_APP,
    //     .ins = GET_EXTENDED_PUBKEY,
    //     .handler = (command_handler_t)handler_get_extended_pubkey
    // },
    // {
    //     .cla = CLA_APP,
    //     .ins = GET_WALLET_ADDRESS,
    //     .handler = (command_handler_t)handler_get_wallet_address
    // },
    // {
    //     .cla = CLA_APP,
    //     .ins = REGISTER_WALLET,
    //     .handler = (command_handler_t)handler_register_wallet
    // },
    // {
    //     .cla = CLA_APP,
    //     .ins = SIGN_PSBT,
    //     .handler = (command_handler_t)handler_sign_psbt
    // },
    // {
    //     .cla = CLA_APP,
    //     .ins = GET_MASTER_FINGERPRINT,
    //     .handler = (command_handler_t)handler_get_master_fingerprint
    // },
    // {
    //     .cla = CLA_APP,
    //     .ins = SIGN_MESSAGE,
    //     .handler = (command_handler_t)handler_sign_message
    // },
};
// clang-format on

void init_coin_config(btchip_altcoin_config_t *coin_config) {
    memset(coin_config, 0, sizeof(btchip_altcoin_config_t));

    // new app only
    coin_config->bip32_pubkey_version = BIP32_PUBKEY_VERSION;

    // new app and legacy
    coin_config->bip44_coin_type = BIP44_COIN_TYPE;
    coin_config->p2pkh_version = COIN_P2PKH_VERSION;
    coin_config->p2sh_version = COIN_P2SH_VERSION;

    // we assume in display.c that the ticker size is at most 5 characters (+ null)
    _Static_assert(sizeof(COIN_COINID_SHORT) <= 6, "COIN_COINID_SHORT too large");
    _Static_assert(sizeof(COIN_COINID_SHORT) <= sizeof(coin_config->name_short),
                   "COIN_COINID_SHORT too large");
    strcpy(coin_config->name_short, COIN_COINID_SHORT);

#ifndef DISABLE_LEGACY_SUPPORT
    // legacy only
    _Static_assert(sizeof(COIN_COINID) <= sizeof(coin_config->coinid), "COIN_COINID too large");
    strcpy(coin_config->coinid, COIN_COINID);

    _Static_assert(sizeof(COIN_COINID_NAME) <= sizeof(coin_config->name),
                   "COIN_COINID_NAME too large");

    strcpy(coin_config->name, COIN_COINID_NAME);
    coin_config->kind = COIN_KIND;
#endif
}

void app_main() {
    for (;;) {
        // Length of APDU command received in G_io_apdu_buffer
        int input_len = 0;
        // Structured APDU command
        command_t cmd;

        // Reset length of APDU response
        G_output_len = 0;

        // Receive command bytes in G_io_apdu_buffer

        input_len = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);

        if (input_len < 0) {
            PRINTF("=> io_exchange error\n");
            return;
        }

        if (G_io_apdu_buffer[0] == CLA_APP_LEGACY) {
            if (G_app_mode != APP_MODE_LEGACY) {
                explicit_bzero(&btchip_context_D, sizeof(btchip_context_D));

                btchip_context_init();

                G_app_mode = APP_MODE_LEGACY;
            }

            if (btchip_context_D.called_from_swap && vars.swap_data.should_exit) {
                btchip_context_D.io_flags |= IO_RETURN_AFTER_TX;
            }

            // legacy codes, use old dispatcher
            btchip_context_D.inLength = input_len;

            app_dispatch();

            if (btchip_context_D.called_from_swap && vars.swap_data.should_exit) {
                os_sched_exit(0);
            }
        }
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void coin_main(btchip_altcoin_config_t *coin_config) {
    // assumptions on the length of data structures

    _Static_assert(sizeof(cx_sha256_t) <= 108, "cx_sha256_t too large");

    btchip_altcoin_config_t config;
    if (coin_config == NULL) {
        init_coin_config(&config);
        G_coin_config = &config;
    } else {
        G_coin_config = coin_config;
    }

#ifdef HAVE_SEMIHOSTED_PRINTF
    PRINTF("APDU State size: %d\n", sizeof(command_state_t));
    PRINTF("Legacy State size: %d\n", sizeof(btchip_context_D));
#endif

    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));

    memset(G_io_apdu_buffer, 0, 255);  // paranoia

    // Process the incoming APDUs

    for (;;) {
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
}

__attribute__((section(".boot"))) int main(int arg0) {
    G_app_mode = APP_MODE_UNINITIALIZED;

#ifdef USE_LIBCOIN
    BEGIN_TRY {
        TRY {
            unsigned int libcall_params[5];
            btchip_altcoin_config_t coin_config;
            init_coin_config(&coin_config);

            G_app_mode =
                APP_MODE_LEGACY;  // in library mode, we currently only run with legacy APDUs

            PRINTF("Hello from PLC Ultima\n");
            check_api_level(CX_COMPAT_APILEVEL);
            // delegate to bitcoin app/lib
            libcall_params[0] = "PLC Ultima";
            libcall_params[1] = 0x100;
            libcall_params[2] = RUN_APPLICATION;
            libcall_params[3] = &coin_config;
            libcall_params[4] = 0;
            if (arg0) {
                // call as a library
                libcall_params[2] = ((unsigned int *) arg0)[1];
                libcall_params[4] = ((unsigned int *) arg0)[3];  // library arguments
                os_lib_call(&libcall_params);
                ((unsigned int *) arg0)[0] = libcall_params[1];
                os_lib_end();
            } else {
                // launch coin application
                os_lib_call(&libcall_params);
            }
        }
        FINALLY {
        }
    }
    END_TRY;
    // no return
#else
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    io_reset_timeouts();

    if (!arg0) {
        // Bitcoin application launched from dashboard
        coin_main(NULL);
        return 0;
    }

    struct libargs_s *args = (struct libargs_s *) arg0;
    if (args->id != 0x100) {
        app_exit();
        return 0;
    }
    switch (args->command) {
        case RUN_APPLICATION:
            // coin application launched from dashboard
            if (args->coin_config == NULL)
                app_exit();
            else
                coin_main(args->coin_config);
            break;
        default:
#ifndef DISABLE_LEGACY_SUPPORT
            // called as bitcoin or altcoin library
            library_main(args);
#else
            app_exit();
#endif
    }
#endif  // USE_LIBCOIN
    return 0;
}
