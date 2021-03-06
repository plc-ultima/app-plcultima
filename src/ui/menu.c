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

#include "os.h"
#include "ux.h"

#include "../globals.h"
#include "menu.h"

UX_STEP_NOCB(ux_menu_ready_step_plcultima, pnn, {&C_plcultima_logo, "PLC Ultima", "is ready"});
UX_STEP_NOCB(ux_menu_ready_step_plcultima_testnet,
             pnn,
             {&C_plcultima_testnet_logo, "PLC Ultima", "Testnet is ready"});

UX_STEP_NOCB(ux_menu_version_step, bn, {"Version", APPVERSION});
UX_STEP_VALID(ux_menu_exit_step, pb, os_sched_exit(-1), {&C_icon_dashboard_x, "Quit"});

// FLOW for the main menu (for plcultima):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: quit
UX_FLOW(ux_menu_main_flow_plcultima,
        &ux_menu_ready_step_plcultima,
        &ux_menu_version_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

// FLOW for the main menu (for plcultima testnet):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: quit
UX_FLOW(ux_menu_main_flow_plcultima_testnet,
        &ux_menu_ready_step_plcultima_testnet,
        &ux_menu_version_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

void ui_menu_main() {
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    if (G_coin_config->kind == COIN_KIND_PLCULTIMA) {
        ux_flow_init(0, ux_menu_main_flow_plcultima, NULL);
    } else if (G_coin_config->kind == COIN_KIND_PLCULTIMA_TESTNET) {
        ux_flow_init(0, ux_menu_main_flow_plcultima_testnet, NULL);
    }
}
