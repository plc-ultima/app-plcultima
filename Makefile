# ****************************************************************************
#    Ledger App for PLC Ultima
#    (c) 2021 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: compile with the right path restrictions
# APP_LOAD_PARAMS  = --curve secp256k1
APP_LOAD_PARAMS  = $(COMMON_LOAD_PARAMS)
APP_PATH = ""

APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 1
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"


APP_STACK_SIZE = 1500

# simplify for tests
ifndef COIN
COIN=plcultima_testnet
endif

# Custom NanoS linking script to overlap legacy globals and new globals
ifeq ($(TARGET_NAME),TARGET_NANOS)
SCRIPT_LD:=$(CURDIR)/script-nanos.ld
endif

# Flags: BOLOS_SETTINGS, GLOBAL_PIN, DERIVE_MASTER
APP_LOAD_FLAGS=--appFlags 0xa50 --dep 'PLC Ultima':$(APPVERSION)
DEFINES_LIB = USE_LIBCOIN

# PLC Ultima
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused

DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"plcultima\"
DEFINES   += COIN_COINID_HEADER=\"PLCUltima\"
DEFINES   += COIN_COINID_SHORT=\"PLCU\"
APP_LOAD_PARAMS += --path $(APP_PATH)

ifeq ($(COIN),plcultima)
DEFINES   += BIP44_COIN_TYPE=780
DEFINES   += COIN_P2PKH_VERSION=0xC80528
DEFINES   += COIN_P2SH_VERSION=0xC80529
DEFINES   += COIN_COINID_NAME=\"PLC\\x20Ultima\"
DEFINES   += COIN_KIND=COIN_KIND_PLCULTIMA
APPNAME ="PLC Ultima"
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

else ifeq ($(COIN),plcultima_testnet)
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += COIN_P2PKH_VERSION=0xC80524
DEFINES   += COIN_P2SH_VERSION=0xC80525
DEFINES   += COIN_COINID_NAME=\"PLC\\x20Ultima\\x20Test\"
DEFINES   += COIN_KIND=COIN_KIND_PLCULTIMA_TESTNET
APPNAME ="PLC Ultima Testnet"

else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use plcultima_testnet, plcultima)
endif
endif

APP_LOAD_PARAMS += $(APP_LOAD_FLAGS)
DEFINES += $(DEFINES_LIB)

ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=icons/nanos_app_$(COIN).gif
else
ICONNAME=icons/nanox_app_$(COIN).gif
endif

all: default

# TODO: double check if all those flags are still relevant/needed (was copied from legacy app-bitcoin)

DEFINES   += APPNAME=\"$(APPNAME)\"
DEFINES   += APPVERSION=\"$(APPVERSION)\"
DEFINES   += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)
DEFINES   += OS_IO_SEPROXYHAL
DEFINES   += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0
DEFINES   += HAVE_UX_FLOW

DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY


ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=72
DEFINES       += HAVE_WALLET_ID_SDK
else
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES       += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES       += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES       += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES       += HAVE_BLE_APDU # basic ledger apdu transport over BLE
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    # enables optimizations using the shared 1K CXRAM region
    DEFINES   += USE_CXRAM_SECTION
endif

ifndef DEBUG
        DEBUG = 0
endif

ifeq ($(DEBUG),0)
        DEFINES   += PRINTF\(...\)=
else
        ifeq ($(DEBUG),10)
                $(warning Using semihosted PRINTF. Only run with speculos!)
                DEFINES   += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
        else
                ifeq ($(TARGET_NAME),TARGET_NANOS)
                        DEFINES   += HAVE_PRINTF PRINTF=screen_printf
                else
                        DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
                endif
        endif
endif


# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src


ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC      := $(CLANGPATH)clang
CFLAGS  += -Oz
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_ux

ifeq ($(TARGET_NAME),TARGET_NANOX)
    SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile


# Temporary restriction until we a Resistance Nano X icon
ifeq ($(TARGET_NAME),TARGET_NANOS)
listvariants:
	@echo VARIANTS COIN plcultima_testnet plcultima
else
listvariants:
	@echo VARIANTS COIN plcultima_testnet plcultima
endif


# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
