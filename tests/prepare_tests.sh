#!/bin/bash
cd ..
make clean
make -j DEBUG=1 COIN=plcultima # compile optionally with PRINTF
mv bin/ tests/plcultima-bin
make clean
make -j DEBUG=1 COIN=plcultima_testnet
mv bin/ tests/plcultima-testnet-bin
