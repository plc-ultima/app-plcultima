def test_get_coin_version(cmd):
    (p2pkh_prefix, p2sh_prefix, coin_name, coin_ticker) = cmd.get_coin_version()

    # PLC Ultima app: (0xC80528, 0xC80529, "plcultima", "PLCU")
    assert (p2pkh_prefix,
            p2sh_prefix,
            coin_name,
            coin_ticker) == (0xC80524, 0xC80525, "plcultima", "PLCU")
