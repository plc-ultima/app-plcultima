from bitcoin_client.bitcoin_base_cmd import AddrType


def test_get_public_key(cmd):
    # legacy address
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.Legacy,
        bip32_path="m/44'/1'/0'/0/0",
        display=False
    )

    assert pub_key == bytes.fromhex("04"
                                    "019d728e15ef7dd6f200b48f3b18350749a26435a7d472e5559f2815d417e688"
                                    "0f14324e577be202960b26c90105af06ba4c9439449a6958ad8f0bfdd06c6d95")
    assert addr == "U2xFX4ZeG1x4xLvaXC63QPEQL9YyjD9kR2NkH"
    assert bip32_chain_code == bytes.fromhex(
        "ef1c01d2c0265dabb738344f8b51159cf99230ba95ed1fec1d8ccb0624620220")
