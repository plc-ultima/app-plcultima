from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import automation


def sign_from_json(cmd, filepath: Path):
    tx_dct: Dict[str, Any] = json.load(open(filepath, "r"))

    raw_utxos: List[Tuple[bytes, int]] = [
        (bytes.fromhex(utxo_dct["raw"]), output_index)
        for utxo_dct in tx_dct["utxos"]
        for output_index in utxo_dct["output_indexes"]
    ]
    fees: int = tx_dct["fees"]
    sign_paths = tx_dct["sign_paths"]
    sigs = cmd.sign_new_tx(to=tx_dct["to"],
                           fees=fees,
                           change_path=tx_dct["change_path"],
                           sign_paths=sign_paths,
                           raw_utxos=raw_utxos,
                           lock_time=tx_dct["lock_time"])

    i = 0
    for sig in sigs:
        expected_pubkey = tx_dct["sigs"][i]["pubkey"]
        expected_sig = tx_dct["sigs"][i]["sig"]
        print(f"  Expected pubkey for input {i}   : {expected_pubkey}")
        assert expected_pubkey == sig[1].hex()
        print(f"  Expected signature for input {i}: {expected_sig}")
        assert expected_sig == sig[-1][-1].hex()
        print(f"  Path for input {i}              : {sign_paths}")
        i += 1


def test_untrusted_hash_sign_fail_nonzero_p1_p2(cmd, transport):
    # payloads do not matter, should check and fail before checking it (but non-empty is required)
    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x01, None, b"\x00")
    assert sw == 0x6B00, "should fail with p1 and p2 both non-zero"
    sw, _ = transport.exchange(0xE0, 0x48, 0x01, 0x00, None, b"\x00")
    assert sw == 0x6B00, "should fail with non-zero p1"
    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x01, None, b"\x00")
    assert sw == 0x6B00, "should fail with non-zero p2"


def test_untrusted_hash_sign_fail_short_payload(cmd, transport):
    # should fail if the payload is less than 7 bytes
    sw, _ = transport.exchange(0xE0, 0x48, 0x00, 0x00, None, b"\x01\x02\x03\x04\x05\x06")
    assert sw == 0x6700


@automation("automations/accept.json")
def test_sign_p2pkh_accept(cmd):
    for filepath in Path("data/").rglob("p2pkh-sh/tx.json"):
        sign_from_json(cmd, filepath)


@automation("automations/reject.json")
def test_sign_fail_p2pkh_reject(cmd):
    with pytest.raises(ConditionOfUseNotSatisfiedError):
        sign_from_json(cmd, "data/one-to-many/p2pkh-sh/tx.json")
