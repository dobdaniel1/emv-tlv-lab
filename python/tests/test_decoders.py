import pytest

from emv_tlv import (
    TlvError,
    decode_aip,
    decode_cid,
    decode_cvm_list,
    decode_cvm_results,
    decode_tsi,
    decode_tvr,
    explain,
    tag_name,
)


def test_tvr_floor_limit():
    assert decode_tvr(bytes.fromhex("0000008000")) == ["Transaction exceeds floor limit"]


def test_tvr_multiple_bits_and_rfu():
    result = decode_tvr(bytes.fromhex("8040000001"))
    assert result == [
        "Offline data authentication was not performed",
        "Expired application",
        "RFU (byte 5 bit 1)",
    ]


def test_tvr_wrong_length():
    with pytest.raises(TlvError):
        decode_tvr(b"\x00")


def test_tsi():
    assert decode_tsi(bytes.fromhex("E800")) == [
        "Offline data authentication was performed",
        "Cardholder verification was performed",
        "Card risk management was performed",
        "Terminal risk management was performed",
    ]


def test_aip():
    assert decode_aip(bytes.fromhex("3900")) == [
        "DDA supported",
        "Cardholder verification is supported",
        "Terminal risk management is to be performed",
        "CDA supported",
    ]


def test_cvm_results():
    assert decode_cvm_results(bytes.fromhex("420300")) == [
        "Method: Enciphered PIN verified online",
        "Condition: If terminal supports the CVM",
        "Result: Unknown",
    ]
    with pytest.raises(TlvError):
        decode_cvm_results(b"\x00")


def test_cvm_list():
    value = bytes.fromhex("000000000000271042031E031F00")
    assert decode_cvm_list(value) == [
        "Amount X: 0",
        "Amount Y: 10000",
        "Rule 1: Enciphered PIN verified online | If terminal supports the CVM"
        " | on failure: next rule",
        "Rule 2: Signature | If terminal supports the CVM | on failure: fail",
        "Rule 3: No CVM required | Always | on failure: fail",
    ]
    with pytest.raises(TlvError):
        decode_cvm_list(b"\x00" * 9)


@pytest.mark.parametrize(
    "cid,kind",
    [("00", "AAC (decline)"), ("40", "TC (approve offline)"), ("80", "ARQC (go online)")],
)
def test_cid(cid, kind):
    assert decode_cid(bytes.fromhex(cid)) == [f"Cryptogram: {kind}"]


def test_cid_advice_and_length():
    assert "Advice required" in decode_cid(b"\x08")
    with pytest.raises(TlvError):
        decode_cid(b"")


def test_explain_dol_and_unknown():
    assert explain("9F38", bytes.fromhex("9F6604")) == [
        "9F66 (4 bytes) Terminal Transaction Qualifiers (TTQ)"
    ]
    assert explain("9F02", b"\x00") == []


def test_tag_name():
    assert tag_name("9f26") == "Application Cryptogram"
    assert tag_name("DF01") == "Unknown tag"
