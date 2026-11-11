import pytest
from hypothesis import given
from hypothesis import strategies as st

from emv_tlv import Tlv, TlvError, encode, find, parse, parse_dol
from emv_tlv.tlv import encode_length


def test_parse_field55(field55):
    items = parse(field55)
    assert [i.tag for i in items][:3] == ["9F26", "9F27", "9F10"]
    assert find(items, "9F02").value == bytes.fromhex("000000010000")
    assert find(items, "95").length == 5
    assert encode(items).hex().upper() == field55


def test_constructed_tags_are_nested():
    select = encode(
        [
            Tlv(
                "6F",
                b"",
                [
                    Tlv("84", bytes.fromhex("A0000000031010")),
                    Tlv("A5", b"", [Tlv("50", b"VISA DEBIT"), Tlv("87", b"\x01")]),
                ],
            )
        ]
    )
    (fci,) = parse(select)
    assert fci.constructed
    assert fci.find("50").value == b"VISA DEBIT"
    assert not fci.find("84").constructed
    assert fci.find("9F38") is None


def test_padding_skipped():
    assert [i.tag for i in parse("00009F270180FF00")] == ["9F27"]


def test_long_length_forms():
    value = bytes(200)
    data = bytes.fromhex("9F10") + encode_length(200) + value
    assert data[2:4] == b"\x81\xc8"
    assert parse(data)[0].value == value
    assert encode_length(300) == b"\x82\x01\x2c"


@pytest.mark.parametrize(
    "bad",
    [
        "9F",  # truncated multi-byte tag
        "9F27",  # missing length
        "9F2702",  # value shorter than declared
        "9F27820001",  # length bytes truncated
        "9F278500",  # unsupported length form
        "ZZ",  # not hex
    ],
)
def test_malformed(bad):
    with pytest.raises(TlvError):
        parse(bad)


def test_parse_dol():
    assert parse_dol(bytes.fromhex("9F02069F03069F1A0295055F2A029A039C019F3704")) == [
        ("9F02", 6),
        ("9F03", 6),
        ("9F1A", 2),
        ("95", 5),
        ("5F2A", 2),
        ("9A", 3),
        ("9C", 1),
        ("9F37", 4),
    ]


tags = st.sampled_from(["9F02", "9F26", "95", "5A", "9F10", "DF8101"])


@given(st.lists(st.tuples(tags, st.binary(max_size=300)), max_size=8))
def test_round_trip(pairs):
    items = [Tlv(t, v) for t, v in pairs]
    parsed = parse(encode(items))
    assert [(i.tag, i.value) for i in parsed] == pairs
