from emv_tlv import Tlv, encode, parse, render
from emv_tlv.cli import main
from emv_tlv.render import mask


def test_render_field55(field55):
    text = render(parse(field55))
    assert "9F27 Cryptogram Information Data [1] 80" in text
    assert "- Cryptogram: ARQC (go online)" in text
    assert "- Transaction exceeds floor limit" in text


def test_render_masks_card_data():
    data = encode(
        [
            Tlv(
                "70",
                b"",
                [
                    Tlv("5A", bytes.fromhex("4111111111111111")),
                    Tlv("57", bytes.fromhex("4111111111111111D28122011234567F")),
                    Tlv("5F20", b"TEST/CARD"),
                    Tlv("50", b"VISA"),
                ],
            )
        ]
    )
    text = render(parse(data))
    assert "411111******1111" in text
    assert "4111111111111111" not in text
    assert "TEST/CARD" not in text
    assert "(VISA)" in text
    assert "4111111111111111" in render(parse(data), masked=False)


def test_mask_short_pan():
    assert mask("5A", bytes.fromhex("12345678")) == "12345678"


def test_render_undecodable_value():
    assert "Cannot decode" in render(parse("950100"))


def test_cli_decode(capsys, field55):
    assert main(["decode", field55]) == 0
    assert "ARQC" in capsys.readouterr().out


def test_cli_shortcuts(capsys):
    assert main(["tvr", "0000008000"]) == 0
    assert "floor limit" in capsys.readouterr().out
    assert main(["tsi", "0000"]) == 0
    assert "No bits set" in capsys.readouterr().out


def test_cli_errors(capsys):
    assert main(["decode", "9F27"]) == 1
    assert main(["tvr", "zz"]) == 1
    assert "error:" in capsys.readouterr().err
