"""Human-readable meaning of bit fields and coded values."""

from .dictionary import data
from .errors import TlvError
from .tlv import parse_dol


def decode_bits(tag: str, value: bytes) -> list[str]:
    """List the meaning of every set bit. Bit 8 is the most significant bit of each byte."""
    table = data()["bits"][tag]
    if len(value) != len(table):
        raise TlvError(f"Tag {tag} must be {len(table)} bytes, got {len(value)}")
    found = []
    for byte_no, (byte, names) in enumerate(zip(value, table, strict=True), start=1):
        for pos, name in enumerate(names):
            bit = 8 - pos
            if byte & (1 << (bit - 1)):
                found.append(name or f"RFU (byte {byte_no} bit {bit})")
    return found


def decode_tvr(value: bytes) -> list[str]:
    return decode_bits("95", value)


def decode_tsi(value: bytes) -> list[str]:
    return decode_bits("9B", value)


def decode_aip(value: bytes) -> list[str]:
    return decode_bits("82", value)


def _cvm_rule(code: int, condition: int) -> str:
    method = data()["cvm_codes"].get(f"{code & 0x3F:02X}", "Unknown CVM")
    cond = data()["cvm_conditions"].get(f"{condition:02X}", "Unknown condition")
    then = "next rule" if code & 0x40 else "fail"
    return f"{method} | {cond} | on failure: {then}"


def decode_cvm_results(value: bytes) -> list[str]:
    if len(value) != 3:
        raise TlvError("CVM Results must be 3 bytes")
    method = data()["cvm_codes"].get(f"{value[0] & 0x3F:02X}", "Unknown CVM")
    cond = data()["cvm_conditions"].get(f"{value[1]:02X}", "Unknown condition")
    result = data()["cvm_results"].get(f"{value[2]:02X}", "Unknown")
    return [f"Method: {method}", f"Condition: {cond}", f"Result: {result}"]


def decode_cvm_list(value: bytes) -> list[str]:
    if len(value) < 8 or len(value) % 2:
        raise TlvError("CVM List must be 8 bytes of amounts plus 2-byte rules")
    x, y = int.from_bytes(value[:4], "big"), int.from_bytes(value[4:8], "big")
    rules = [_cvm_rule(value[i], value[i + 1]) for i in range(8, len(value), 2)]
    return [f"Amount X: {x}", f"Amount Y: {y}"] + [f"Rule {n}: {r}" for n, r in enumerate(rules, 1)]


def decode_cid(value: bytes) -> list[str]:
    if len(value) != 1:
        raise TlvError("CID must be 1 byte")
    kind = data()["cryptogram_types"][str(value[0] >> 6)]
    lines = [f"Cryptogram: {kind}"]
    if value[0] & 0x08:
        lines.append("Advice required")
    return lines


def decode_dol(value: bytes) -> list[str]:
    from .dictionary import tag_name

    return [f"{tag} ({length} bytes) {tag_name(tag)}" for tag, length in parse_dol(value)]


DECODERS = {
    "95": decode_tvr,
    "9B": decode_tsi,
    "82": decode_aip,
    "8E": decode_cvm_list,
    "9F34": decode_cvm_results,
    "9F27": decode_cid,
    "8C": decode_dol,
    "8D": decode_dol,
    "9F38": decode_dol,
}


def explain(tag: str, value: bytes) -> list[str]:
    decoder = DECODERS.get(tag.upper())
    return decoder(value) if decoder else []
