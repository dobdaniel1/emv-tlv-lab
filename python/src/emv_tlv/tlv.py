"""BER-TLV parsing and encoding as used by EMV (EMV Book 3, Annex B)."""

from dataclasses import dataclass, field

from .errors import TlvError

PADDING = (0x00, 0xFF)


@dataclass
class Tlv:
    tag: str
    value: bytes
    children: list["Tlv"] = field(default_factory=list)

    @property
    def constructed(self) -> bool:
        return bool(bytes.fromhex(self.tag)[0] & 0x20)

    @property
    def length(self) -> int:
        return len(self.value)

    def find(self, tag: str) -> "Tlv | None":
        return find(self.children, tag)


def _read_tag(data: bytes, i: int) -> tuple[str, int]:
    start = i
    if data[i] & 0x1F == 0x1F:
        i += 1
        while i < len(data) and data[i] & 0x80:
            i += 1
        if i >= len(data):
            raise TlvError(f"Tag at offset {start} is truncated")
    i += 1
    return data[start:i].hex().upper(), i


def _read_length(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise TlvError(f"Missing length at offset {i}")
    first = data[i]
    if first < 0x80:
        return first, i + 1
    count = first & 0x7F
    if count == 0 or count > 3:
        raise TlvError(f"Unsupported length form 0x{first:02X} at offset {i}")
    raw = data[i + 1 : i + 1 + count]
    if len(raw) != count:
        raise TlvError(f"Length at offset {i} is truncated")
    return int.from_bytes(raw, "big"), i + 1 + count


def parse(data: bytes | str) -> list[Tlv]:
    """Parse a sequence of TLV objects. Constructed tags are parsed recursively."""
    if isinstance(data, str):
        try:
            data = bytes.fromhex("".join(data.split()))
        except ValueError:
            raise TlvError("Input is not valid hex") from None

    items, i = [], 0
    while i < len(data):
        if data[i] in PADDING:
            i += 1
            continue
        tag, i = _read_tag(data, i)
        length, i = _read_length(data, i)
        value = data[i : i + length]
        if len(value) != length:
            raise TlvError(f"Tag {tag} declares {length} bytes but only {len(value)} remain")
        i += length
        node = Tlv(tag, value)
        if node.constructed:
            node.children = parse(value)
        items.append(node)
    return items


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode(items: list[Tlv]) -> bytes:
    out = bytearray()
    for item in items:
        value = encode(item.children) if item.children else item.value
        out += bytes.fromhex(item.tag) + encode_length(len(value)) + value
    return bytes(out)


def find(items: list[Tlv], tag: str) -> Tlv | None:
    """Depth-first search for the first object with this tag."""
    tag = tag.upper()
    for item in items:
        if item.tag == tag:
            return item
        found = find(item.children, tag)
        if found:
            return found
    return None


def parse_dol(data: bytes) -> list[tuple[str, int]]:
    """Parse a Data Object List (PDOL, CDOL): tag and length pairs, no values."""
    entries, i = [], 0
    while i < len(data):
        tag, i = _read_tag(data, i)
        length, i = _read_length(data, i)
        entries.append((tag, length))
    return entries
