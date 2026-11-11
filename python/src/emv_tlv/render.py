from .decoders import explain
from .dictionary import tag_info
from .errors import TlvError
from .tlv import Tlv


def mask(tag: str, value: bytes) -> str:
    """PAN and track 2 keep first 6 and last 4 digits; names are hidden."""
    text = value.hex().upper()
    if tag == "5F20":
        return "*" * len(value)
    if tag in ("5A", "57"):
        digits = text.rstrip("F")
        sep = digits.find("D")
        pan, rest = (digits, "") if sep < 0 else (digits[:sep], digits[sep:])
        if len(pan) > 10:
            pan = pan[:6] + "*" * (len(pan) - 10) + pan[-4:]
        return pan + ("D" + "*" * (len(rest) - 1) if rest else "")
    return text


def _display(tag: str, value: bytes, masked: bool) -> str:
    info = tag_info(tag)
    if masked and info.get("sensitive"):
        return mask(tag, value)
    if info.get("format") in ("ans", "an") and all(0x20 <= b < 0x7F for b in value):
        return f"{value.hex().upper()} ({value.decode('ascii')})"
    return value.hex().upper()


def render(items: list[Tlv], masked: bool = True, depth: int = 0) -> str:
    lines = []
    pad = "  " * depth
    for item in items:
        name = tag_info(item.tag).get("name", "Unknown tag")
        if item.children:
            lines.append(f"{pad}{item.tag} {name} [{item.length}]")
            lines.append(render(item.children, masked, depth + 1))
            continue
        lines.append(
            f"{pad}{item.tag} {name} [{item.length}] {_display(item.tag, item.value, masked)}"
        )
        try:
            meanings = explain(item.tag, item.value)
        except TlvError as exc:
            meanings = [f"Cannot decode: {exc}"]
        lines += [f"{pad}    - {m}" for m in meanings]
    return "\n".join(lines)
