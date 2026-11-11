import argparse
import sys

from .decoders import explain
from .errors import TlvError
from .render import render
from .tlv import parse

SHORTCUTS = {"tvr": "95", "tsi": "9B", "aip": "82", "cvm": "9F34", "cid": "9F27", "cvmlist": "8E"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="emv-tlv", description="Decode EMV TLV data")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("decode", help="decode a TLV hex string, for example field 55")
    d.add_argument("hex")
    d.add_argument("--no-mask", action="store_true")

    for name, tag in SHORTCUTS.items():
        s = sub.add_parser(name, help=f"explain a raw tag {tag} value")
        s.add_argument("hex")
        s.set_defaults(tag=tag)

    args = parser.parse_args(argv)
    try:
        if args.command == "decode":
            print(render(parse(args.hex), masked=not args.no_mask))
        else:
            meanings = explain(args.tag, bytes.fromhex(args.hex))
            print("\n".join(meanings) if meanings else "No bits set")
    except (TlvError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
