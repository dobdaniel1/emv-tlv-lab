import { explain, tagInfo, tagName } from "./decoders.ts";
import { type Tlv, TlvError, bytesToHex } from "./tlv.ts";

export interface Row {
  depth: number;
  tag: string;
  name: string;
  length: number;
  value: string;
  meanings: string[];
}

export function maskValue(tag: string, value: Uint8Array): string {
  if (tag === "5F20") return "*".repeat(value.length);
  const digits = bytesToHex(value).replace(/F+$/, "");
  const sep = digits.indexOf("D");
  let pan = sep < 0 ? digits : digits.slice(0, sep);
  const rest = sep < 0 ? "" : digits.slice(sep);
  if (pan.length > 10) pan = pan.slice(0, 6) + "*".repeat(pan.length - 10) + pan.slice(-4);
  return pan + (rest ? "D" + "*".repeat(rest.length - 1) : "");
}

function display(tag: string, value: Uint8Array, masked: boolean): string {
  const info = tagInfo(tag);
  if (masked && info?.sensitive) return maskValue(tag, value);
  const hex = bytesToHex(value);
  if ((info?.format === "an" || info?.format === "ans") && value.every((b) => b >= 0x20 && b < 0x7f)) {
    return `${hex} (${String.fromCharCode(...value)})`;
  }
  return hex;
}

export function toRows(items: Tlv[], masked = true, depth = 0): Row[] {
  return items.flatMap((item) => {
    const base = { depth, tag: item.tag, name: tagName(item.tag), length: item.value.length };
    if (item.children.length) {
      return [{ ...base, value: "", meanings: [] }, ...toRows(item.children, masked, depth + 1)];
    }
    let meanings: string[];
    try {
      meanings = explain(item.tag, item.value);
    } catch (err) {
      meanings = [`Cannot decode: ${(err as TlvError).message}`];
    }
    return [{ ...base, value: display(item.tag, item.value, masked), meanings }];
  });
}
