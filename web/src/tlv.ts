// BER-TLV parsing, mirroring python/src/emv_tlv/tlv.py.

export interface Tlv {
  tag: string;
  value: Uint8Array;
  children: Tlv[];
}

export class TlvError extends Error {}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 || /[^0-9a-fA-F]/.test(clean)) {
    throw new TlvError("Input is not valid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function isConstructed(tag: string): boolean {
  return (parseInt(tag.slice(0, 2), 16) & 0x20) !== 0;
}

function readTag(data: Uint8Array, i: number): [string, number] {
  const start = i;
  if ((data[i] & 0x1f) === 0x1f) {
    i++;
    while (i < data.length && data[i] & 0x80) i++;
    if (i >= data.length) throw new TlvError(`Tag at offset ${start} is truncated`);
  }
  i++;
  return [bytesToHex(data.slice(start, i)), i];
}

function readLength(data: Uint8Array, i: number): [number, number] {
  if (i >= data.length) throw new TlvError(`Missing length at offset ${i}`);
  const first = data[i];
  if (first < 0x80) return [first, i + 1];
  const count = first & 0x7f;
  if (count === 0 || count > 3) {
    throw new TlvError(`Unsupported length form 0x${first.toString(16).toUpperCase()} at offset ${i}`);
  }
  if (i + 1 + count > data.length) throw new TlvError(`Length at offset ${i} is truncated`);
  let length = 0;
  for (let k = 1; k <= count; k++) length = (length << 8) | data[i + k];
  return [length, i + 1 + count];
}

export function parse(input: Uint8Array | string): Tlv[] {
  const data = typeof input === "string" ? hexToBytes(input) : input;
  const items: Tlv[] = [];
  let i = 0;
  while (i < data.length) {
    if (data[i] === 0x00 || data[i] === 0xff) {
      i++;
      continue;
    }
    let tag: string;
    let length: number;
    [tag, i] = readTag(data, i);
    [length, i] = readLength(data, i);
    if (i + length > data.length) {
      throw new TlvError(`Tag ${tag} declares ${length} bytes but only ${data.length - i} remain`);
    }
    const value = data.slice(i, i + length);
    i += length;
    items.push({ tag, value, children: isConstructed(tag) ? parse(value) : [] });
  }
  return items;
}

export function parseDol(data: Uint8Array): Array<[string, number]> {
  const entries: Array<[string, number]> = [];
  let i = 0;
  while (i < data.length) {
    let tag: string;
    let length: number;
    [tag, i] = readTag(data, i);
    [length, i] = readLength(data, i);
    entries.push([tag, length]);
  }
  return entries;
}
