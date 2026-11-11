// Bit field and coded value meanings, driven by the shared emv.json.

import spec from "../../python/src/emv_tlv/emv.json" with { type: "json" };
import { TlvError, parseDol } from "./tlv.ts";

type Table = Record<string, string>;
const bits = spec.bits as Record<string, (string | null)[][]>;
const tags = spec.tags as Record<string, { name: string; format: string; sensitive?: boolean }>;

export function tagInfo(tag: string) {
  return tags[tag.toUpperCase()];
}

export function tagName(tag: string): string {
  return tagInfo(tag)?.name ?? "Unknown tag";
}

const hex2 = (n: number) => n.toString(16).padStart(2, "0").toUpperCase();

export function decodeBits(tag: string, value: Uint8Array): string[] {
  const table = bits[tag];
  if (value.length !== table.length) {
    throw new TlvError(`Tag ${tag} must be ${table.length} bytes, got ${value.length}`);
  }
  const found: string[] = [];
  table.forEach((names, byteIndex) => {
    names.forEach((name, pos) => {
      const bit = 8 - pos;
      if (value[byteIndex] & (1 << (bit - 1))) found.push(name ?? `RFU (byte ${byteIndex + 1} bit ${bit})`);
    });
  });
  return found;
}

function cvmMethod(code: number): string {
  return (spec.cvm_codes as Table)[hex2(code & 0x3f)] ?? "Unknown CVM";
}

function cvmCondition(code: number): string {
  return (spec.cvm_conditions as Table)[hex2(code)] ?? "Unknown condition";
}

export function decodeCvmResults(value: Uint8Array): string[] {
  if (value.length !== 3) throw new TlvError("CVM Results must be 3 bytes");
  return [
    `Method: ${cvmMethod(value[0])}`,
    `Condition: ${cvmCondition(value[1])}`,
    `Result: ${(spec.cvm_results as Table)[hex2(value[2])] ?? "Unknown"}`,
  ];
}

export function decodeCvmList(value: Uint8Array): string[] {
  if (value.length < 8 || value.length % 2) {
    throw new TlvError("CVM List must be 8 bytes of amounts plus 2-byte rules");
  }
  const view = new DataView(value.buffer, value.byteOffset);
  const lines = [`Amount X: ${view.getUint32(0)}`, `Amount Y: ${view.getUint32(4)}`];
  for (let i = 8, n = 1; i < value.length; i += 2, n++) {
    const then = value[i] & 0x40 ? "next rule" : "fail";
    lines.push(`Rule ${n}: ${cvmMethod(value[i])} | ${cvmCondition(value[i + 1])} | on failure: ${then}`);
  }
  return lines;
}

export function decodeCid(value: Uint8Array): string[] {
  if (value.length !== 1) throw new TlvError("CID must be 1 byte");
  const lines = [`Cryptogram: ${(spec.cryptogram_types as Table)[String(value[0] >> 6)]}`];
  if (value[0] & 0x08) lines.push("Advice required");
  return lines;
}

function decodeDol(value: Uint8Array): string[] {
  return parseDol(value).map(([tag, len]) => `${tag} (${len} bytes) ${tagName(tag)}`);
}

const DECODERS: Record<string, (v: Uint8Array) => string[]> = {
  "95": (v) => decodeBits("95", v),
  "9B": (v) => decodeBits("9B", v),
  "82": (v) => decodeBits("82", v),
  "8E": decodeCvmList,
  "9F34": decodeCvmResults,
  "9F27": decodeCid,
  "8C": decodeDol,
  "8D": decodeDol,
  "9F38": decodeDol,
};

export function explain(tag: string, value: Uint8Array): string[] {
  const decoder = DECODERS[tag.toUpperCase()];
  return decoder ? decoder(value) : [];
}
