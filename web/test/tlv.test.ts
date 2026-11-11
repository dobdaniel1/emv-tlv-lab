import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBits, decodeCid, decodeCvmList, decodeCvmResults, explain, tagName } from "../src/decoders.ts";
import { maskValue, toRows } from "../src/render.ts";
import { SAMPLE_FIELD_55 } from "../src/sample.ts";
import { TlvError, bytesToHex, hexToBytes, parse, parseDol } from "../src/tlv.ts";

test("parses the sample field 55", () => {
  const items = parse(SAMPLE_FIELD_55);
  assert.equal(items.length, 13);
  assert.equal(items[0].tag, "9F26");
  assert.equal(bytesToHex(items[0].value), "1122334455667788");
});

test("nests constructed tags", () => {
  const [fci] = parse("6F0F8407A0000000031010A50450025649");
  assert.equal(fci.children.length, 2);
  assert.equal(fci.children[1].children[0].tag, "50");
});

test("skips padding and reads long lengths", () => {
  assert.deepEqual(parse("00009F270180FF").map((t) => t.tag), ["9F27"]);
  const long = parse("9F1081C8" + "00".repeat(200));
  assert.equal(long[0].value.length, 200);
});

for (const bad of ["9F", "9F27", "9F2702", "9F27820001", "9F278500", "ZZ", "123"]) {
  test(`rejects malformed input ${bad}`, () => assert.throws(() => parse(bad), TlvError));
}

test("decodes TVR, TSI and AIP bits", () => {
  assert.deepEqual(decodeBits("95", hexToBytes("0000008000")), ["Transaction exceeds floor limit"]);
  assert.deepEqual(decodeBits("95", hexToBytes("0000000001")), ["RFU (byte 5 bit 1)"]);
  assert.equal(decodeBits("9B", hexToBytes("E800")).length, 4);
  assert.ok(decodeBits("82", hexToBytes("3900")).includes("CDA supported"));
  assert.throws(() => decodeBits("95", hexToBytes("00")), TlvError);
});

test("decodes CVM values and CID", () => {
  assert.equal(decodeCvmResults(hexToBytes("420300"))[0], "Method: Enciphered PIN verified online");
  assert.throws(() => decodeCvmResults(hexToBytes("00")), TlvError);
  const list = decodeCvmList(hexToBytes("00000000000027104203" + "1F00"));
  assert.deepEqual(list.slice(0, 2), ["Amount X: 0", "Amount Y: 10000"]);
  assert.match(list[2], /next rule$/);
  assert.throws(() => decodeCvmList(hexToBytes("00")), TlvError);
  assert.deepEqual(decodeCid(hexToBytes("88")), ["Cryptogram: ARQC (go online)", "Advice required"]);
  assert.throws(() => decodeCid(new Uint8Array()), TlvError);
});

test("explains DOLs and names tags", () => {
  assert.deepEqual(parseDol(hexToBytes("9F02069F3704")), [["9F02", 6], ["9F37", 4]]);
  assert.deepEqual(explain("9F38", hexToBytes("9F6604")), ["9F66 (4 bytes) Terminal Transaction Qualifiers (TTQ)"]);
  assert.deepEqual(explain("9F02", hexToBytes("00")), []);
  assert.equal(tagName("df01"), "Unknown tag");
});

test("masks card data in rows", () => {
  const rows = toRows(parse("70125A08411111111111111" + "15F2005544553542F"));
  assert.equal(rows[1].value, "411111******1111");
  assert.equal(rows[2].value, "*****");
  assert.equal(maskValue("57", hexToBytes("4111111111111111D28122011F")), "411111******1111D********");
  const clear = toRows(parse("5A084111111111111111"), false);
  assert.equal(clear[0].value, "4111111111111111");
});

test("rows show text and decode errors", () => {
  const rows = toRows(parse("500456495341950100"));
  assert.equal(rows[0].value, "56495341 (VISA)");
  assert.match(rows[1].meanings[0], /^Cannot decode/);
});
