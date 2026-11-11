import { toRows } from "./render.ts";
import { SAMPLE_FIELD_55 } from "./sample.ts";
import { parse } from "./tlv.ts";

const input = document.querySelector<HTMLTextAreaElement>("#input")!;
const mask = document.querySelector<HTMLInputElement>("#mask")!;
const output = document.querySelector<HTMLTableSectionElement>("#output")!;
const error = document.querySelector<HTMLParagraphElement>("#error")!;

function cell(row: HTMLTableRowElement, text: string, className = ""): HTMLTableCellElement {
  const td = row.insertCell();
  td.textContent = text;
  td.className = className;
  return td;
}

function update(): void {
  output.replaceChildren();
  error.textContent = "";
  if (!input.value.trim()) return;
  try {
    for (const r of toRows(parse(input.value), mask.checked)) {
      const tr = output.insertRow();
      cell(tr, r.tag, "tag").style.paddingLeft = `${0.75 + r.depth * 1.25}rem`;
      cell(tr, r.name);
      cell(tr, String(r.length), "num");
      const value = cell(tr, r.value, "value");
      if (r.meanings.length) {
        const list = document.createElement("ul");
        for (const m of r.meanings) list.appendChild(document.createElement("li")).textContent = m;
        value.appendChild(list);
      }
    }
  } catch (err) {
    error.textContent = (err as Error).message;
  }
}

document.querySelector("#sample")!.addEventListener("click", () => {
  input.value = SAMPLE_FIELD_55;
  update();
});
input.addEventListener("input", update);
mask.addEventListener("change", update);
