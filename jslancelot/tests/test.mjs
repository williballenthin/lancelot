// mirrors pylancelot/tests/test_pylancelot.py
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { getBinExport2BytesFromBytes } from "../index.js";

// test fixtures are shared with the Python bindings.
const k32 = await readFile(new URL("../../pylancelot/tests/data/k32.dll_", import.meta.url));
const altsvc = await readFile(new URL("../../pylancelot/tests/data/altsvc.c.obj", import.meta.url));
const eh_prolog_pat = await readFile(new URL("../../pyflirt/tests/data/__EH_prolog3.pat", import.meta.url));
const eh_prolog_sig = await readFile(new URL("../../pyflirt/tests/data/__EH_prolog3.sig", import.meta.url));

test("binexport2", async () => {
  const buf = await getBinExport2BytesFromBytes(k32);
  assert.ok(buf instanceof Uint8Array);
  assert.ok(buf.length > 0);
});

test("invalid pe", async () => {
  await assert.rejects(getBinExport2BytesFromBytes(new Uint8Array()));
  await assert.rejects(getBinExport2BytesFromBytes(Uint8Array.from([0x4d, 0x5a, 0x90, 0x30, 0x30])));
});

test("load pe", async () => {
  await getBinExport2BytesFromBytes(k32);
});

test("load coff", async () => {
  await getBinExport2BytesFromBytes(altsvc);
});

test("hint function", async () => {
  // 7dd70e00  int32_t* __stdcall _GetStartupInfoA@4(int32_t* arg1)
  // 7dd70e00  8bff               mov     edi, edi
  // 7dd70e02  55                 push    ebp {__saved_ebp}
  await getBinExport2BytesFromBytes(k32, { functionHints: [0x7dd70e02] });
});

test("flirt signatures from bytes", async () => {
  // both the compiled (.sig) and textual (.pat) formats,
  // recognized by content rather than filename.
  await getBinExport2BytesFromBytes(k32, { sigs: [eh_prolog_sig, eh_prolog_pat] });
});

test("executable id", async () => {
  const buf = await getBinExport2BytesFromBytes(k32, { executableId: "k32.dll" });
  assert.ok(buf.length > 0);
});
