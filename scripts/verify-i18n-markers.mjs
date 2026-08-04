#!/usr/bin/env node
// Assert that a label rendered through <Field required> does not also carry a
// "*" of its own.
//
// Field draws the required marker itself. A label string ending in "*" then
// renders as "Name * *", which is exactly what shipped when the console forms
// were migrated onto the shared primitive — visible only in a screenshot, since
// nothing about it fails to compile.
//
// The check is deliberately scoped: labels still rendered by hand-rolled blocks
// keep their own marker, and stripping those would leave required fields
// unmarked. So this reads the actual call sites rather than every key — a form
// migrated onto Field(required) is caught the moment its label is not stripped.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WEB = join(ROOT, "web");
const LOCALES = join(WEB, "packages/shared/src/i18n/locales");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".tsx")) out.push(p);
  }
  return out;
}

// Find `<Field ... required ...>` and pull the t('...') out of its label.
// Both attribute orders occur, and the element is usually multi-line.
const FIELD_BLOCK = /<Field\b([^>]*?)>/gs;
const LABEL_T = /label=\{t\(\s*['"]([^'"]+)['"]/;

const used = new Map(); // key -> Set of files
for (const file of walk(join(WEB, "apps"))) {
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(FIELD_BLOCK)) {
    const attrs = m[1];
    if (!/\brequired\b/.test(attrs)) continue;
    // `required={!editing}` still draws the marker in the required case.
    const label = attrs.match(LABEL_T);
    if (!label) continue;
    const rel = file.slice(WEB.length + 1);
    if (!used.has(label[1])) used.set(label[1], new Set());
    used.get(label[1]).add(rel);
  }
}

function loadLocale(name) {
  const src = readFileSync(join(LOCALES, name), "utf8");
  // Anchor on the export, not the first brace: the file header is a comment
  // that itself mentions "{{var}}" interpolation.
  const at = src.indexOf("export default");
  if (at < 0) throw new Error(`${name}: no default export`);
  const body = src.slice(src.indexOf("{", at), src.lastIndexOf("}") + 1);
  return new Function(`return ${body}`)();
}

function lookup(obj, dotted) {
  let cur = obj;
  for (const part of dotted.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = cur[part];
  }
  return typeof cur === "string" ? cur : undefined;
}

const locales = readdirSync(LOCALES).filter((f) => f.endsWith(".ts"));
let failed = 0;

for (const localeFile of locales) {
  const messages = loadLocale(localeFile);
  for (const [key, files] of used) {
    const value = lookup(messages, key);
    if (value === undefined) {
      console.error(
        `✗ ${localeFile}: ${key} is used as a <Field required> label ` +
          `(${[...files].join(", ")}) but is missing from this locale`,
      );
      failed++;
      continue;
    }
    if (/\*\s*$/.test(value)) {
      console.error(
        `✗ ${localeFile}: ${key} = ${JSON.stringify(value)}\n` +
          `  It is rendered through <Field required> (${[...files].join(", ")}), which draws\n` +
          `  the marker itself — this renders as "${value} *". Drop the trailing asterisk.`,
      );
      failed++;
    }
  }
}

if (failed) {
  console.error(`\n✗ verify-i18n-markers: ${failed} problem(s)`);
  process.exit(1);
}
console.log(`✓ verify-i18n-markers: ${used.size} required labels × ${locales.length} locales OK`);
