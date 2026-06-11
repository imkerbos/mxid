#!/usr/bin/env node
// Walk every web/{apps,packages}/* package.json and assert every path
// referenced in `main`, `module`, `types`, `exports`, `bin` exists on disk.
// Catches drift like `"./ui": "./src/ui/index.ts"` when the file is `.tsx`.

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WEB = join(ROOT, "web");

const pkgDirs = [];
for (const sub of ["apps", "packages"]) {
  const base = join(WEB, sub);
  if (!existsSync(base)) continue;
  for (const name of readdirSync(base)) {
    const dir = join(base, name);
    if (statSync(dir).isDirectory() && existsSync(join(dir, "package.json"))) {
      pkgDirs.push(dir);
    }
  }
}

const errors = [];

function checkPath(pkgDir, pkgName, field, relPath) {
  if (typeof relPath !== "string") return;
  // Skip URL / non-local refs.
  if (relPath.startsWith("http") || relPath.startsWith("#")) return;
  const abs = resolve(pkgDir, relPath);
  if (!existsSync(abs)) {
    errors.push(`${pkgName} ${field} -> ${relPath} (resolved ${abs}) missing`);
  }
}

function walkExports(pkgDir, pkgName, node, trail = "exports") {
  if (node == null) return;
  if (typeof node === "string") {
    checkPath(pkgDir, pkgName, trail, node);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkExports(pkgDir, pkgName, v, `${trail}[${i}]`));
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      walkExports(pkgDir, pkgName, v, `${trail}.${k}`);
    }
  }
}

for (const pkgDir of pkgDirs) {
  const pkgPath = join(pkgDir, "package.json");
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch (e) {
    errors.push(`${pkgPath}: parse error ${e.message}`);
    continue;
  }
  const name = pkg.name ?? pkgDir;
  for (const f of ["main", "module", "types", "browser"]) {
    if (pkg[f]) checkPath(pkgDir, name, f, pkg[f]);
  }
  if (pkg.exports) walkExports(pkgDir, name, pkg.exports);
  if (pkg.bin) {
    if (typeof pkg.bin === "string") checkPath(pkgDir, name, "bin", pkg.bin);
    else for (const [k, v] of Object.entries(pkg.bin)) checkPath(pkgDir, name, `bin.${k}`, v);
  }
}

if (errors.length) {
  console.error("✗ verify-exports: broken package.json paths");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}
console.log(`✓ verify-exports: ${pkgDirs.length} packages OK`);
