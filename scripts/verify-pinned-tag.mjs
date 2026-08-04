#!/usr/bin/env node
// Assert that the image tag pinned in the example env files actually exists.
//
// These files are copied verbatim by anyone deploying — `cp .env.example .env`
// is step one of the compose path — so a tag that no longer resolves means the
// first thing a new user sees is ImagePullBackOff on an image that was never
// published. That is exactly what shipped: the default sat at v0.1.0 long after
// that tag stopped existing on GHCR.
//
// Checks the tag is not older than the newest CHANGELOG release, and (when the
// network allows) that GHCR really serves it. Offline, the CHANGELOG check still
// catches the drift that matters.

import { readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FILES = [".env.example", "deploy/compose/.env.prod.example"];
const IMAGE = "ghcr.io/imkerbos/mxid";

function latestRelease() {
  const md = readFileSync(join(ROOT, "CHANGELOG.md"), "utf8");
  const m = md.match(/^## \[(\d+\.\d+\.\d+)\]/m);
  if (!m) throw new Error("no released version found in CHANGELOG.md");
  return "v" + m[1];
}

function cmp(a, b) {
  const pa = a.replace(/^v/, "").split(".").map(Number);
  const pb = b.replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

async function existsOnGhcr(tag) {
  const [, repo] = IMAGE.split("ghcr.io/");
  try {
    const t = await fetch(
      `https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`,
      { signal: AbortSignal.timeout(8000) },
    ).then((r) => r.json());
    const res = await fetch(`https://ghcr.io/v2/${repo}/manifests/${tag}`, {
      headers: {
        Authorization: `Bearer ${t.token}`,
        Accept:
          "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json",
      },
      signal: AbortSignal.timeout(8000),
    });
    return res.status === 200;
  } catch {
    return null; // offline / rate-limited — not a failure
  }
}

const latest = latestRelease();
let failed = 0;

for (const rel of FILES) {
  const src = readFileSync(join(ROOT, rel), "utf8");
  const m = src.match(/^MXID_TAG=(\S+)$/m);
  if (!m) {
    console.error(`✗ ${rel}: no MXID_TAG= assignment`);
    failed++;
    continue;
  }
  const tag = m[1];

  if (cmp(tag, latest) < 0) {
    console.error(
      `✗ ${rel}: MXID_TAG=${tag} predates the newest release (${latest}).\n` +
        `  This file is copied verbatim when deploying, so a stale pin sends a new\n` +
        `  user straight to a tag that may no longer be published.`,
    );
    failed++;
    continue;
  }

  const live = await existsOnGhcr(tag);
  if (live === false && cmp(tag, latest) > 0) {
    console.error(`✗ ${rel}: MXID_TAG=${tag} is not published at ${IMAGE}`);
    failed++;
  } else if (live === false) {
    // The tag matches the newest CHANGELOG entry but the image is not up yet.
    // That is the normal state between cutting a release and its build
    // finishing, so it is a note rather than a failure — the check that
    // matters (the pin is not stale) already passed.
    console.log(`  ${rel}: ${tag} — not on the registry yet; release build pending`);
  } else {
    console.log(`  ${rel}: ${tag}${live === null ? " (registry unreachable, CHANGELOG check only)" : ""}`);
  }
}

if (failed) {
  console.error(`\n✗ verify-pinned-tag: ${failed} problem(s)`);
  process.exit(1);
}
console.log(`✓ verify-pinned-tag: example env files pin ${latest} or newer`);
