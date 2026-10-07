#!/usr/bin/env node
// Medusa browser sidecar: the executable behind the `browser` tool.
// Loads a page in headless Chromium via Playwright, records network
// traffic (XHR/fetch/document), and prints one JSON object on stdout:
//
//   { "url": ..., "title": ..., "finalUrl": ..., "requests": [...],
//     "endpoints": [...] }
//
// Contract: `browser-observe --url <target> [--wait ms] [--json]`
// The --json flag is accepted for interface symmetry; output is always
// JSON on stdout. Exit codes: 0 success, 2 usage error, 3 navigation
// error, 4 playwright not importable (install + `playwright install`).

const args = process.argv.slice(2);
function opt(name) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}
const url = opt("--url") || args.find((a) => !a.startsWith("-")) || null;
const waitMs = parseInt(opt("--wait") || "12000", 10);
const settleMs = parseInt(opt("--settle") || "3000", 10);

if (!url) {
  console.error("usage: browser-observe --url <target> [--wait ms] [--settle ms]");
  process.exit(2);
}

async function loadPlaywright() {
  // Try normal resolution first (local node_modules), then the global
  // npm root (`npm install -g playwright` puts the package there).
  try {
    return await import("playwright");
  } catch {
    const { execSync } = await import("node:child_process");
    let globalRoot = "";
    try {
      globalRoot = execSync("npm root -g", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      throw new Error("playwright not importable and `npm root -g` failed");
    }
    const { createRequire } = await import("node:module");
    const req = createRequire(globalRoot + "/noop.js");
    return req("playwright");
  }
}

const requests = [];
const seen = new Set();

function record(request, response) {
  const r = {
    url: request.url(),
    method: request.method(),
    type: request.resourceType(),
    status: response ? response.status() : null,
  };
  requests.push(r);
}

const pw = await loadPlaywright().catch((e) => {
  console.error(String(e));
  process.exit(4);
});

const browser = await pw.chromium.launch({ headless: true });
try {
  const page = await browser.newPage({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 MedusaSidecar/1",
  });
  page.on("request", (req) => record(req, null));
  page.on("response", (res) => {
    const req = res.request();
    const last = [...requests].reverse().find((r) => r.url === req.url());
    if (last) last.status = res.status();
  });

  let finalUrl = url;
  let title = null;
  try {
    const resp = await page.goto(url, { waitUntil: "domcontentloaded", timeout: waitMs });
    if (resp) {
      const first = [...requests].reverse().find((r) => r.url === resp.url());
      if (first) first.status = resp.status();
    }
    finalUrl = page.url();
    title = await page.title().catch(() => null);
    // Give SPAs time to fire their XHR/fetch calls after first paint.
    await page.waitForLoadState("networkidle", { timeout: settleMs }).catch(() => {});
  } catch (e) {
    console.error(`navigation failed: ${e && e.message ? e.message : e}`);
    process.exit(3);
  }

  // API-ish endpoints: XHR/fetch plus document navigations, deduped,
  // same-origin relative to the final page URL.
  let origin = null;
  try {
    origin = new URL(finalUrl).origin;
  } catch {}
  const endpoints = [];
  for (const r of requests) {
    if (r.type !== "xhr" && r.type !== "fetch" && r.type !== "document") continue;
    let path = r.url;
    try {
      const u = new URL(r.url);
      if (origin && u.origin !== origin) continue;
      path = u.pathname + (u.search || "");
    } catch {
      continue;
    }
    if (path === "/" || path === "") continue;
    const key = `${r.method} ${path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({ method: r.method, path, status: r.status });
  }

  const out = { url, finalUrl, title, requests: requests.slice(0, 500), endpoints };
  console.log(JSON.stringify(out));
} finally {
  await browser.close().catch(() => {});
}
