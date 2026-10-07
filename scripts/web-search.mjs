#!/usr/bin/env node
// Medusa web-search sidecar (browser fallback). The plain HTTP path
// (html.duckduckgo.com) serves a 202 bot challenge to non-browser
// clients after a few queries; a real headless Chromium passes it. This
// script searches DuckDuckGo in the browser and prints ONE JSON object:
//
//   { "query": ..., "results": [{ "title": ..., "url": ..., "snippet": ... }] }
//
// Contract: `web-search --query <q>`. Exit codes: 0 success, 2 usage
// error, 3 navigation/extraction error, 4 playwright not importable.

const args = process.argv.slice(2);
function opt(name) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}
const query = opt("--query");

if (!query || !query.trim()) {
  console.error("usage: web-search --query <search terms>");
  process.exit(2);
}

async function loadPlaywright() {
  // Local node_modules first, then the global npm root (npm install -g).
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

const pw = await loadPlaywright().catch((e) => {
  console.error(String(e));
  process.exit(4);
});

function extractResults() {
  // Run in the page: collect result__a links, unwrapping DDG's
  // redirect-wrapped hrefs (uddg param carries the real target).
  const out = [];
  const links = document.querySelectorAll("a.result__a");
  const snippets = [...document.querySelectorAll(".result__snippet")].map((s) =>
    s.textContent.replace(/\s+/g, " ").trim()
  );
  links.forEach((a, i) => {
    let url = a.href || "";
    try {
      const u = new URL(a.href, location.href);
      const uddg = u.searchParams.get("uddg");
      if (uddg) url = uddg;
    } catch {
      /* keep a.href */
    }
    out.push({
      title: (a.textContent || "").replace(/\s+/g, " ").trim(),
      url,
      snippet: snippets[i] || "",
    });
  });
  return out.slice(0, 10);
}

const browser = await pw.chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const targets = [
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
    `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}`,
  ];
  let results = null;
  let lastErr = "";
  for (const url of targets) {
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
      // The anomaly challenge (if any) self-resolves in a real browser
      // via JS + reload; wait for actual results to appear.
      await page.waitForSelector("a.result__a, a.result-link", { timeout: 20000 });
      results = await page.evaluate(extractResults);
      if (results && results.length > 0) break;
    } catch (e) {
      lastErr = String(e && e.message ? e.message : e);
    }
  }
  if (!results) {
    console.error(`no results extracted (${lastErr || "empty page"})`);
    process.exit(3);
  }
  console.log(JSON.stringify({ query, engine: "duckduckgo-browser", results }));
} finally {
  await browser.close().catch(() => {});
}
