#!/usr/bin/env node
// medusa-oob.mjs — one-shot out-of-band (OOB) callback orchestration around
// interactsh-client (ProjectDiscovery). The raw client polls forever and
// cannot be executed one-shot, so this sidecar manages a DETACHED background
// client plus a small state file under <state_dir>/oob/.
//
// Actions (--action, default "check"):
//   start — register a listener; prints the callback URL as a JSON line
//   check — print collected interactions as JSON lines
//   stop  — stop the background client and clear state
//
// Output is JSON Lines shaped for medusa's interactsh parser
// ({protocol, full_id, host, summary, ...}); errors print {"error": ...}.
// A listener auto-expires after 30 minutes if never stopped explicitly.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const OOB_DIR = join(SCRIPT_DIR, "..", "oob");
const STATE = join(OOB_DIR, "state.json");
const INTERACTIONS = join(OOB_DIR, "interactions.jsonl");
const CLIENT_LOG = join(OOB_DIR, "client.log");
const SESSION_TTL_MS = 30 * 60 * 1000;
const URL_RE = /([a-z0-9]+\.(?:oast\.[a-z]+|interact\.sh))/i;

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}
function fail(msg) {
  emit({ error: String(msg) });
  process.exit(1);
}
function argOf(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : def;
}
function readState() {
  if (!existsSync(STATE)) return null;
  try {
    return JSON.parse(readFileSync(STATE, "utf8"));
  } catch {
    return null;
  }
}
function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

// Locate the interactsh-client binary. libuv does not auto-append .exe on
// Windows for extensionless commands, so probe explicitly.
function clientCommand() {
  const candidates =
    process.platform === "win32"
      ? ["interactsh-client.exe", "interactsh-client"]
      : ["interactsh-client"];
  for (const cmd of candidates) {
    try {
      const probe = spawnSync(cmd, ["-version"], { stdio: "ignore", timeout: 20000 });
      if (!probe.error) return cmd;
    } catch {
      /* try next candidate */
    }
  }
  fail(
    "interactsh-client not found on PATH — install it: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  );
}

function stopListener(quiet) {
  const st = readState();
  if (st && isAlive(st.pid)) {
    try {
      process.kill(st.pid);
    } catch {
      /* already gone */
    }
  }
  rmSync(OOB_DIR, { recursive: true, force: true });
  if (!quiet) {
    emit({
      protocol: "oob-listener",
      full_id: "stopped",
      host: "stopped",
      summary: "OOB listener stopped and state cleared",
    });
  }
}

function startListener(target) {
  mkdirSync(OOB_DIR, { recursive: true });
  const st = readState();
  if (st && isAlive(st.pid) && Date.now() - st.startedAt < SESSION_TTL_MS) {
    emit({
      protocol: "oob-listener",
      full_id: st.url,
      host: st.url,
      summary: `OOB listener already running (${st.url}) — embed it in payloads (SSRF/XXE/blind injection), then check`,
    });
    return;
  }
  if (st) stopListener(true);

  const cmd = clientCommand();
  rmSync(INTERACTIONS, { force: true });
  rmSync(CLIENT_LOG, { force: true });
  // Stderr goes to a FILE: the child is detached and must keep writing after
  // this sidecar exits (a broken pipe would kill it).
  const errFd = openSync(CLIENT_LOG, "a");
  const child = spawn(
    cmd,
    // -duc is load-bearing: the update check hangs without network to the
    // release API and registration never completes.
    ["-json", "-o", INTERACTIONS, "-pi", "3", "-n", "1", "-auth=false", "-duc"],
    { detached: true, stdio: ["ignore", "ignore", errFd] }
  );
  child.unref();

  // Registration prints "[INF] <payload-domain>" to stderr within a few
  // seconds; poll the log file until the URL appears.
  const deadline = Date.now() + 25000;
  (function waitForUrl() {
    let url = null;
    if (existsSync(CLIENT_LOG)) {
      const m = readFileSync(CLIENT_LOG, "utf8").match(URL_RE);
      if (m) url = m[1].toLowerCase();
    }
    if (url) {
      writeFileSync(
        STATE,
        JSON.stringify({ pid: child.pid, url, target, startedAt: Date.now() })
      );
      emit({
        protocol: "oob-listener",
        full_id: url,
        host: url,
        summary: `OOB listener started: ${url} — embed this URL in payloads (SSRF/XXE/blind injection), deliver them, then run action=check`,
      });
      return;
    }
    if (Date.now() > deadline) {
      try {
        process.kill(child.pid);
      } catch {}
      fail("interactsh-client did not register a payload URL in 25s (check network reachability to oast.pro)");
    }
    setTimeout(waitForUrl, 500);
  })();
}

function checkListener() {
  const st = readState();
  if (!st) {
    fail("no OOB listener running — run action=start first");
  }
  if (!isAlive(st.pid)) {
    fail("listener process died — restart with action=start");
  }
  if (Date.now() - st.startedAt > SESSION_TTL_MS) {
    stopListener(true);
    fail("listener expired after 30 min — restart with action=start");
  }

  const lines = existsSync(INTERACTIONS)
    ? readFileSync(INTERACTIONS, "utf8").split(/\r?\n/).filter(Boolean)
    : [];
  const parsed = [];
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line));
    } catch {
      /* skip partial line mid-write */
    }
  }

  const counts = {};
  const ips = new Set();
  for (const v of parsed) {
    const proto = v.protocol || "oob";
    counts[proto] = (counts[proto] || 0) + 1;
    if (v["remote-address"]) ips.add(v["remote-address"]);
  }

  const total = parsed.length;
  emit({
    protocol: "oob-summary",
    full_id: st.url,
    host: st.url,
    summary:
      (total === 0
        ? `OOB listener ${st.url}: no interactions yet (target ${st.target || "?"} has not called back)`
        : `OOB callbacks CONFIRMED on ${st.url}: ${total} interactions (${Object.entries(counts)
            .map(([k, n]) => `${k}=${n}`)
            .join(" ")}) from ${[...ips].slice(0, 5).join(", ")}`),
  });

  // Detailed HTTP interactions first (the interesting ones for SSRF/XXE);
  // DNS produces case-permutation noise per lookup, so it is summarized.
  const http = parsed.filter((v) => v.protocol === "http").slice(0, 10);
  for (const v of http) {
    const firstLine = (v["raw-request"] || "").split("\r\n")[0] || "";
    emit({
      protocol: "http",
      full_id: v["full-id"] || st.url,
      host: v["full-id"] || st.url,
      "remote-address": v["remote-address"] || "",
      summary: `OOB HTTP ${firstLine} from ${v["remote-address"] || "unknown"}`,
    });
  }
  if (http.length === 0 && total > 0) {
    emit({
      protocol: "oob-summary",
      full_id: st.url,
      host: st.url,
      summary: `Only DNS callbacks so far (DNS exfiltration or resolver noise); re-check after delivering the payload`,
    });
  }
}

const action = argOf("action", "check");
const target = argOf("target", "");
if (action === "start") startListener(target);
else if (action === "check") checkListener();
else if (action === "stop") stopListener(false);
else fail(`unknown action "${action}" (start | check | stop)`);
