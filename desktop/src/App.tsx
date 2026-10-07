import { useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import avatarUrl from "./assets/avatar.png";
import "./App.css";

/* ---------- backend types ---------- */
type ToolInfo = {
  id: string; name: string; installed: boolean; version?: string | null;
  caps: string[]; healthy: boolean; category: string; description: string;
  path?: string | null; docs_url: string;
};
type CapInfo = { id: string; description: string; importance: string; providers: string[]; available: boolean };
type ProvInfo = { id: string; tag: string; model: string; ready: boolean; active: boolean };
type DoctorInfo = { platform: string; tools_installed: number; tools_total: number; caps_covered: number; caps_total: number; issues: string[] };
type AgentEvt = { type: string; payload: string; summary: string; session?: string; capability?: string | null; target?: string | null; output?: string | null; model_secs?: number | null; tool_secs?: number | null; ctx?: { used: number; limit: number; pct: number; estimated: boolean } | null; finding?: { id: number; severity: string; title: string; target: string; status: string; detail: string } | null; compact?: { before: number; after: number; freed: number; fallback: boolean } | null; vault_key?: { op: string; key: string; kind?: string; refreshed?: boolean } | null };
type SessionSummary = { id: string; title: string; target: string | null; time_created: number; time_updated: number; records: number };
/** One persisted JSONL line from the backend session store. Mirrors
 *  medusa_lib::infra::sessions::SessionRecord (snake_case `type` tags). */
type TimedRec =
  | { type: "session"; time: number; version: number; id: string; title: string; target: string | null }
    | { type: "note"; time: number; text: string }
    | { type: "user"; time: number; text: string }
    | { type: "chat"; time: number; user: string; agent: string; user_time?: number }
  | { type: "think"; time: number; text: string }
  | { type: "target"; time: number; target: string }
    | { type: "tool"; time: number; cap: string; target: string; reason: string; model_secs?: number }
    | { type: "provider"; time: number; provider: string }
    | { type: "obs"; time: number; text: string }
    | { type: "tool_done"; time: number; summary: string; output: string; tool_secs?: number }
  | { type: "finding"; time: number; id: number; severity: string; title: string; target: string; status: string; detail: string; step?: number }
  | { type: "ctx_usage"; time: number; used: number; limit: number; pct: number; estimated?: boolean }
  | { type: "compacted"; time: number; before: number; after: number; freed: number; fallback?: boolean }
  | { type: "vault_op"; time: number; op: string; key: string; kind?: string };

/* ---------- icons (from design) ---------- */
const ICON: Record<string, string> = {
  chat: "M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z",
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  target: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM12 11.2a.8.8 0 1 0 0 1.6.8.8 0 0 0 0-1.6z",
  pulse: "M3 12h4l2-6 4 12 2-6h6",
  plus: "M12 5v14M5 12h14",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4",
  check: "M5 12.5l4.5 4.5L19 7.5",
  x: "M6 6l12 12M18 6L6 18",
  up: "M12 19V5M6 11l6-6 6 6",
  copy: "M9 9h10v11H9zM5 15V4h10",
  book: "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3zM5 17a3 3 0 0 1 3-3h10",
  refresh: "M20 11a8 8 0 0 0-14.5-3.5M4 5v4h4M4 13a8 8 0 0 0 14.5 3.5M20 19v-4h-4",
  right: "M9 6l6 6-6 6",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  alert: "M12 4l9 16H3zM12 10v4M12 17.3v.01",
  lock: "M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3",
  pause: "M8 5v14M16 5v14",
  file: "M6 3h8l4 4v14H6zM14 3v4h4",
  thumbup: "M7 11v9H4v-9zM7 11l4-7c1.5 0 2.5 1.2 2.2 2.7L12.8 9H19a2 2 0 0 1 2 2.4l-1.3 6.5A2 2 0 0 1 17.7 20H7",
  thumbdown: "M7 13V4H4v9zM7 13l4 7c1.5 0 2.5-1.2 2.2-2.7L12.8 15H19a2 2 0 0 0 2-2.4l-1.3-6.5A2 2 0 0 0 17.7 4H7",
  mic: "M12 3a3 3 0 0 0-3 3v5a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3zM6 11a6 6 0 0 0 12 0M12 17v4",
  clip: "M20 11.5l-8 8a5 5 0 0 1-7-7l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7L9.5 17.3a1.7 1.7 0 0 1-2.4-2.4L15 7",
  plane: "M21 3L10 14M21 3l-7 18-4-7-7-4z",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
  sliders: "M4 7h9M17 7h3M4 17h3M11 17h9M15 4v6M9 14v6",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3.5 2",
};
function Ic({ n, s = 18 }: { n: string; s?: number }) {
  return (
    <svg className="ic" width={s} height={s} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICON[n]} />
    </svg>
  );
}
function Logo({ z = 46 }: { z?: number }) {
  return <img className="logo-img" src={avatarUrl} width={z} height={z} alt="" aria-hidden="true" />;
}
function Markdown({ text }: { text: string }) {
  return (
    <div className="md">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  );
}

/* ---------- taxonomy (mirrors registry; domains drive the ring) ---------- */
const CATS = [
  { id: "network", name: "Network discovery" },
  { id: "dns", name: "DNS and asset discovery" },
  { id: "external", name: "External surface" },
  { id: "http", name: "HTTP and web discovery" },
  { id: "web", name: "Web security testing" },
  { id: "traffic", name: "Traffic analysis" },
  { id: "source", name: "Source-code analysis" },
  { id: "supply_chain", name: "Dependency and supply chain" },
  { id: "container", name: "Container and Kubernetes" },
  { id: "binary", name: "Binary and reverse engineering" },
  { id: "cloud", name: "Cloud" },
  { id: "database", name: "Database security" },
  { id: "identity", name: "Identity and directory" },
];
const DOMAINS = [
  { id: "network", n: "Network" }, { id: "dns", n: "DNS and assets" }, { id: "http", n: "HTTP" },
  { id: "web", n: "Web testing" }, { id: "traffic", n: "Traffic" }, { id: "source", n: "Source code" },
  { id: "dependency", n: "Dependencies" }, { id: "container", n: "Containers" }, { id: "runtime", n: "Runtime" },
  { id: "binary", n: "Binary" }, { id: "cloud", n: "Cloud" }, { id: "external", n: "External" },
  { id: "identity", n: "Identity" }, { id: "database", n: "Database" }, { id: "api", n: "API" },
  { id: "browser", n: "Browser" },
];
function capDomain(id: string): string {
  const p = id.split(".")[0];
  if (p === "supply_chain" || id === "vulnerability.lookup" || id === "sbom.generate") return "dependency";
  if (p === "container" && (id.startsWith("runtime.") || id === "runtime.monitoring")) return "runtime";
  if (p === "packet" || p === "protocol" || p === "traffic") return "traffic";
  if (DOMAINS.some((d) => d.id === p)) return p;
  return "network";
}
const PROFILES: Record<string, { n: string; domains: string[]; imp: string }> = {
  baseline: { n: "Baseline", domains: ["network", "dns", "http"], imp: "HM" },
  high_coverage: { n: "High coverage", domains: DOMAINS.map((d) => d.id), imp: "HM" },
  web_application: { n: "Web application", domains: ["dns", "http", "web", "source", "traffic", "api", "browser"], imp: "HM" },
  network: { n: "Network", domains: ["network", "dns", "traffic", "external"], imp: "HM" },
  source_code: { n: "Source code", domains: ["source", "dependency"], imp: "HM" },
  cloud: { n: "Cloud", domains: ["cloud", "container", "dependency"], imp: "HM" },
  container: { n: "Container", domains: ["container", "dependency", "runtime"], imp: "HM" },
  full: { n: "Full", domains: DOMAINS.map((d) => d.id), imp: "HML" },
};
type View = "session" | "tools" | "coverage" | "doctor";
type Step = { cap: string; target: string; reason: string; provider: string; result: string; outputs: string[]; raw?: string; at: number; dur?: number; toolSecs?: number; state: "run" | "done" | "wait"; open: boolean };
type Finding = { sev: string; title: string; host: string; cap: string; id?: number; status?: string; detail?: string };
/** Live context-meter reading from the backend's ContextUsage events. */
type CtxState = { used: number; limit: number; pct: number; estimated: boolean };
/** Vault KEY NAMES only — values never leave the backend. */
type VaultKey = { key: string; kind: string };
type ChatMsg = { user: string; agent: string; pending?: boolean; at: number; agentAt?: number };
type Approval = { title: string; message: string; options: string[]; selected: number; chatTarget: string | null };
/** One entry in the chat stream — a user message, a model reply, a
 *  thinking snippet, or a tool-call card. Each carries `at` (ms epoch) so
 *  the transcript renders in true chronological order. */
type AgentMsg =
    | { kind: "think"; text: string; at: number; llmSecs?: number }
    | { kind: "tool"; step: Step }
    | { kind: "note"; text: string; at: number };

/** HH:MM:SS clock label for message/tool/thinking timestamps. */
function fmtT(ts: number) {
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** "Oct 2 14:32" label for the saved-session list. */
function fmtDay(ts: number) {
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** Compact token counts for the context meter and compaction notes. */
function fmtTokens(n: number) {
  if (n >= 1000) {
    const v = n / 1000;
    return `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, "")}k`;
  }
  return `${n}`;
}

function parseFinding(line: string): Finding | null {
  const m = line.match(/^(.*?)\s*\[(critical|high|medium|low|info)\]\s*(.*?)\s*\(([^)]+)\)\s*$/i);
  if (!m) return null;
  const sev = m[2].charAt(0).toUpperCase() + m[2].slice(1).toLowerCase();
  return { sev, title: m[3].trim(), host: m[1].trim(), cap: "web.vulnerability_scan" };
}

export default function App() {
  const [view, setView] = useState<View>("session");
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [caps, setCaps] = useState<CapInfo[]>([]);
  const [doctor, setDoctor] = useState<DoctorInfo | null>(null);
  const [profile, setProfile] = useState("web_application");
  const [filter, setFilter] = useState("all");
  const [cat, setCat] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [dom, setDom] = useState<string | null>(null);
  const [capF, setCapF] = useState("all");
  // session
  const [target, setTarget] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  // Context-window meter (tokens used vs the model's window). Updated by
  // ContextUsage events; rebuilt from ctx_usage records on replay.
  const [ctx, setCtx] = useState<CtxState | null>(null);
  // Vault key names for this session (values never reach the UI).
  const [vaultKeys, setVaultKeys] = useState<VaultKey[]>([]);
  /** Wall-clock moment the run finished — anchors the findings summary
   *  in the time-sorted chat instead of pinning it to the bottom. */
  const [doneAt, setDoneAt] = useState<number | null>(null);
  /** Selectable model providers (config `providers` map + builtin catalog
   *  + the plain model block). Switching persists and hot-swaps workers. */
  const [provs, setProvs] = useState<ProvInfo[]>([]);
  const [provMenu, setProvMenu] = useState(false);
  const [phase, setPhase] = useState<"idle" | "wait" | "run" | "done">("idle");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  // True while a model (LLM) call is in flight — the working row shows
  // animated dots instead of text.
  const [thinking, setThinking] = useState(false);
  // When the current model wait started — drives the live "waiting …"
  // timer. Stamped on EVERY ModelThinking arrival (one decide emits one
  // marker; retries happen inside a single decide with no re-emit, so
  // the timer still covers full retry cycles). No latch flag: the
  // previous transition-guard design could stick across a silently
  // cancelled turn and never re-stamp again.
  const [thinkingSince, setThinkingSince] = useState<number>(Date.now());
  // Latency note shown BESIDE the dots while waiting on the model (e.g.
  // "model call failed — retrying 2/5"). Lives separately from `status`
  // so ModelThinking re-emits (retry loop) don't wipe it.
  const [waitNote, setWaitNote] = useState<string | null>(null);
  // Per-step duration attribution (LLM vs tool) on tool cards. Default
  // on; persisted across restarts.
  const [showDurations, setShowDurations] = useState(() => localStorage.getItem("medusa-durations") !== "0");
  const [providers, setProviders] = useState<string[]>([]);
  const [obsCount, setObsCount] = useState(0);
  const [chat, setChat] = useState<ChatMsg[]>([]);
  const [stream, setStream] = useState<AgentMsg[]>([]);
  const [input, setInput] = useState("");
  const [slash, setSlash] = useState(false);
  const [approval, setApproval] = useState<Approval | null>(null);
  const [customAns, setCustomAns] = useState("");
  // first run + toast
  const [sheet, setSheet] = useState(false);
  const [toast, setToast] = useState("");
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [curSession, setCurSession] = useState<string | null>(null);
  // Mirror of curSession for the event listener (stable closure): the
  // backend tags every event with its session id; we only render the
  // session we're looking at. Background sessions keep persisting.
  const curSessionRef = useRef<string | null>(null);
  const setCur = (id: string | null) => { curSessionRef.current = id; setCurSession(id); };
  const toastT = useRef<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const toolById = useMemo(() => {
    const m = new Map<string, ToolInfo>();
    tools.forEach((t) => m.set(t.id, t));
    return m;
  }, [tools]);
  const installed = useMemo(() => tools.filter((t) => t.installed), [tools]);

  function showToast(m: string) {
    setToast(m);
    if (toastT.current) window.clearTimeout(toastT.current);
    toastT.current = window.setTimeout(() => setToast(""), 2200);
  }

  // Update the most recent TOOL card in the stream immutably. Scans backwards
  // so think/error cards interleaved between tool events don't swallow updates.
  function patchLastTool(fn: (step: Step) => Step) {
    setStream((s) => {
      for (let i = s.length - 1; i >= 0; i--) {
        const m = s[i];
        if (m.kind === "tool") {
          const step = fn(m.step);
          if (step === m.step) return s;
          const n = s.slice();
          n[i] = { kind: "tool", step };
          return n;
        }
      }
      return s;
    });
  }

  async function reload() {
    try {
      const [d, t, c] = await Promise.all([
        invoke<DoctorInfo>("get_doctor"),
        invoke<ToolInfo[]>("get_tools"),
        invoke<CapInfo[]>("get_capability_details"),
      ]);
      setDoctor(d); setTools(t); setCaps(c);
    } catch { /* backend unavailable in browser preview */ }
  }

  async function reloadSessions() {
    try { setSessions(await invoke<SessionSummary[]>("list_sessions")); } catch { /* backend unavailable in browser preview */ }
  }

  useEffect(() => {
    reload();
    reloadSessions();
    invoke<ProvInfo[]>("list_providers").then(setProvs).catch(() => { /* backend unavailable in preview */ });
    if (!localStorage.getItem("medusa-seen")) setSheet(true);
    const un = listen<AgentEvt>("agent-event", (ev) => {
      const p = ev.payload;
      // Actor-per-session: render only the session we are looking at.
      // Background sessions persist server-side; switching replays them.
      if (p.session && curSessionRef.current && p.session !== curSessionRef.current) return;
      // Any event other than a model-wait marker or a status note ends
      // the "thinking" animation and clears the wait note (a decision
      // landed, a tool is running).
      if (p.type !== "ModelThinking" && p.type !== "Status") { setThinking(false); setWaitNote(null); }
      if (p.type === "Reply") {
        // The agent's conversational answer ends the turn: fill the
        // pending bubble, stop the spinner.
        setChat((c) => {
          const n = [...c];
          for (let i = n.length - 1; i >= 0; i--) {
            if (n[i].pending) { n[i] = { ...n[i], agent: p.summary || "", pending: false, agentAt: Date.now() }; break; }
          }
          return n;
        });
        setBusy(false);
        setStatus("");
        reloadSessions();
        return;
      } else if (p.type === "Narrated") {
        // Mid-turn agent message (a narrated finding): a NORMAL chat
        // bubble, not a thinking card. The turn keeps running.
        setStream((s) => [...s, { kind: "note", text: p.summary || "", at: Date.now() }]);
        return;
      } else if (p.type === "ScopeGranted") {
        setTarget(p.summary ? p.summary.replace(/^Scope:\s*/, "") : "");
        return;
      } else if (p.type === "CapabilityRequested") {
        // summary: "{capability} on {target} — {reason}"
        const [cap, rest] = (p.summary || "").split(" on ");
        const parts = (rest || "").split("\u2014");
        const reason = parts.slice(1).join("\u2014").trim();
        setStream((s) => {
          // reasoning arrives BEFORE the action it justifies (ChatGPT/Claude order).
          // The thinking card carries the LLM time (the model's artifact);
          // the tool card shows only execution time.
          const now = Date.now();
          const next: AgentMsg[] = reason ? [...s, { kind: "think", text: reason, at: now, llmSecs: p.model_secs ?? undefined }] : [...s];
          next.push({ kind: "tool", step: { cap: cap || p.capability || "", target: (p.target || parts[0] || "").trim(), reason, provider: "", result: "Running", outputs: [], at: now, state: "run", open: true } });
          return next;
        });
        return;
      } else if (p.type === "ProviderSelected") {
        const parts = (p.summary || "").split(" via ");
        setProviders((pr) => (parts[1] && !pr.includes(parts[1]) ? [...pr, parts[1]] : pr));
        patchLastTool((st) => ({ ...st, provider: parts[1] || st.provider }));
        return;
      } else if (p.type === "ObservationAdded") {
        setObsCount((c) => c + 1);
        const f = parseFinding(p.summary || "");
        if (f) setFindings((fl) => [...fl, { ...f, cap: "web.vulnerability_scan" }]);
        patchLastTool((st) => ({ ...st, outputs: [...st.outputs, p.summary || ""] }));
        return;
      } else if (p.type === "FindingRecorded") {
        // Model-reported registry entry (structured — no regex). Later
        // records for the same id are status updates: upsert.
        const fr = p.finding;
        if (fr) {
          const sev = fr.severity.charAt(0).toUpperCase() + fr.severity.slice(1).toLowerCase();
          const entry: Finding = { sev, title: fr.title, host: fr.target, cap: "registry", id: fr.id, status: fr.status, detail: fr.detail || undefined };
          setFindings((fl) => {
            const i = fl.findIndex((f) => f.id === fr.id);
            if (i >= 0) { const n = [...fl]; n[i] = entry; return n; }
            return [...fl, entry];
          });
        }
        return;
      } else if (p.type === "ContextUsage") {
        if (p.ctx) setCtx({ used: p.ctx.used, limit: p.ctx.limit, pct: p.ctx.pct, estimated: p.ctx.estimated });
        return;
      } else if (p.type === "Compacted") {
        const c = p.compact;
        const text = c ? `Conversation compacted${c.fallback ? " (summarizer unavailable — oldest-first truncation)" : ""}: ${fmtTokens(c.before)} → ${fmtTokens(c.after)} tokens (freed ${fmtTokens(c.freed)}). Findings and vault keys preserved.` : (p.summary || "Conversation compacted.");
        setStream((s) => [...s, { kind: "note", text, at: Date.now() }]);
        return;
      } else if (p.type === "VaultStored" || p.type === "VaultRecalled") {
        const vk = p.vault_key;
        if (vk && vk.op === "stored") {
          setVaultKeys((ks) => (ks.some((k) => k.key === vk.key) ? ks.map((k) => (k.key === vk.key ? { key: vk.key, kind: vk.kind || k.kind } : k)) : [...ks, { key: vk.key, kind: vk.kind || "secret" }]));
        }
        return;
      } else if (p.type === "ToolExecuted") {
        patchLastTool((st) => (st.state === "run" ? { ...st, state: "done", result: p.summary || "", raw: p.output || "", dur: Date.now() - st.at, toolSecs: p.tool_secs ?? undefined, open: false } : st));
        return;
      } else if (p.type === "HypothesisAdded") {
        setStream((s) => [...s, { kind: "think", text: p.summary || "", at: Date.now() }]);
        return;
      } else if (p.type === "ActionRejected") {
        const text = p.summary || "";
        setStream((s) => [...s, { kind: "think", text, at: Date.now() }]);
        showToast(text || "Action rejected");
        return;
      } else if (p.type === "ApprovalRequested") {
        // A request, not a rejection: policy blocked a high-risk
        // capability and the runtime is waiting on this dialog.
        setPhase("wait");
        setApproval({ title: "Approval Required", message: p.summary || "", options: ["Allow once", "Deny", "Type your own answer"], selected: 0, chatTarget: null });
        patchLastTool((st) => (st.state === "run" ? { ...st, state: "wait", result: "Waiting for you" } : st));
        return;
      } else if (p.type === "ModelThinking") {
        // Model call in flight: animated dots plus a live stall timer.
        // Stamped every arrival — the wait note (if any) persists across
        // the retry loop's re-emits.
        setThinkingSince(Date.now());
        setThinking(true);
        return;
      } else if (p.type === "Status") {
        // Retry/latency note during model waits.
        setWaitNote(p.summary || "");
        return;
      } else if (p.type === "InvestigationStarted" || p.type === "StepStarted" || p.type === "ToolStarted" || p.type === "ToolFinished") {
        setStatus(p.summary || "");
        return;
      } else if (p.type === "Error") {
        const text = p.summary || "Backend error";
        setStatus("");
        showToast(text.length > 160 ? text.slice(0, 160) + "…" : text);
        setStream((s) => [...s, { kind: "think", text, at: Date.now() }]);
        return;
      } else if (p.type === "Finished") {
        setBusy(false);
        setStatus("");
        setDoneAt(Date.now());
        // "idle" = a fresh session was started after this run was cancelled;
        // don't let the stale Finished flip the new session to "done".
        setPhase((ph) => (ph === "wait" || ph === "idle" ? ph : "done"));
        reloadSessions();
        return;
      }
    });
    return () => { un.then((f) => f()); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [stream, findings, chat, status]);

  // Auto-focus the composer: on opening the session view and whenever an
  // overlay (approval, first-run sheet, drawer) closes.
  useEffect(() => {
    if (view === "session" && !approval && !sheet && !sel) inputRef.current?.focus();
  }, [view, approval, sheet, sel]);

  // approval keyboard: ↑â†“ navigate, Enter select, Esc deny
  useEffect(() => {
    if (!approval) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === "ArrowUp") { e.preventDefault(); setApproval((a) => (a ? { ...a, selected: Math.max(0, a.selected - 1) } : a)); }
      else if (e.key === "ArrowDown") { e.preventDefault(); setApproval((a) => (a ? { ...a, selected: Math.min(2, a.selected + 1) } : a)); }
      else if (e.key === "Enter" && (e.target as HTMLElement)?.tagName !== "TEXTAREA" && (e.target as HTMLElement)?.tagName !== "INPUT") { e.preventDefault(); chooseApproval(approval.selected); }
      else if (e.key === "Escape") { denyApproval(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [approval]);

  async function approveBackend(allow: boolean) {
    try { await invoke("approve", { allow }); } catch { /* ignore */ }
  }
  function denyApproval() {
    approveBackend(false);
    setApproval(null);
    showToast("Denied. Medusa will note the gap in the report.");
  }
  async function chooseApproval(idx: number) {
    if (!approval) return;
    const opt = approval.options[idx];
    if (opt === "Type your own answer") return; // reveal inline input (rendered when selected)
    if (opt === "Yes" || opt === "Allow once") {
      setApproval(null);
      await approveBackend(true);
      setPhase("run");
      patchLastTool((st) => (st.state === "wait" ? { ...st, state: "run", result: "Running" } : st));
    } else {
      denyApproval();
    }
  }
  async function sendCustomAnswer() {
    const v = customAns.trim();
    if (!v) return;
    setCustomAns("");
    setApproval(null);
    await handleUserText(v);
  }

  /* ---------- persisted sessions ---------- */

  /** Replay a saved session into the live view: chat turns, thinking,
   *  tool step cards and findings are rebuilt with the same patching
   *  logic the live event handler uses. */
  async function openSession(id: string) {
    try {
      const data = await invoke<{ records: TimedRec[]; running: boolean }>("open_session", { id });
      const recs = data.records;
      const chat: ChatMsg[] = [];
      const stream: AgentMsg[] = [];
      const findings: Finding[] = [];
      const provs: string[] = [];
      let tgt: string | null = null;
      let obs = 0;
      let ctxState: CtxState | null = null;
      const vaultState: VaultKey[] = [];
      // Anchor for the findings summary: when the last scan activity
      // ended (last tool completion), else the last record's time.
      let lastToolDoneAt: number | null = null;
      let lastAt: number | null = null;
      const patchTool = (fn: (st: Step) => Step) => {
        for (let i = stream.length - 1; i >= 0; i--) {
          const m = stream[i];
          if (m.kind === "tool") { stream[i] = { kind: "tool", step: fn(m.step) }; break; }
        }
      };
      for (const r of recs) {
        lastAt = r.time;
        if (r.type === "session") { tgt = tgt ?? r.target; continue; }
        if (r.type === "target") { tgt = r.target; continue; }
        if (r.type === "note") { stream.push({ kind: "note", text: r.text, at: r.time }); continue; }
        if (r.type === "user") { chat.push({ user: r.text, agent: "", pending: false, at: r.time }); continue; }
        if (r.type === "chat") {
          // A User record (written at send time) may already hold the
          // bubble for this turn — fill it instead of duplicating.
          const last = chat[chat.length - 1];
          if (last && !last.agent && last.user === r.user) {
            chat[chat.length - 1] = { ...last, agent: r.agent, agentAt: r.time };
          } else {
            chat.push({ user: r.user, agent: r.agent, at: r.user_time || r.time, agentAt: r.time });
          }
          continue;
        }
        if (r.type === "think") { stream.push({ kind: "think", text: r.text, at: r.time }); continue; }
        if (r.type === "tool") {
          if (r.reason) stream.push({ kind: "think", text: r.reason, at: r.time, llmSecs: r.model_secs || undefined });
          stream.push({ kind: "tool", step: { cap: r.cap, target: r.target, reason: r.reason, provider: "", result: "Running", outputs: [], at: r.time, state: "run", open: true } });
          continue;
        }
        if (r.type === "provider") { if (!provs.includes(r.provider)) provs.push(r.provider); patchTool((st) => ({ ...st, provider: r.provider })); continue; }
        if (r.type === "obs") {
          obs++;
          const f = parseFinding(r.text);
          if (f) findings.push({ ...f, cap: "web.vulnerability_scan" });
          patchTool((st) => ({ ...st, outputs: [...st.outputs, r.text] }));
          continue;
        }
        if (r.type === "tool_done") { lastToolDoneAt = r.time; patchTool((st) => ({ ...st, state: "done", result: r.summary, raw: r.output, open: false, toolSecs: r.tool_secs || undefined })); continue; }
        if (r.type === "finding") {
          // Registry rows replay verbatim (later rows for the same id
          // carry the newer status): upsert by id.
          const sev = r.severity.charAt(0).toUpperCase() + r.severity.slice(1).toLowerCase();
          const entry: Finding = { sev, title: r.title, host: r.target, cap: "registry", id: r.id, status: r.status, detail: r.detail || undefined };
          const i = findings.findIndex((f) => f.id === r.id);
          if (i >= 0) findings[i] = entry; else findings.push(entry);
          continue;
        }
        if (r.type === "ctx_usage") { ctxState = { used: r.used, limit: r.limit, pct: r.pct, estimated: !!r.estimated }; continue; }
        if (r.type === "compacted") {
          stream.push({ kind: "note", text: `Conversation compacted${r.fallback ? " (fallback truncation)" : ""}: ${fmtTokens(r.before)} → ${fmtTokens(r.after)} tokens (freed ${fmtTokens(r.freed)}). Findings and vault keys preserved.`, at: r.time });
          continue;
        }
        if (r.type === "vault_op") {
          // Key names only — values are never persisted, by backend design.
          if (r.op === "stored" && !vaultState.some((k) => k.key === r.key)) vaultState.push({ key: r.key, kind: r.kind || "secret" });
          continue;
        }
      }
      setChat(chat); setStream(stream); setFindings(findings); setProviders(provs); setObsCount(obs);
      setCtx(ctxState); setVaultKeys(vaultState);
      setDoneAt(data.running ? null : (lastToolDoneAt ?? lastAt));
      setTarget(tgt || "");
      setCur(id);
      // A background worker may still be mid-turn: restore the running
      // state so live events keep streaming and the composer shows it.
      setBusy(data.running); setStatus(data.running ? "Working…" : "");
      setPhase(data.running ? "run" : stream.length || chat.length ? "done" : "idle");
      setView("session");
    } catch (e) { showToast(String(e)); }
  }

  /** Reset the live view to an empty session. Detaches WITHOUT stopping
   *  the old session — its worker keeps running in the background and
   *  persists; switching back resumes live streaming. */
  async function newSession() {
    try { await invoke("close_session"); } catch { /* backend unavailable in preview */ }
    setCur(null);
    setTarget(""); setFindings([]); setDoneAt(null); setPhase("idle"); setBusy(false); setStatus("");
    setProviders([]); setObsCount(0); setChat([]); setStream([]); setApproval(null);
    setCtx(null); setVaultKeys([]);
    setInput(""); setSlash(false); setView("session");
    inputRef.current?.focus();
  }

  /** Stop the current turn of the viewed session. The worker survives
   *  with its memory — the next message continues the conversation.
   *  A cancelled turn emits NOTHING backend-side, so the UI stands down
   *  its own wait state here — otherwise the dots, timer, and Stop
   *  button freeze forever. Late straggler events (e.g. a tool that
   *  couldn't be interrupted) still render harmlessly into the stream. */
  function stopRun() {
    invoke("cancel_assess").catch(() => {});
    setThinking(false);
    setWaitNote(null);
    setBusy(false);
    setStatus("");
    showToast("Stopping the current turn…");
  }

  /** Manually compact the viewed session now instead of waiting for the
   *  auto-compaction threshold. Findings and vault keys are preserved. */
  function compactNow() {
    invoke("compact_session").then(() => showToast("Compacting conversation…")).catch(() => showToast("Compaction unavailable"));
  }

  /** Context-meter color: green <70%, amber 70–89%, red ≥90%. */
  function ctxClass(pct: number) {
    return pct >= 90 ? "ctx bad" : pct >= 70 ? "ctx warn" : "ctx";
  }

  /** The unified path: every message goes to the session's LLM brain via
   *  its worker. The model decides - answer (Reply event) or act (tool
   *  events) - and everything streams back tagged with the session id. */
  /** Switch the model provider: persists to config.json and hot-swaps
   *  every live session worker before its next turn. */
  async function pickProvider(id: string) {
    setProvMenu(false);
    try {
      const list = await invoke<ProvInfo[]>("set_provider", { id: id || null });
      setProvs(list);
      const a = list.find((p) => p.active);
      showToast(a ? `Model switched to ${a.tag} · ${a.model}` : "Model switched");
    } catch (e) { showToast(String(e)); }
  }

  async function handleUserText(v: string) {
    const text = v.trim();
    if (!text) return;
    if (text.startsWith("/")) { runCmd(text); return; }
    // Show the user's message immediately; the Reply event fills it in.
    // A fresh turn starts with clean wait state — its first ModelThinking
    // stamps the stall timer.
    setChat((c) => [...c, { user: text, agent: "", pending: true, at: Date.now() }]);
    setBusy(true);
    setThinking(false);
    setWaitNote(null);
    try {
      const sid = await invoke<string>("send_message", { message: text });
      if (sid && sid !== curSessionRef.current) { setCur(sid); reloadSessions(); }
    } catch (e) {
      setChat((c) => {
        const n = [...c];
        for (let k = n.length - 1; k >= 0; k--) {
          if (n[k].pending) { n[k] = { ...n[k], agent: `Backend unavailable: ${String(e)}`, pending: false, agentAt: Date.now() }; break; }
        }
        return n;
      });
      setBusy(false);
    }
  }
  function runCmd(text: string) {
    const [c, ...a] = text.trim().split(/\s+/);
    const arg = a.join(" ").toLowerCase();
    const catMatch = CATS.find((x) => x.id === arg || x.name.toLowerCase().includes(arg));
    if (c === "/tools") {
      setFilter("all"); setQ(""); setCat(catMatch ? catMatch.id : null); setView("tools");
    } else if (c === "/tool" || c === "/install") {
      const t = tools.find((x) => x.id === arg || x.name.toLowerCase() === arg) || tools.find((x) => x.id === "nuclei") || tools[0];
      if (t) { setView("tools"); setSel(t.id); }
    } else if (c === "/capabilities" || c === "/coverage") setView("coverage");
    else if (c === "/doctor") setView("doctor");
    else if (c === "/refresh-tools") doRefresh();
    else showToast("Unknown command. Type / to see the list.");
  }
  async function doRefresh() {
    showToast("Scanning tools…");
    try {
      const d = await invoke<DoctorInfo>("refresh_tools");
      setDoctor(d);
      const t = await invoke<ToolInfo[]>("get_tools");
      setTools(t);
      showToast(`Rescanned ${t.length} tools`);
    } catch { showToast("Refresh failed"); }
  }

  /* ---------- coverage math (frontend, from live caps) ---------- */
  function capStatus(c: CapInfo): "covered" | "partial" | "none" {
    if (c.available) return "covered";
    return "none";
  }
  const pCaps = useMemo(() => {
    const P = PROFILES[profile];
    return caps.filter((c) => P.domains.includes(capDomain(c.id)) && P.imp.includes(c.importance.charAt(0).toUpperCase()));
  }, [caps, profile]);
  const pCov = useMemo(() => {
    if (!pCaps.length) return 0;
    return pCaps.filter((c) => capStatus(c) === "covered").length / pCaps.length;
  }, [pCaps]);
  const domCov = (d: string) => {
    const P = PROFILES[profile];
    const list = caps.filter((c) => capDomain(c.id) === d && P.imp.includes(c.importance.charAt(0).toUpperCase()));
    if (!list.length) return null;
    return list.filter((c) => capStatus(c) === "covered").length / list.length;
  };

  /* ---------- ring ---------- */
  function ring(pk: string, compact: boolean, dark: boolean) {
    const P = PROFILES[pk];
    const W = compact ? 220 : 680, H = compact ? 220 : 620, cx = W / 2, cy = H / 2;
    const r0 = compact ? 46 : 92, rm = compact ? 100 : 184;
    const n = DOMAINS.length, step = (2 * Math.PI) / n, gap = compact ? 0.06 : 0.05;
    const pt = (r: number, a: number): [number, number] => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
    const sec = (ra: number, rb: number, a0: number, a1: number) => {
      const [x1, y1] = pt(rb, a0), [x2, y2] = pt(rb, a1), [x3, y3] = pt(ra, a1), [x4, y4] = pt(ra, a0);
      return `M${x1.toFixed(1)},${y1.toFixed(1)}A${rb},${rb} 0 0 1 ${x2.toFixed(1)},${y2.toFixed(1)}L${x3.toFixed(1)},${y3.toFixed(1)}A${ra},${ra} 0 0 0 ${x4.toFixed(1)},${y4.toFixed(1)}Z`;
    };
    const total = Math.round((pCaps.length ? pCov : 0) * 100);
    let g = "";
    DOMAINS.forEach((d, i) => {
      const a0 = i * step + gap / 2, a1 = (i + 1) * step - gap / 2, am = (a0 + a1) / 2;
      const cov = domCov(d.id), inP = P.domains.includes(d.id);
      let body = `<path class="trk ${cov === null ? "dash" : ""}" d="${sec(r0, rm, a0, a1)}"/>`;
      if (cov !== null && cov > 0) body += `<path class="fil ${inP ? "" : "off"}" d="${sec(r0, r0 + (rm - r0) * Math.max(cov, 0.03), a0, a1)}"/>`;
      let lab = "";
      if (!compact) {
        const [lx, ly] = pt(rm + 20, am), s = Math.sin(am), co = Math.cos(am);
        const anchor = s > 0.25 ? "start" : s < -0.25 ? "end" : "middle";
        const y = co > 0.5 ? ly - 16 : co < -0.5 ? ly + 6 : ly - 6;
        lab = `<text class="lab ${inP ? "" : "off"}" text-anchor="${anchor}"><tspan x="${lx.toFixed(1)}" y="${y.toFixed(1)}">${d.n}</tspan><tspan class="pc" x="${lx.toFixed(1)}" y="${(y + 15).toFixed(1)}">${cov === null ? "Not in registry yet" : Math.round(cov * 100) + "%"}</tspan></text>`;
      }
      g += compact ? `<g>${body}</g>` : `<g class="seg ${dom === d.id ? "sel" : ""}" data-dom="${d.id}">${body}${lab}</g>`;
    });
    const center = dark ? "" : compact
      ? `<text x="${cx}" y="${cy + 9}" text-anchor="middle" class="big" style="font-size:30px">${total}%</text>`
      : `<text x="${cx}" y="${cy + 8}" text-anchor="middle" class="big">${total}<tspan style="font-size:28px">%</tspan></text><text x="${cx}" y="${cy + 34}" text-anchor="middle" class="csub">${P.n} profile</text>`;
    return `<svg class="${dark ? "ring-dark" : ""}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Coverage for the ${P.n} profile is ${total} percent">${g}${center}</svg>`;
  }

  /* ---------- header per view ---------- */
  const HEAD: Record<View, [string, string, React.ReactNode]> = {
    session: [target || "New session", `${PROFILES[profile].n} profile · ${pCaps.length} capabilities planned`,
      (<><span className="chip ok"><Ic n="shield" s={13} />In scope</span><button
        className={`hh-toggle${showDurations ? " on" : ""}`}
        onClick={() => setShowDurations((v) => { localStorage.setItem("medusa-durations", v ? "0" : "1"); return !v; })}
        title="Show per-step durations (LLM vs tool) on tool cards"
      ><Ic n="clock" s={13} />Timings</button><button className="btn sm" onClick={() => showToast("Report export opens here")}><Ic n="file" s={14} />Export report</button>{busy && <button className="btn sm" onClick={async () => { try { await invoke("cancel_assess"); } catch { /* ignore */ } setBusy(false); }}>Cancel</button>}</>)],
    tools: [`Tools`, `${installed.length} ready on this machine`, (<button className="btn" onClick={doRefresh}><Ic n="refresh" s={15} />Refresh tools</button>)],
    coverage: [`Coverage`, `What Medusa can and can’t assess on this machine`, (<></>)],
    doctor: [`Doctor`, `Why a tool or capability works, or doesn’t`, (<button className="btn" onClick={doRefresh}><Ic n="refresh" s={15} />Run again</button>)],
  };
  // Single-view nav: the tool/coverage/doctor views stay reachable via
  // slash commands (/tools, /coverage, /doctor) and in-app links.
  const NAV: [View, string, string][] = [["session", "Session", "chat"]];

  /** Findings by severity for the permanent sidebar card and the
   *  done-state summary (computed once, used in both places). */
  const fCounts = {
    High: findings.filter((f) => f.sev === "High" || f.sev === "Critical").length,
    Medium: findings.filter((f) => f.sev === "Medium").length,
    Low: findings.filter((f) => f.sev === "Low" || f.sev === "Info").length,
  };

  /** Session rows, rendered in the left sidebar (the single home for
   *  the session list since the right panel no longer carries it). */
  function sessionRows() {
    return sessions.map((s) => (
      <div
        key={s.id}
        className={`hrow${s.id === curSession ? " on" : ""}`}
        role="button"
        tabIndex={0}
        aria-current={s.id === curSession ? "true" : undefined}
        onClick={() => { if (s.id !== curSession) openSession(s.id); }}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (s.id !== curSession) openSession(s.id); } }}
      >
        <span className="dot" aria-hidden="true" />
        <span>
          <b>{s.title}</b>
          <small>{[s.target, fmtDay(s.time_updated), s.records ? `${s.records} events` : null].filter(Boolean).join(" · ")}</small>
        </span>
        <button className="hdel" title={`Delete "${s.title}"`} aria-label={`Delete session ${s.title}`}
          onClick={(e) => { e.stopPropagation(); delSession(s.id); }}>
          <Ic n="x" s={13} />
        </button>
      </div>
    ));
  }

  /** Delete a session transcript permanently (backend drops a live
   *  worker first). Deleting the viewed session resets to a fresh view. */
  async function delSession(id: string) {
    try {
      await invoke("delete_session", { id });
      showToast("Session deleted");
      if (id === curSessionRef.current) await newSession();
      reloadSessions();
    } catch (e) { showToast(String(e)); }
  }

  return (
    <div className="app">
      <aside className="side">
        <div className="brand"><Logo z={34} /><span>Medusa</span></div>
        <nav className="nv" aria-label="Main">
          {NAV.map(([v, label, icon]) => (
            <button key={v} onClick={() => setView(v)} className={view === v ? "on" : ""} aria-current={view === v ? "page" : undefined}>
              <Ic n={icon} s={18} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="ssess">
          <div className="ssess-hd"><h3>Sessions</h3><span>{sessions.length}</span><button className="btn sm" onClick={newSession}>New</button></div>
          <div className="slist">
            {sessionRows()}
            {sessions.length === 0 && (
              <p className="sempty">No saved sessions yet. Messages and assessments are stored locally on this machine.</p>
            )}
          </div>
        </div>
        <div className="env-mini"><span>{installed.length}/{tools.length || "—"} tools · {Math.round(pCov * 100)}%</span><button className="linklike" onClick={() => setView("coverage")}>View</button></div>
        <div className="sfoot">
          <button onClick={doRefresh}><span>Refresh tools</span><Ic n="refresh" s={17} /></button>
        </div>
      </aside>
      <main className="panel">
        <header className="top">
          <div className="tl">
            <div><h1>{HEAD[view][0]}</h1><p>{HEAD[view][1]}</p></div>
            <div className="acts">{HEAD[view][2]}</div>
          </div>
        </header>
        <div className="content">
          {view === "session" && SessionView()}
          {view === "tools" && ToolsView()}
          {view === "coverage" && CoverageView()}
          {view === "doctor" && DoctorView()}
        </div>
      </main>

      {sel && <><div className="scrim on" onClick={() => setSel(null)} /><Drawer id={sel} onClose={() => setSel(null)} doRefresh={doRefresh} /></>}
      {approval && <ApprovalModal approval={approval} onChoose={chooseApproval} onDeny={denyApproval} customAns={customAns} setCustomAns={setCustomAns} onSendCustom={sendCustomAnswer} />}
      {sheet && <FirstRunSheet onDone={() => { localStorage.setItem("medusa-seen", "1"); setSheet(false); }} onTools={() => { localStorage.setItem("medusa-seen", "1"); setSheet(false); setView("tools"); }} />}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );

  /* ================= session ================= */
  function SessionView() {
    const usedCaps = [...new Set(stream.filter((m) => m.kind === "tool").map((m) => m.kind === "tool" ? m.step.cap : "").filter(Boolean))];
    const stepCount = stream.filter((m) => m.kind === "tool").length;
    // Findings counts come from the App-level fCounts (shared with the
    // permanent sidebar card); the detailed list renders below at done.
    const counts = fCounts;
    const started = stream.length > 0 || phase === "run" || phase === "wait" || phase === "done";
    // Render chat turns and agent stream events as ONE flat, TIME-SORTED
    // sequence of `.col` flex children: user messages right, agent content
    // left with aligned avatar, every entry stamped with its clock time.
    function interleave(): React.ReactNode {
      type Item = { at: number; node: React.ReactNode };
      const items: Item[] = [];
      chat.forEach((m, ci) => {
        if (m.user) items.push({ at: m.at, node: (
          <div className="msg-u-wrap" key={`u${ci}`}>
            <div className="msg-time">{fmtT(m.at)}</div>
            <div className="msg-u">{m.user}</div>
          </div>
        ) });
        if (m.agent && !m.pending) {
          const at = m.agentAt ?? m.at;
          const stepLimited = /I hit the per-turn step limit/i.test(m.agent);
          items.push({ at, node: (
            <div className="msg-a" key={`a${ci}`}><Logo z={30} /><div className="body">
              <div className="msg-time">{fmtT(at)}</div>
              <Markdown text={m.agent} />
              {stepLimited && (
                <button className="btn cont-btn" onClick={() => handleUserText("continue")}>
                  <Ic n="right" s={14} />Continue
                </button>
              )}
            </div></div>
          ) });
        }
      });
      stream.forEach((m, si) => items.push({ at: m.kind === "tool" ? m.step.at : m.at, node: m.kind === "think"
        ? <details className="think" key={`s${si}`}><summary><span className="chev"><Ic n="right" s={14} /></span><span>Thinking</span><span className="th-time">{fmtT(m.at)}{showDurations && m.llmSecs != null && m.llmSecs > 0 ? <span className="st-dur"> · LLM {fmtDur(m.llmSecs)}</span> : null}</span><CopyBtn title="Copy thinking and duration" text={`Thinking · ${fmtT(m.at)}${showDurations && m.llmSecs != null && m.llmSecs > 0 ? ` · LLM ${fmtDur(m.llmSecs)}` : ""}\n${m.text}`} /></summary><div className="th-body"><div className="th-row">{m.text}</div></div></details>
        : m.kind === "note"
        ? <div className="msg-a" key={`s${si}`}><Logo z={30} /><div className="body"><div className="msg-time">{fmtT(m.at)}</div><Markdown text={m.text} /></div></div>
        : <div className="msg-a" key={`s${si}`}><Logo z={30} /><div className="body"><StepCard step={m.step} showDurations={showDurations} /></div></div> }));
      // Findings summary is an ordinary time-sorted message pinned to the
      // moment the run finished — never a timestamp-less block dangling at
      // the bottom of the chat.
      if (phase === "done" && findings.length > 0) {
        const at = doneAt ?? Date.now();
        items.push({ at, node: (
          <div className="msg-a" key="findings"><Logo z={30} /><div className="body">
            <div className="msg-time">{fmtT(at)}</div>
            <p>The scan is done. {findings.length === 1 ? "There is 1 finding" : `There are ${findings.length} findings`}{counts.High ? ", and the high-severity one should come first" : ""}.</p>
            <div className="steps finds">{findings.map((f, j) => (
              <div className="find" key={j}><span><span className={`pill ${f.sev}`}>{f.sev}</span></span><div><b>{f.title}</b>{f.status && f.status !== "open" ? <code> {f.status}</code> : null}<small>{f.host}</small>{f.detail ? <small>{f.detail}</small> : null} <code>{f.cap}</code></div></div>
            ))}</div>
          </div></div>
        ) });
      }
      // Stable sort keeps same-tick ordering (thinking before its tool card).
      items.sort((a, b) => a.at - b.at);
      return <>{items.map((it) => it.node)}</>;
    }
    return (
      <div className="sess">
        <div className="conv">
          <div className="scroll" ref={scrollRef}><div className="col">
            {!started && chat.length === 0 && !busy && (
              <div className="empty-state">
                <Logo z={44} />
                <h2>New session</h2>
                <p>Ask Medusa anything, or type <code>assess scanme.nmap.org</code> to start an assessment.</p>
              </div>
            )}
            {interleave()}
            {busy && (phase !== "done" || chat.some((m) => m.pending || stream.length > 0)) && <div className="msg-a"><Logo z={30} /><div className="body"><p className="working-row">{thinking ? <><span className="dots" aria-label="Waiting on the model"><span /><span /><span /></span><WaitTimer since={thinkingSince} />{waitNote}</> : <><span className="spin" style={{ display: "inline-block", verticalAlign: "-3px", marginRight: 8 }} />{status || "Working…"}</>}<button className="stop-btn" onClick={stopRun}>Stop</button></p></div></div>}
          </div></div>
          <div className="composer"><div className="in">
            <div className={`slash${slash ? " on" : ""}`}>
              <div className="hd"><span>Commands</span><span>Run on this machine, no model involved</span></div>
              {[["/tools", "Browse every tool by category"], ["/tools <category>", "Show one category, such as network"], ["/tool <name>", "Open details for a single tool"], ["/capabilities", "See providers for each capability"], ["/coverage", "See coverage for the current profile"], ["/doctor", "Diagnose this environment"], ["/install <tool>", "Show install options. Nothing runs."], ["/refresh-tools", "Scan for tools again"]].map(([cmd, desc], i) => (
                <button key={cmd} className={i === 0 ? "hot" : ""} onClick={() => { setSlash(false); setInput(""); runCmd(cmd.split(" ")[0]); }}><code>{cmd}</code><span>{desc}</span></button>
              ))}
            </div>
            <div className="prov-bar">
              <div className="prov-wrap">
                <button className="prov-pill" onClick={() => { setProvMenu((v) => !v); invoke<ProvInfo[]>("list_providers").then(setProvs).catch(() => { /* backend unavailable in preview */ }); }} title="Switch model provider">
                  <span className="prov-tag">{provs.find((p) => p.active)?.tag ?? "model"}</span>
                  <span className="prov-model">{provs.find((p) => p.active)?.model ?? (provs.length ? "…" : "offline")}</span>
                  <span className="prov-caret" aria-hidden="true">▾</span>
                </button>
                {provMenu && (
                  <div className="prov-menu" role="menu">
                    <div className="prov-menu-hd">Model providers</div>
                    {provs.map((p) => (
                      <button key={p.id || "default"} className={`prov-opt${p.active ? " on" : ""}`} disabled={!p.ready}
                        title={!p.ready ? "Cannot resolve this provider — API key not set" : p.model}
                        onClick={() => pickProvider(p.id)}>
                        <span className="prov-tag">{p.tag}</span>
                        <span className="prov-model">{p.model}</span>
                        {p.active ? <span className="prov-check">✓</span> : !p.ready ? <span className="prov-warn">needs API key</span> : null}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {provMenu && <div className="prov-backdrop" onClick={() => setProvMenu(false)} />}
            </div>
            <div className="cmp">
              <button className="ibtn" onClick={() => showToast("Attach a target list or scope file")} aria-label="Attach"><Ic n="clip" s={17} /></button>
              <button className="ibtn" onClick={() => showToast("Voice input is not part of this preview")} aria-label="Voice"><Ic n="mic" s={17} /></button>
              <div className="cin">
                <textarea ref={inputRef} rows={1} value={input} placeholder="Start typing, or type / for commands" aria-label="Message Medusa"
                  onChange={(e) => { setInput(e.target.value); setSlash(e.target.value.startsWith("/")); }}
                  onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); const v = input; setInput(""); setSlash(false); handleUserText(v); } if (e.key === "Escape") setSlash(false); }} />
              </div>
              <button className="go" aria-label="Send" onClick={() => { const v = input; setInput(""); setSlash(false); handleUserText(v); }}><Ic n="plane" s={19} /></button>
            </div>
            <p className="cap">{target ? <>Scope: {target} · {PROFILES[profile].n} profile · Medusa asks before running active tests</> : <>No target yet · {PROFILES[profile].n} profile · Medusa asks before running active tests</>}{ctx ? <> · <span className={ctxClass(ctx.pct)} title={`${fmtTokens(ctx.used)} / ${fmtTokens(ctx.limit)} tokens${ctx.estimated ? " (estimated — endpoint omits usage)" : ""}`}>ctx {ctx.pct}%{ctx.estimated ? " ~" : ""}</span></> : null}{started ? <> · <button className="linklike" onClick={compactNow} title="Summarize older turns now (findings and vault keys are preserved)">compact</button></> : null}</p>
          </div></div>
        </div>
        <aside className="hist" aria-label="Session details">
          <div className="scards">
            <div className="scard">
              <div className="scard-hd"><span>Context</span><b>{ctx ? `${ctx.pct}%` : "—"}</b></div>
              <div className="meter"><i style={{ width: `${ctx?.pct ?? 0}%` }} className={ctx ? (ctx.pct >= 90 ? "bad" : ctx.pct >= 70 ? "warn" : "") : ""} /><em style={{ left: "85%" }} title="Auto-compact threshold" /></div>
              <small>{ctx ? <>{fmtTokens(ctx.used)} / {fmtTokens(ctx.limit)} tokens{ctx.estimated ? " (est.)" : ""} · auto-compact at 85%</> : "No context data yet — start a turn."}</small>
            </div>
            <div className="scard">
              <div className="scard-hd"><span>Findings</span><b>{findings.length}</b></div>
              {findings.length > 0 ? (
                <div className="sevrow">
                  {fCounts.High > 0 && <span className="pill High">{fCounts.High} high</span>}
                  {fCounts.Medium > 0 && <span className="pill Medium">{fCounts.Medium} med</span>}
                  {fCounts.Low > 0 && <span className="pill Low">{fCounts.Low} low</span>}
                </div>
              ) : <small>No findings yet — Medusa reports them here.</small>}
            </div>
            <div className="scard">
              <div className="scard-hd"><span>Vault</span><b>{vaultKeys.length}</b></div>
              {vaultKeys.length > 0 ? (
                <div className="tagrow">{vaultKeys.map((k) => (<span key={k.key} className="tag">🔑 {k.key}</span>))}</div>
              ) : <small>Empty — recovered secrets land here.</small>}
            </div>
          </div>
          <section className="hstats">
            <h3>This session</h3>
            <div className="kv"><span>Observations</span><b>{obsCount}</b></div>
            <div className="kv"><span>Steps</span><b>{stepCount}</b></div>
            <div className="kv"><span>Capabilities used</span><b>{usedCaps.length}</b></div>
            {providers.length > 0 && (
              <div className="tagrow" style={{ marginTop: 4 }}>{providers.map((x) => (<span key={x} className="tag">{x}</span>))}</div>
            )}
          </section>
          <div className="hfoot"><button className="btn" onClick={() => showToast("Archive opens here")}><Ic n="trash" s={15} />Archive sessions</button></div>
        </aside>
      </div>
    );
  }

  /* ================= tools ================= */
  function ToolsView() {
    const ql = q.trim().toLowerCase();
    const groups = CATS.map((c) => {
      const all = tools.filter((t) => catOf(t) === c.id);
      const list = all.filter((t) =>
        (filter === "all" || (filter === "installed" ? t.installed : !t.installed)) &&
        (!ql || `${t.name} ${t.id} ${t.description} ${t.caps.join(" ")}`.toLowerCase().includes(ql)));
      return { c, all, list };
    }).filter((g) => g.list.length);
    return (
      <div className="pad">
        <div className="toolbar">
          <div className="seg-ctl" role="group" aria-label="Filter">
            {[["all", "All"], ["installed", "Installed"], ["missing", "Not installed"]].map(([f, label]) => (
              <button key={f} onClick={() => setFilter(f)} className={filter === f ? "on" : ""}>{label}</button>
            ))}
          </div>
          <label className="search"><Ic n="search" s={16} /><input placeholder="Search tools or capabilities" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search tools" /></label>
        </div>
        <div className="cats">
          <button onClick={() => setCat(null)} className={!cat ? "on" : ""}>All categories</button>
          {CATS.map((c) => (<button key={c.id} onClick={() => setCat(cat === c.id ? null : c.id)} className={cat === c.id ? "on" : ""}>{c.name}</button>))}
        </div>
        {cat && <div className="cats" style={{ marginTop: -12 }}><button onClick={() => setCat(null)}>✕ {CATS.find((c) => c.id === cat)?.name}</button></div>}
        {groups.filter((g) => !cat || g.c.id === cat).map((g) => (
          <div className="group" key={g.c.id}>
            <div className="group-h"><h2>{g.c.name}</h2><small>{g.all.filter((t) => t.installed).length} of {g.all.length} installed</small></div>
            <div className="card rows">
              {g.list.map((t) => (
                <button className="trow" key={t.id} onClick={() => setSel(t.id)}>
                  <span className={`tav${t.installed ? "" : " off"}`}>{t.name[0].toUpperCase()}</span>
                  <span className="nm"><b>{t.name}</b><small>{t.description}</small></span>
                  <span className="caps">{t.caps.slice(0, 2).map((cp) => (<span key={cp} className="tag">{cp}</span>))}{t.caps.length > 2 && <span className="tag">+{t.caps.length - 2}</span>}</span>
                  <span className="stat">{t.installed ? (<><span className="dot" />{t.version || "installed"}</>) : (<><span className="dot off" /><span style={{ color: "var(--ink-2)" }}>Not installed</span></>)}</span>
                  <Ic n="right" s={16} />
                </button>
              ))}
            </div>
          </div>
        ))}
        {!groups.filter((g) => !cat || g.c.id === cat).length && <div className="card empty">No tools match. Clear the search or pick another category.</div>}
        <p className="small-note">Medusa never installs tools on its own. Install a tool yourself, then refresh.</p>
      </div>
    );
  }

  /* ================= coverage ================= */
  function CoverageView() {
    const st = pCaps.map((c) => capStatus(c));
    const n = { covered: st.filter((s) => s === "covered").length, partial: st.filter((s) => s === "partial").length, none: st.filter((s) => s === "none").length };
    const gaps = pCaps.filter((c) => capStatus(c) !== "covered");
    const byPrio = (imp: string) => gaps.filter((c) => c.importance.charAt(0).toUpperCase() === imp);
    const tally = new Map<string, string[]>();
    gaps.forEach((c) => c.providers.forEach((id) => {
      const t = toolById.get(id);
      if (t && !t.installed) { const l = tally.get(id) || []; l.push(c.id); tally.set(id, l); }
    }));
    const rec = [...tally.entries()].sort((a, b) => b[1].length - a[1].length || (toolById.get(a[0])?.name || "").localeCompare(toolById.get(b[0])?.name || "")).slice(0, 4);
    const list = pCaps.filter((c) => (!dom || capDomain(c.id) === dom) && (capF === "all" || capStatus(c) === capF));
    const dn = dom ? DOMAINS.find((d) => d.id === dom)?.n : null;
    return (
      <div className="pad">
        <div className="cov-hero">
          <div className="card ringcard"><div onClick={(e) => { const g = (e.target as HTMLElement).closest("[data-dom]"); if (g) { const d = g.getAttribute("data-dom")!; setDom(dom === d ? null : d); } }} dangerouslySetInnerHTML={{ __html: ring(profile, false, false) }} /></div>
          <div className="cov-side"><div><h2>Your environment covers {Math.round(pCov * 100)}% of the {PROFILES[profile].n} profile.</h2></div>
            <p>A tool being installed doesn&apos;t always mean a capability is covered. Medusa counts what it can actually use on this machine.</p>
            <div className="legend"><span><i style={{ background: "var(--accent)" }} />{n.covered} covered</span><span><i style={{ background: "var(--bronze)" }} />{n.partial} partial</span><span><i style={{ background: "var(--ink-3)" }} />{n.none} not available</span></div>
            <div><h3 style={{ marginBottom: 8 }}>Assessment profile</h3><div className="profiles">{Object.keys(PROFILES).map((k) => (<button key={k} onClick={() => { setProfile(k); setDom(null); }} className={k === profile ? "on" : ""}>{PROFILES[k].n}</button>))}</div></div>
          </div>
        </div>
        <div className="two">
          <div className="card"><h2>Missing capabilities</h2>
            {(["H", "M", "L"] as const).map((imp) => {
              const l = byPrio(imp);
              if (!l.length) return null;
              const col = imp === "H" ? "var(--red)" : imp === "M" ? "var(--bronze)" : "var(--slate)";
              const label = imp === "H" ? "High" : imp === "M" ? "Medium" : "Low";
              return (
                <div key={imp}><div className="prio"><i style={{ background: col }} />{label} priority</div>
                  {l.map((c) => (<div className="mrow" key={c.id}><span><code>{c.id}</code><br /><small>{c.description}</small></span>{statusPill(capStatus(c))}</div>))}
                </div>
              );
            })}
            {!gaps.length && <p className="small-note" style={{ padding: "10px 0 14px" }}>Everything in this profile is covered.</p>}
            <div style={{ height: 10 }} />
          </div>
          <div className="card"><h2>Tools worth adding</h2><p className="small-note" style={{ marginBottom: 6 }}>Ranked by how many gaps each one closes. You decide what to install.</p>
            {rec.length ? rec.map(([id, cl]) => {
              const t = toolById.get(id)!;
              return (
                <div className="rec" key={id}><span className="tav off">{t.name[0].toUpperCase()}</span>
                  <span><b>{t.name}</b><small>Closes {cl.length} {cl.length === 1 ? "gap" : "gaps"}: {cl.slice(0, 2).join(", ")}{cl.length > 2 ? " and more" : ""}</small></span>
                  <button className="btn sm" onClick={() => setSel(id)}>Install options</button>
                </div>
              );
            }) : <p className="small-note" style={{ padding: "10px 0 14px" }}>Nothing to add for this profile.</p>}
            <div style={{ height: 10 }} />
          </div>
        </div>
        <div className="group-h"><h2>Capabilities{dn ? ` in ${dn}` : ""}</h2>{dom ? <button className="linkbtn" onClick={() => setDom(null)}>Show all domains</button> : <small>Select a segment in the ring to focus a domain</small>}</div>
        <div className="toolbar"><div className="seg-ctl">{[["all", "All"], ["covered", "Covered"], ["partial", "Partial"], ["none", "Not available"]].map(([f, label]) => (
          <button key={f} onClick={() => setCapF(f)} className={capF === f ? "on" : ""}>{label}</button>
        ))}</div></div>
        <div className="card rows captable">
          {list.length ? list.map((c) => (
            <div className="trow" key={c.id}>
              <span><code>{c.id}</code><small>{c.description}</small></span>
              <span className="prov-row" style={{ margin: 0 }}>{c.providers.length ? c.providers.map((id) => {
                const t = toolById.get(id);
                return <span key={id} className={`prov ${t?.installed ? "ok" : "no"}`}>{t?.installed ? <Ic n="check" s={13} /> : <Ic n="x" s={13} />}{t?.name || id}</span>;
              }) : <span className="prov no">no registered provider</span>}</span>
              <span className="stat">{statusPill(capStatus(c))}</span>
            </div>
          )) : <div className="empty">No capabilities match this filter.</div>}
        </div>
      </div>
    );
  }

  /* ================= doctor ================= */
  function DoctorView() {
    const d = doctor;
    const cards: { title: string; rows: { kind: "ok" | "warn" | "bad"; t: string; p?: string }[] }[] = [
      { title: "Platform", rows: [
        { kind: "ok", t: d ? `${d.platform}` : "Detecting platform…", p: "Medusa picks install methods that fit your system." },
        { kind: "ok", t: d ? `PATH resolves tools (${d.tools_installed}/${d.tools_total} installed)` : "Scanning PATH…", p: "Tools are found on PATH and in known install folders." },
      ]},
      { title: "Security capabilities", rows: [
        { kind: d && d.caps_covered > 0 ? "ok" : "warn", t: d ? `${d.caps_covered}/${d.caps_total} capabilities covered` : "Scoring capabilities…", p: "What Medusa can actually use on this machine." },
        { kind: "ok", t: "Packet capture", p: "TShark/tcpdump adapters parse capture output." },
      ]},
      { title: "Connectivity and package managers", rows: [
        { kind: "ok", t: "winget, cargo, npm, go", p: "Used to suggest install commands. Medusa only shows them." },
      ]},
    ];
    return (
      <div className="pad">
        <div className="dgrid">
          {cards.map((c) => (
            <div className="card dcard" key={c.title}><h2>{c.title}</h2>
              {c.rows.map((r, i) => (
                <div className="chk" key={i}><span className={`st ${r.kind === "ok" ? "" : r.kind === "warn" ? "wait" : "bad"}`}>{r.kind === "ok" ? <Ic n="check" s={12} /> : r.kind === "warn" ? <Ic n="alert" s={12} /> : <Ic n="x" s={12} />}</span><span><b>{r.t}</b>{r.p && <p>{r.p}</p>}</span></div>
              ))}
            </div>
          ))}
        </div>
        <div className="group-h" style={{ marginTop: 28 }}><h2>Issues to look at</h2><small>{d ? `${d.issues.length} found` : "scanning…"}</small></div>
        {d && d.issues.length === 0 && <div className="issue"><div><b>No issues</b><p>Everything Medusa needs is in place.</p></div></div>}
        {d?.issues.map((iss, i) => (
          <div className="issue" key={i}><div><b>Issue {i + 1}</b><p>{iss}</p></div><button className="btn sm" onClick={doRefresh}>Refresh tools</button></div>
        ))}
      </div>
    );
  }
}

/* ---------- small pieces (outside App to keep hooks rules simple) ---------- */
/** Compact human duration for timing chips: 42ms / 0.4s / 12s / 3m10s / 1h2m. */
function fmtDur(s: number): string {
  if (s < 1) return `${Math.max(1, Math.round(s * 1000))}ms`;
  if (s < 10) return `${s.toFixed(1)}s`;
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) { const total = Math.round(s); const m = Math.floor(total / 60); const r = total % 60; return r ? `${m}m${r}s` : `${m}m`; }
  const h = Math.floor(s / 3600); const m = Math.round((s % 3600) / 60);
  return m ? `${h}h${m}m` : `${h}h`;
}

/** Live "waiting …" timer shown beside the thinking dots while a model
 *  call is in flight. Gateway stalls last minutes with zero events, so
 *  without this the turn looks frozen. Ticks locally, costs nothing. */
function WaitTimer({ since }: { since: number }) {
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  return <span className="wait-t">waiting {fmtDur(Math.max(0, (Date.now() - since) / 1000))}</span>;
}

/** Clipboard write with a legacy fallback (execCommand) for contexts
 *  where the async Clipboard API is unavailable. */
async function copyStr(t: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(t);
    return;
  } catch { /* fall through to execCommand */ }
  const ta = document.createElement("textarea");
  ta.value = t;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}

/** Copy button for thinking/tool cards. Copies the card's full text —
 *  timestamp, durations, and body — even when its <details> is
 *  collapsed (collapsed content is otherwise unselectable). Stops at
 *  the button so the card doesn't toggle open/closed on click. */
function CopyBtn({ text, title }: { text: string; title?: string }) {
  const [ok, setOk] = useState(false);
  const label = title ?? "Copy card text";
  return (
    <button className="copybtn" title={label} aria-label={label}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        copyStr(text).then(() => { setOk(true); window.setTimeout(() => setOk(false), 1200); }).catch(() => {});
      }}>
      <Ic n={ok ? "check" : "copy"} s={13} />
    </button>
  );
}

function StepCard({ step, showDurations }: { step: Step; showDurations: boolean }) {
  // Tool cards show execution time only — LLM latency belongs to the
  // thinking card (the model's artifact), not the tool. Fast executions
  // (<100ms, e.g. direct localhost HTTP) show as milliseconds.
  const toolS = step.toolSecs ?? (step.dur != null ? step.dur / 1000 : null);
  const timing = showDurations && toolS != null && toolS > 0 ? `tool ${fmtDur(toolS)}` : "";
  const headLine = `${stepTitle(step.cap)} (${step.cap}) on ${step.target} · ${fmtT(step.at)}${timing ? ` · ${timing}` : ""}${step.result && step.result !== "Running" ? ` — ${step.result}` : ""}`;
  const copyText = [headLine, step.reason ? `Reason: ${step.reason}` : "", step.raw || "", step.outputs.join("\n")].filter(Boolean).join("\n");
  return (
    <details className="step" open={step.open}>
      <summary>
        {step.state === "run" ? <span className="st run"><span className="spin" /></span> : step.state === "wait" ? <span className="st wait"><Ic n="pause" s={13} /></span> : <span className="st"><Ic n="check" s={13} /></span>}
        <span className="st-main"><b>{stepTitle(step.cap)}</b><code>{step.cap}</code><span className="via">{step.provider ? `${prettyTool(step.provider)}${step.reason ? ` — ${step.reason}` : ""}` : step.reason || step.target}</span></span>
        <span className="st-res">{step.result}</span><span className="st-time">{fmtT(step.at)}{timing ? <span className="st-dur"> · {timing}</span> : null}</span><CopyBtn title="Copy tool card and duration" text={copyText} /><span className="chev"><Ic n="right" s={16} /></span>
      </summary>
      <div className="st-body">
        {step.raw ? <pre className="out">{step.raw}</pre> : null}
        {step.outputs.length ? <pre className="out obs">{step.outputs.join("\n")}</pre> : null}
        {!step.raw && !step.outputs.length && (step.state === "done" ? <span>Tool produced no output.</span> : <span>No output yet.</span>)}
      </div>
    </details>
  );
}

function statusPill(s: string) {
  return <span className={`pill ${s}`}>{s === "covered" ? "Covered" : s === "partial" ? "Partial" : "Not available"}</span>;
}
function prettyTool(id: string) {
  return id.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
function stepTitle(cap: string) {
  const m: Record<string, string> = {
    "network.port_scan": "Find open ports", "network.service_detection": "Identify services",
    "network.host_discovery": "Find live hosts", "network.os_detection": "Guess the OS",
    "subdomain.discovery": "Find subdomains", "dns.enumeration": "List DNS records", "dns.resolution": "Resolve names",
    "http.probe": "Probe web services", "http.crawl": "Crawl pages", "http.endpoint_discovery": "Find hidden paths",
    "web.vulnerability_scan": "Scan for known vulnerabilities", "web.fuzzing": "Fuzz inputs",
    "web.injection_testing": "Test injection points", "web.oob_testing": "Test out-of-band callbacks",
  };
  return m[cap] || cap;
}
function catOf(t: { category: string }): string {
  const m: Record<string, string> = {
    NetworkDiscovery: "network", DnsAsset: "dns", ExternalSurface: "external",
    HttpWebDiscovery: "http", WebSecurity: "web", TrafficAnalysis: "traffic",
    SourceAnalysis: "source", SupplyChain: "supply_chain", ContainerK8s: "container",
    BinaryRe: "binary", Cloud: "cloud",
  };
  return m[t.category] || "network";
}

function Drawer({ id, onClose, doRefresh }: { id: string; onClose: () => void; doRefresh: () => void }) {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [caps, setCaps] = useState<CapInfo[]>([]);
  useEffect(() => {
    invoke<ToolInfo[]>("get_tools").then(setTools).catch(() => {});
    invoke<CapInfo[]>("get_capability_details").then(setCaps).catch(() => {});
  }, []);
  const t = tools.find((x) => x.id === id);
  if (!t) return null;
  const toolCaps = caps.filter((c) => t.caps.includes(c.id));
  return (
    <>
      <div className="scrim on" onClick={onClose} />
      <aside className="drawer on" aria-label="Tool details">
        <div className="dr-h"><span className={`tav${t.installed ? "" : " off"}`}>{t.name[0].toUpperCase()}</span>
          <div><h2>{t.name}</h2><p>{t.category}</p></div>
          <button className="x" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <div className="dr-b">
          <p style={{ margin: 0, color: "var(--ink-2)" }}>{t.description}.</p>
          <div className="facts">
            <div><small>Status</small><span>{t.installed ? (t.healthy ? "Healthy" : "Installed, limited") : "Not installed"}</span></div>
            <div><small>Version</small><span>{t.version || "—"}</span></div>
            {t.path && <div style={{ gridColumn: "1/-1" }}><small>Location</small><span className="mono" style={{ fontSize: 12 }}>{t.path}</span></div>}
          </div>
          <section><h2 style={{ marginBottom: 6 }}>Capabilities</h2>
            <div className="caplist">{toolCaps.map((c) => (
              <div className="capi" key={c.id}><div><code>{c.id}</code><small>{c.description}</small>
                <div className="prov-row"><small style={{ color: "var(--ink-3)" }}>Providers</small>{c.providers.map((p) => (<span key={p} className="prov">{p}</span>))}</div>
              </div>{c.available && <span className="pill covered">Covered</span>}</div>
            ))}</div>
          </section>
          {!t.installed && (
            <section><h2 style={{ marginBottom: 4 }}>Install {t.name}</h2>
              <p className="small-note" style={{ marginBottom: 12 }}>Medusa doesn&apos;t run installers. Use the official source, then refresh tools.</p>
              <div className="method"><span className="kind docs">Official documentation</span>
                <span className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)" }}>{t.docs_url}</span>
                <a className="btn sm" style={{ alignSelf: "flex-start", textDecoration: "none" }} href={`https://${t.docs_url}`} target="_blank" rel="noreferrer">Open documentation</a>
              </div>
              <div style={{ marginTop: 14 }}><button className="btn" onClick={doRefresh}>Refresh tools</button></div>
            </section>
          )}
        </div>
      </aside>
    </>
  );
}

function ApprovalModal({ approval, onChoose, onDeny, customAns, setCustomAns, onSendCustom }: {
  approval: { title: string; message: string; options: string[]; selected: number };
  onChoose: (i: number) => void; onDeny: () => void;
  customAns: string; setCustomAns: (s: string) => void; onSendCustom: () => void;
}) {
  const custom = approval.options[approval.selected] === "Type your own answer";
  return (
    <div className="sheetwrap" onClick={onDeny}>
      <div className="sheet" role="dialog" aria-label={approval.title} onClick={(e) => e.stopPropagation()} style={{ width: "min(520px,100%)" }}>
        <div className="brand"><Logo z={30} /><span>Medusa</span></div>
        <h2 style={{ fontSize: 22 }}>{approval.title}</h2>
        <p className="sub" style={{ whiteSpace: "pre-wrap" }}>{approval.message}</p>
        <div className="approve" style={{ border: 0, padding: 0 }}>
          <div className="opts">
            {approval.options.map((opt, i) => (
              <button key={opt} className={`opt${approval.selected === i ? " sel" : ""}`} onClick={() => onChoose(i)}>
                <span className="st" style={{ width: 20, height: 20 }}>{approval.selected === i ? "▸" : ""}</span>{opt}
              </button>
            ))}
          </div>
          {custom && (
            <div className="box" style={{ marginTop: 4 }}>
              <textarea rows={2} value={customAns} placeholder="Type your answer, e.g. allow for this target only" aria-label="Type your own answer"
                onChange={(e) => setCustomAns(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSendCustom(); } }} />
              <button className="send" aria-label="Send custom answer" onClick={onSendCustom}>↑</button>
            </div>
          )}
        </div>
        <p className="fr-foot">↑â†“ navigate · Enter select · Esc deny. Your choice applies once.</p>
      </div>
    </div>
  );
}

function FirstRunSheet({ onDone, onTools }: { onDone: () => void; onTools: () => void }) {
  const [rows, setRows] = useState<{ cat: string; done: boolean; n: string }[]>([
    { cat: "Network discovery", done: false, n: "Checking…" }, { cat: "DNS and asset discovery", done: false, n: "Checking…" },
    { cat: "HTTP and web discovery", done: false, n: "Checking…" }, { cat: "Web security testing", done: false, n: "Checking…" },
    { cat: "Source-code analysis", done: false, n: "Checking…" }, { cat: "Everything else", done: false, n: "Checking…" },
  ]);
  const [bars, setBars] = useState<{ n: string; w: number }[] | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  useEffect(() => {
    let i = 0;
    const next = async () => {
      if (i >= rows.length) {
        try {
          const [t, c] = await Promise.all([
            invoke<ToolInfo[]>("get_tools"),
            invoke<CapInfo[]>("get_capability_details"),
          ]);
          const n = t.filter((x) => x.installed).length;
          setSummary(`${n} tools found, ${t.length - n} not installed`);
          const domCov = (d: string) => {
            const list = c.filter((x) => capDomain(x.id) === d);
            if (!list.length) return 0;
            return list.filter((x) => x.available).length / list.length;
          };
          setBars([["Network", "network"], ["DNS and assets", "dns"], ["HTTP", "http"], ["Web testing", "web"], ["Source code", "source"], ["Runtime", "runtime"]]
            .map(([n2, d]) => ({ n: n2, w: Math.round(domCov(d) * 100) })));
        } catch { setSummary("Tool scan unavailable in preview"); }
        return;
      }
      const r = i;
      setTimeout(() => {
        setRows((prev) => prev.map((row, j) => (j === r ? { ...row, done: true, n: "done" } : row)));
        i++; next();
      }, 260);
    };
    const t = setTimeout(next, 400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className="sheetwrap">
      <div className="sheet" role="dialog" aria-labelledby="frT">
        <div className="brand"><Logo z={30} /><span>Medusa</span></div>
        <h2 id="frT">Checking your environment</h2>
        <p className="sub">Looking for security tools on this machine. Nothing is installed or changed.</p>
        <div>{rows.map((r) => (
          <div key={r.cat} className={`fr-row${r.done ? " done" : ""}`}><span className="st">{r.done ? "✓" : ""}</span><span>{r.cat}</span><span className="fr-n">{r.n}</span></div>
        ))}</div>
        {summary && (
          <div className="fr-sum"><h3>{summary}</h3>
            {bars && bars.map((b) => (
              <div className="brow" key={b.n}><span>{b.n}</span><span className="b"><i style={{ width: `${b.w}%` }} /></span><span>{b.w}%</span></div>
            ))}
            <p className="fr-foot">Missing tools are fine. Medusa works with what you have and tells you what it can&apos;t cover.</p>
            <div className="fr-act"><button className="btn" onClick={onTools}>Review tools</button><button className="btn pri" onClick={onDone}>Continue to Medusa</button></div>
          </div>
        )}
      </div>
    </div>
  );
}
